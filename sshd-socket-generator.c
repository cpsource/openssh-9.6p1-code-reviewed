#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "includes.h"

#include "hostfile.h"   /* Needs to be included before auth.h */
#include "auth.h"
#include "kex.h"
#include "log.h"
#include "misc.h"
#include "monitor.h"
#include "ssh-gss.h"    /* Needs to be included before monitor_wrap.h */
#include "monitor_wrap.h"
#include "pathnames.h"
#include "servconf.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssherr.h"

#define MAX_LISTEN_STREAMS      (16)
#define MAX_LISTEN_STREAM_LEN   (NI_MAXHOST + NI_MAXSERV + sizeof("ListenAddress=[:]") + 1)
typedef char listen_stream_set[MAX_LISTEN_STREAMS][MAX_LISTEN_STREAM_LEN];

/* Global variables required for sshd config parsing. */
ServerOptions options = {};
struct sshbuf *cfg = NULL;
struct include_list includes = TAILQ_HEAD_INITIALIZER(includes);

/* Other global variables that are required for this to build, because of their
 * use throughout the codebase. We do NOT use these variables for the
 * generator. */
Authctxt *the_authctxt = NULL;
int privsep_is_preauth = 1;
int use_privsep = -1;
struct monitor *pmonitor = NULL;
struct ssh *the_active_state = NULL;
struct sshauthopt *auth_opts = NULL;
struct sshbuf *loginmsg = NULL;

/* Stub globals and functions required to satisfy link dependencies from
 * monitor.o and related objects.  None of these are used by the generator. */
typedef struct Session Session;
struct passwd *privsep_pw = NULL;
int auth_sock = -1;
u_int utmp_len = 0;

struct sshkey *get_hostkey_by_index(int ind) { return NULL; }
struct sshkey *get_hostkey_public_by_index(int ind, struct ssh *ssh)
    { return NULL; }
struct sshkey *get_hostkey_public_by_type(int type, int nid, struct ssh *ssh)
    { return NULL; }
struct sshkey *get_hostkey_private_by_type(int type, int nid, struct ssh *ssh)
    { return NULL; }
int get_hostkey_index(struct sshkey *key, int compare, struct ssh *ssh)
    { return -1; }
int sshd_hostkey_sign(struct ssh *ssh, struct sshkey *privkey,
    struct sshkey *pubkey, u_char **signature, size_t *slenp,
    const u_char *data, size_t dlen, const char *alg)
    { return SSH_ERR_INTERNAL_ERROR; }

void session_unused(int id) {}
Session *session_new(void) { return NULL; }
Session *session_by_tty(char *tty) { return NULL; }
void session_pty_cleanup2(Session *s) {}
void session_destroy_all(struct ssh *ssh, void (*closefunc)(Session *)) {}
const char *session_get_remote_name_or_ip(struct ssh *ssh,
    u_int utmp_size, int use_dns) { return NULL; }

int pty_allocate(int *ptyfd, int *ttyfd, char *namebuf, size_t namebuflen)
    { return 0; }
void pty_setowner(struct passwd *pw, const char *tty, const char *role) {}

void record_login(pid_t pid, const char *tty, const char *user, uid_t uid,
    const char *host, struct sockaddr *addr, socklen_t addrlen) {}

int sshsk_sign(const char *provider, struct sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const char *pin) { return SSH_ERR_INTERNAL_ERROR; }

static int listen_stream_set_append(listen_stream_set set, const char *listen_stream) {
        size_t n;

        if (!set)
                return -EINVAL;

        n = strnlen(listen_stream, MAX_LISTEN_STREAM_LEN);
        if (n == MAX_LISTEN_STREAM_LEN)
                return -EINVAL;

        for (int i = 0; i < MAX_LISTEN_STREAMS; i++) {
                if (strcmp(set[i], listen_stream) == 0)
                        return 0;

                if (strnlen(set[i], MAX_LISTEN_STREAM_LEN) > 0)
                        continue;

                memcpy(set[i], listen_stream, n);
                set[i][n] = '\0';

                return 0;
        }

        return -E2BIG;
}

static int listen_stream_set_len(listen_stream_set set) {
        int r = 0;

        if (!set)
                return 0;

        for (int i = 0; i < MAX_LISTEN_STREAMS; i++) {
                if (strnlen(set[i], MAX_LISTEN_STREAM_LEN) > 0)
                        r++;
        }

        return r;
}

static char *path_append(const char *base, const char *append) {
        bool add_slash;
        size_t n = 0, len_base, len_append;
        char *path = NULL;

        len_base = strnlen(base, PATH_MAX);
        if (len_base == 0)
                return NULL;
        len_append = strnlen(append, PATH_MAX);
        add_slash = base[len_base - 1] != '/';

        path = calloc(len_base + len_append + (add_slash ? 2 : 1), sizeof(char));
        if (!path)
                return NULL;

        memcpy(path, base, len_base);
        n += len_base;

        if (add_slash)
                path[n++] = '/';

        memcpy(path + n, append, len_append);
        n += len_append;
        path[n] = '\0';

        return path;
}

static int fflush_and_check(FILE *f) {
        errno = 0;
        fflush(f);

        if (ferror(f))
                return errno > 0 ? -errno : -EIO;

        return 0;
}

static bool listen_addr_is_default(int family, const char *addr, const char *port) {
        if (family != AF_UNSPEC)
                return false;

        if (strcmp(addr, "0.0.0.0") != 0 && strcmp(addr, "::") != 0)
                return false;

        if (strcmp(port, "22") != 0)
                return false;

        return true;
}

static int write_systemd_socket_file(const char *destdir) {
        bool have_custom_config = false;
        listen_stream_set listen_streams = {};
        int num_listen_streams, family = options.address_family;
        char *conf = NULL, *overridedir = NULL;
        FILE *f = NULL;
        int dirfd = -1, conffd = -1;
        int r;

        overridedir = path_append(destdir, "ssh.socket.d");
        if (!overridedir) {
                r = -ENOMEM;
                goto out;
        }

        if (mkdir(overridedir, 0755) < 0 && errno != EEXIST) {
                r = -errno;
                goto out;
        }

        /* Open the directory with O_NOFOLLOW to prevent symlink substitution
         * attacks between mkdir and the subsequent file creation. */
        dirfd = open(overridedir, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (dirfd < 0) {
                r = -errno;
                goto out;
        }

        conf = path_append(overridedir, "addresses.conf");
        if (!conf) {
                r = -ENOMEM;
                goto out;
        }

        /* Use openat+O_NOFOLLOW so a pre-placed symlink at addresses.conf
         * cannot redirect the write to an arbitrary file. */
        conffd = openat(dirfd, "addresses.conf",
            O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC, 0644);
        if (conffd < 0) {
                r = -errno;
                goto out;
        }

        f = fdopen(conffd, "w");
        if (!f) {
                r = -errno;
                close(conffd);
                conffd = -1;
                goto out;
        }
        conffd = -1; /* now owned by f */

        fprintf(f,
                "# Automatically generated by sshd-socket-generator\n"
                "\n[Socket]\n"
                "ListenStream=\n");

        for (u_int i = 0; i < options.num_listen_addrs; i++) {
                for (struct addrinfo *ai = options.listen_addrs[i].addrs; ai; ai = ai->ai_next) {
                        char addr[NI_MAXHOST] = {}, port[NI_MAXSERV] = {},
                             listen_stream[MAX_LISTEN_STREAM_LEN] = {};

                        r = getnameinfo(ai->ai_addr, ai->ai_addrlen,
                                        addr, sizeof(addr),
                                        port, sizeof(port),
                                        NI_NUMERICHOST|NI_NUMERICSERV);
                        if (r != 0) {
                                fprintf(stderr, "%s\n", gai_strerror(r));
                                r = r == EAI_SYSTEM ? -errno : -EINVAL;
                                goto out;
                        }


                        if (family != AF_UNSPEC && family != ai->ai_family) {
                                fprintf(stderr, "Skipping address %s, wrong address family", addr);
                                continue;
                        }

                        /* The default [Socket] section of ssh.socket is:
                         *
                         * [Socket]
                         * ListenStream=[::]:22
                         * ListenStream=0.0.0.0:22
                         * BindIPv6Only=ipv6-only
                         * Accept=no
                         * FreeBind=yes
                         *
                         * ...
                         *
                         * As this corresponds to the default /etc/ssh/sshd_config settings:
                         *
                         * # Port 22
                         * # AddressFamily any
                         * # ListenAddress 0.0.0.0
                         * # ListenAddress ::
                         *
                         * ...
                         *
                         * Only create an override if the config would differ from the above. */
                        if (!listen_addr_is_default(family, addr, port))
                                have_custom_config = true;

                        snprintf(listen_stream,
                                 MAX_LISTEN_STREAM_LEN,
                                 "ListenStream=%s%s%s:%s",
                                 ai->ai_family == AF_INET6 ? "[" : "",
                                 addr,
                                 ai->ai_family == AF_INET6 ? "]" : "",
                                 port);

                        r = listen_stream_set_append(listen_streams, listen_stream);
                        if (r < 0)
                                goto out;
                }
        }

        num_listen_streams = listen_stream_set_len(listen_streams);

        if (num_listen_streams <= 0 || !have_custom_config) {
                /* We didn't generate anything useful, so clean up and leave
                 * ssh.socket as-is. */
                r = -ENODATA;
                goto out;
        }

        for (int i = 0; i < num_listen_streams; i++)
                fprintf(f, "%s\n", listen_streams[i]);

        r = fflush_and_check(f);
        if (r < 0)
                goto out;

out:
        if (dirfd >= 0)
                close(dirfd);
        if (conffd >= 0)
                close(conffd);
        if (f)
                fclose(f);

        if (r < 0) {
                (void) remove(conf);
                (void) remove(overridedir);
        }

        free(overridedir);
        free(conf);

        return r;
}

static int parse_sshd_config_options() {
        cfg = sshbuf_new();
        if (!cfg)
                return -ENOMEM;

	initialize_server_options(&options);
        load_server_config(_PATH_SERVER_CONFIG_FILE, cfg);
        parse_server_config(&options, _PATH_SERVER_CONFIG_FILE, cfg, &includes, NULL, 0);
        fill_default_server_options(&options);

        return 0;
}

int main(int argc, char **argv) {
        const char *destdir = NULL;
        int r;

        if (argc < 2) {
                fprintf(stderr, "Expected at least one argument.\n");

                return EXIT_FAILURE;
        }

        destdir = argv[1];
        if (destdir[0] != '/') {
                fprintf(stderr, "Destination directory must be an absolute path.\n");
                return EXIT_FAILURE;
        }

        r = parse_sshd_config_options();
        if (r < 0) {
                fprintf(stderr, "Failed to parse sshd config: %s\n", strerror(-r));

                return EXIT_FAILURE;
        }

        if (options.num_listen_addrs <= 0) {
                /* No listen addresses configured? Don't generate anything. */
                fprintf(stderr, "No listen addresses configured. Will not generate anything.\n");

                return EXIT_SUCCESS;
        }

        r = write_systemd_socket_file(destdir);
        if (r == -ENODATA) {
                fprintf(stderr, "No custom listen addresses configured. Will not generate anything.\n");

                return EXIT_SUCCESS;
        }
        if (r < 0) {
                fprintf(stderr, "Failed to generate ssh.socket: %s\n", strerror(-r));

                return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
}
