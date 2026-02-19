# Makefile — Convenience targets for Host CA management (frflashy.com).
# See README-cert.md for the full setup guide.

.PHONY: help setup sign revoke show

CA_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

help:
	@echo "Host CA — frflashy.com"
	@echo ""
	@echo "Targets:"
	@echo "  make setup                              Generate the CA keypair (run once)"
	@echo "  make sign HOST_KEY=<path> [NAMES=<n>]  Sign a host public key"
	@echo "  make revoke KEY=<path>                 Revoke a key or certificate"
	@echo "  make show CERT=<path>                  Inspect a certificate"
	@echo ""
	@echo "Examples:"
	@echo "  make setup"
	@echo "  make sign HOST_KEY=/tmp/ssh_host_ed25519_key.pub"
	@echo "  make sign HOST_KEY=/tmp/ssh_host_ed25519_key.pub NAMES=frflashy.com,www.frflashy.com"
	@echo "  make revoke KEY=/tmp/ssh_host_ed25519_key.pub"
	@echo "  make show CERT=/tmp/ssh_host_ed25519_key-cert.pub"

setup:
	@bash $(CA_DIR)setup-ca.sh

sign:
ifndef HOST_KEY
	$(error HOST_KEY is required. Usage: make sign HOST_KEY=<path/to/host_key.pub> [NAMES=hostname,...])
endif
	@bash $(CA_DIR)sign-host-key.sh "$(HOST_KEY)" "$(if $(NAMES),$(NAMES),frflashy.com)"

revoke:
ifndef KEY
	$(error KEY is required. Usage: make revoke KEY=<path/to/key.pub>)
endif
	@bash $(CA_DIR)revoke-host-key.sh "$(KEY)"

show:
ifndef CERT
	$(error CERT is required. Usage: make show CERT=<path/to/cert.pub>)
endif
	@bash $(CA_DIR)show-cert.sh "$(CERT)"
