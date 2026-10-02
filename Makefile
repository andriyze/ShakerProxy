.DEFAULT_GOAL := help
.PHONY: help verify fmt-check openapi-check docs-check registry-check test test-go test-ui test-mitm test-mitm-image compose-check security-check shell-check package package-smoke release-images release-bundle release-bundle-smoke vm-confirm vm-timeout vm-daemon-kill vm-reboot vm-host-safety vm-dhcp vm-capture ingest-db-smoke live-events-smoke analyzer-smoke netlab netlab-wifi netlab-mitmproxy dev dev-observe dev-down dev-logs dev-ps dev-reset dev-cli dev-demo dev-demo-live ui-dev

PACKAGE_VERSION ?= 0.1.0-dev.1
GO_IMAGE := golang:1.25.1-bookworm@sha256:c423747fbd96fd8f0b1102d947f51f9b266060217478e5f9bf86f145969562ee
# Named volumes keep Go modules and build results between runs.
GO_CACHE := -v shakerproxy-gomod:/go/pkg/mod -v shakerproxy-gocache:/root/.cache/go-build
SHELLCHECK_IMAGE := koalaman/shellcheck:v0.10.0@sha256:2097951f02e735b613f4a34de20c40f937a6c8f18ecb170612c88c34517221fb
DEV_COMPOSE := docker compose -f deploy/compose.dev.yaml --profile observe
ARGS ?= status
SERVICE ?=

##@ Getting started

help: ## Show this list (the default target)
	@awk 'BEGIN { FS = ":.*## "; print "Usage: make <target>" } /^##@ / { printf "\n%s\n", substr($$0, 5) } /^[A-Za-z0-9_.-]+:.*## / { printf "  %-22s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Development stack (loopback only, SETUP_SAFE)

dev: ## Start the dev stack, wait until ready, print the setup token if setup is pending
	./scripts/dev-up.sh

dev-observe: ## Like dev, plus ingestion and the Zeek/Suricata analyzers
	./scripts/dev-up.sh --observe

dev-logs: ## Follow dev stack logs (one service: make dev-logs SERVICE=control-api)
	$(DEV_COMPOSE) logs --follow --tail 100 $(SERVICE)

dev-ps: ## Show dev stack containers and health
	$(DEV_COMPOSE) ps

dev-cli: ## Run the shakerproxy CLI against the dev gateway daemon: make dev-cli ARGS="doctor"
	docker run --rm $$(test -t 1 && printf -- '-t') -v shakerproxy-dev_gateway-run:/run/shakerproxy -v "$(CURDIR):/src:ro" $(GO_CACHE) -w /src $(GO_IMAGE) go run ./host/cli/cmd/shakerproxy $(ARGS)

dev-demo: ## Load six demo devices and 90 minutes of traffic into the running dev stack (after make dev-observe)
	docker run --rm $(GO_CACHE) -v "$(CURDIR):/src" -w /src -e CGO_ENABLED=0 $(GO_IMAGE) go build -o .cache/devdemo ./tools/devdemo
	docker run --rm --user 65532:65532 --network shakerproxy-dev_control -v shakerproxy-dev_inventory-data:/inventory -v "$(CURDIR)/.local/ingest-token:/run/secrets/ingest_token:ro" -v "$(CURDIR)/.cache/devdemo:/usr/local/bin/devdemo:ro" $(GO_IMAGE) devdemo --inventory /inventory/inventory.json --token-file /run/secrets/ingest_token

dev-demo-live: ## Send one burst of current demo traffic, e.g. inside a test run (VARIANT=2 behaves like newer firmware)
	docker run --rm $(GO_CACHE) -v "$(CURDIR):/src" -w /src -e CGO_ENABLED=0 $(GO_IMAGE) go build -o .cache/devdemo ./tools/devdemo
	docker run --rm --user 65532:65532 --network shakerproxy-dev_control -v shakerproxy-dev_inventory-data:/inventory -v "$(CURDIR)/.local/ingest-token:/run/secrets/ingest_token:ro" -v "$(CURDIR)/.cache/devdemo:/usr/local/bin/devdemo:ro" $(GO_IMAGE) devdemo --inventory /inventory/inventory.json --token-file /run/secrets/ingest_token --live --variant $(or $(VARIANT),1)

ui-dev: ## Run the web UI with hot reload at http://localhost:5173 (start make dev first)
	test -d apps/web-ui/node_modules || npm --prefix apps/web-ui ci
	npm --prefix apps/web-ui run dev

dev-down: ## Stop the dev stack (keeps its data)
	$(DEV_COMPOSE) down

dev-reset: ## Delete all dev data and start fresh with a new setup token
	$(DEV_COMPOSE) down --volumes --remove-orphans
	rm -f .local/setup-token .local/setup-token.digest
	@$(MAKE) --no-print-directory dev

##@ Checks

verify: docs-check registry-check fmt-check openapi-check test compose-check security-check shell-check ## Run every check CI runs locally

openapi-check: ## Fail when the published OpenAPI document is not valid YAML (as CI checks)
	@if command -v ruby >/dev/null; then ruby -ryaml -e 'YAML.safe_load(File.read(ARGV[0]), aliases: true)' schemas/api/openapi.yaml; \
	else docker run --rm -v "$(CURDIR):/src:ro" -w /src ruby:3.3-alpine ruby -ryaml -e 'YAML.safe_load(File.read(ARGV[0]), aliases: true)' schemas/api/openapi.yaml; fi

fmt-check: ## Fail when Go files are not gofmt-formatted (as CI checks)
	@unformatted=$$(docker run --rm -v "$(CURDIR):/src" -w /src $(GO_IMAGE) gofmt -l apps host internal); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

docs-check: ## Check Markdown links, headings and make targets in docs
	node ./scripts/check-docs.mjs

registry-check: ## Check the capability registry
	docker run --rm -v "$(CURDIR):/src" $(GO_CACHE) -w /src $(GO_IMAGE) go run ./tools/registrycheck -root .

test: test-go test-ui test-mitm ## Run all unit tests

test-go: ## Run Go tests in Docker
	docker run --rm -v "$(CURDIR):/src" $(GO_CACHE) -w /src $(GO_IMAGE) sh -c 'go test ./...'

test-ui: ## Run web UI tests, typecheck and build
	npm --prefix apps/web-ui ci
	npm --prefix apps/web-ui test
	npm --prefix apps/web-ui run typecheck
	npm --prefix apps/web-ui run build

test-mitm: ## Run mitmproxy add-on tests (needs python3)
	PYTHONPATH=apps/mitmproxy python3 -m unittest discover -s apps/mitmproxy -p 'test_*.py'
	python3 -m py_compile apps/mitmproxy/shakerproxy_policy.py apps/mitmproxy/shakerproxy_addon.py

test-mitm-image: ## Run the mitmproxy addon hook tests inside the pinned image
	docker build --file apps/mitmproxy/Dockerfile --tag shakerproxy-mitmproxy:test .
	docker run --rm -v "$(CURDIR)/apps/mitmproxy:/tests:ro" --entrypoint /usr/local/bin/python shakerproxy-mitmproxy:test -m unittest discover -s /tests -p 'test_*.py'

compose-check: ## Validate the Compose files
	SHAKERPROXY_POSTGRES_IMAGE=postgres@sha256:421b84e07a72bb8f3715f20501a1fdbe1219aad1fa4af7786a49d9a3f2480296 SHAKERPROXY_CONTROL_API_IMAGE=registry.invalid/control-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa SHAKERPROXY_WEB_UI_IMAGE=registry.invalid/web-ui@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb SHAKERPROXY_EDGE_IMAGE=registry.invalid/edge@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc SHAKERPROXY_INGESTD_IMAGE=registry.invalid/ingestd@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd SHAKERPROXY_ZEEK_IMAGE=registry.invalid/zeek@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee SHAKERPROXY_SURICATA_IMAGE=registry.invalid/suricata@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff SHAKERPROXY_MITMPROXY_IMAGE=registry.invalid/mitmproxy@sha256:1111111111111111111111111111111111111111111111111111111111111111 SHAKERPROXY_CAPTURE_GID=2000 SHAKERPROXY_EDGE_GID=2001 SHAKERPROXY_CLOUD_GID=2002 SHAKERPROXY_HOST_GID=2003 docker compose -f deploy/compose.yaml --profile core --profile observe --profile mitm config --quiet
	docker compose -f deploy/compose.dev.yaml --profile observe config --quiet

security-check: ## Run the security policy checks
	./tests/security/compose-policy.sh
	./tests/security/systemd-policy.sh
	./tests/security/installer-interface.sh
	./tests/security/runtime-provisioning.sh
	./tests/security/development-secret-provisioning.sh
	./tests/security/mitmproxy-netlab-policy.sh

shell-check: ## Lint every shell script with ShellCheck (warnings fail)
	git ls-files -z '*.sh' packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm | xargs -0 docker run --rm -v "$$PWD:/mnt:ro" -w /mnt $(SHELLCHECK_IMAGE) -S warning

##@ Integration tests (dev stack running)

ingest-db-smoke: ## Database-down spooling and recovery (needs make dev-observe)
	./tests/integration/postgres-ingest-smoke.sh

live-events-smoke: ## Live event stream smoke test
	./tests/integration/live-events-smoke.sh

analyzer-smoke: ## PCAPNG-to-database analyzer proof
	./tests/integration/analyzer-smoke.sh

##@ Packaging and release

package: ## Build the Debian host package (PACKAGE_VERSION=...)
	./packaging/build-deb.sh $(PACKAGE_VERSION)

package-smoke: package ## Build and smoke-test the package and installer
	./tests/packaging/deb-smoke.sh dist/shakerproxy-host_$(PACKAGE_VERSION)_amd64.deb
	./tests/packaging/image-publisher-smoke.sh
	./tests/packaging/installer-diagnostics-smoke.sh

release-images: ## Build and push release images (REGISTRY_PREFIX=...)
	@test -n "$(REGISTRY_PREFIX)" || (echo "REGISTRY_PREFIX is required" >&2; exit 2)
	./packaging/build-push-images.sh --version $(PACKAGE_VERSION) --channel "$(or $(CHANNEL),stable)" --registry-prefix "$(REGISTRY_PREFIX)" --output "dist/images-$(PACKAGE_VERSION).json"

release-bundle: package ## Build a signed release bundle (SIGNING_KEY=..., IMAGES_JSON=...)
	@test -n "$(SIGNING_KEY)" || (echo "SIGNING_KEY is required" >&2; exit 2)
	@test -n "$(IMAGES_JSON)" || (echo "IMAGES_JSON is required" >&2; exit 2)
	./packaging/build-release-bundle.sh --version $(PACKAGE_VERSION) --signing-key "$(SIGNING_KEY)" --images-json "$(IMAGES_JSON)" --host-package "dist/shakerproxy-host_$(PACKAGE_VERSION)_amd64.deb" --output "dist/release-$(PACKAGE_VERSION)"

release-bundle-smoke: release-bundle ## Verify a signed release bundle and installer
	./tests/packaging/release-bundle-smoke.sh "dist/release-$(PACKAGE_VERSION)"
	./tests/packaging/installer-verify-smoke.sh "dist/release-$(PACKAGE_VERSION)"

##@ VM and network lab tests (Linux hosts)

vm-confirm: ## VM: confirm a network plan
	./tests/vm/ubuntu-24.04/run.sh confirm

vm-timeout: ## VM: watchdog rollback on timeout
	./tests/vm/ubuntu-24.04/run.sh timeout

vm-daemon-kill: ## VM: rollback after the daemon is killed
	./tests/vm/ubuntu-24.04/run.sh daemon-kill

vm-reboot: ## VM: recovery after reboot
	./tests/vm/ubuntu-24.04/run.sh reboot

vm-host-safety: ## VM: host safety checks
	./tests/vm/ubuntu-24.04/run.sh host-safety

vm-dhcp: ## VM: DHCPv4 lease and NAT
	./tests/vm/ubuntu-24.04/run.sh dhcp

vm-capture: ## VM: bounded packet capture
	./tests/vm/ubuntu-24.04/run.sh capture

netlab: ## Network namespace lab suite (sudo)
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/run.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/high-port-traffic.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/firewall-coexistence.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/single-arm.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/dns-forwarding.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/syntax-validation.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/ipv6-lab.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/coverage-probes.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/vpn-mode.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/bridge-mode.sh
	sudo ./tests/netlab/wifi-hwsim.sh
	SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/mitmproxy-container.sh

netlab-wifi: ## Wi-Fi lab tests with simulated radios: visibility, and the access point in an inline bridge (sudo, needs mac80211_hwsim)
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/wifi-hwsim.sh
	sudo SHAKERPROXY_NETLAB_REQUIRE=1 ./tests/netlab/bridge-ap-hwsim.sh

netlab-mitmproxy: ## mitmproxy container lab test
	./tests/netlab/mitmproxy-container.sh
