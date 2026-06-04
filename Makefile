# AgentSnitch Makefile
# Targets for development, building, and packaging.

.PHONY: help create build build-emitter build-daemon build-doctor build-hookctl build-neready build-extension package-macos-dev build-ui install uninstall clean test fmt lint run-daemon doctor ne-ready ne-typecheck dev-receiver

help:
	@echo "AgentSnitch development targets"
	@echo ""
	@echo "  make build-emitter     - Build the thin hook emitter (Go)"
	@echo "  make dev-receiver      - Run the socket receiver helper (for manual emitter testing)"
	@echo "  make build-daemon      - Build the correlator daemon (Go)"
	@echo "  make build-doctor      - Build the local health-check command (Go)"
	@echo "  make build-hookctl     - Build the Claude hook installer/verifier (Go)"
	@echo "  make build-neready     - Build the Network Extension readiness checker (Go)"
	@echo "  make build-extension   - Build local .systemextension bundle and host bridge dylib"
	@echo "  make package-macos-dev - Embed .systemextension and sign app (ad hoc by default, Developer ID with profiles)"
	@echo "  make create            - Build, sign/package, optionally notarize, install app/hooks/daemon"
	@echo "  make run-daemon        - go run ./cmd/daemon (for live testing)"
	@echo "  make doctor            - Check hook, emitter, daemon, UI, and recent hook health"
	@echo "  make ne-ready          - Check production Network Extension readiness"
	@echo "  make ne-typecheck      - Type-check Swift NE/host bridge sources"
	@echo "  make build-ui          - Build the Tauri UI (requires Tauri CLI + Rust)"
	@echo "  make install           - Build binaries and install Claude Code hooks"
	@echo "  make uninstall         - Remove AgentSnitch Claude Code hooks"
	@echo "  make test              - Run unit tests"
	@echo "  make fmt               - Format code"
	@echo "  make lint              - Lint (golangci, clippy, etc.)"
	@echo "  make clean             - Remove build artifacts"
	@echo ""
	@echo "  AGENTSNITCH_SOCK=/tmp/agentsnitch-dev.sock make run-daemon   # for dev socket"

create:
	@echo "==> Creating installed AgentSnitch build"
	./scripts/create.sh

build: build-emitter build-daemon build-doctor build-hookctl build-neready

build-emitter:
	@echo "==> Building emitter"
	@mkdir -p bin
	go build -o bin/emitter ./cmd/emitter
	@echo "    built: bin/emitter"
	@echo "    socket: ~/.agentsnitch/events.sock (or /tmp/agentsnitch-dev.sock if no HOME)"


build-daemon:
	@echo "==> Building daemon"
	@mkdir -p bin
	go build -o bin/daemon ./cmd/daemon
	@echo "    built: bin/daemon"

build-doctor:
	@echo "==> Building doctor"
	@mkdir -p bin
	go build -o bin/doctor ./cmd/doctor
	@echo "    built: bin/doctor"

build-hookctl:
	@echo "==> Building hookctl"
	@mkdir -p bin
	go build -o bin/hookctl ./cmd/hookctl
	@echo "    built: bin/hookctl"

build-neready:
	@echo "==> Building NE readiness checker"
	@mkdir -p bin
	go build -o bin/neready ./cmd/neready
	@echo "    built: bin/neready"

build-extension:
	@echo "==> Building Network Extension bundle scaffold and host bridge dylib"
	extension/build-extension.sh

package-macos-dev:
	@echo "==> Packaging local macOS app with embedded System Extension"
	scripts/package-macos-dev.sh

run-daemon:
	@echo "==> Running daemon (listens on ~/.agentsnitch/events.sock by default)"
	@echo "    Use AGENTSNITCH_SOCK=/tmp/agentsnitch-dev.sock for /tmp testing."
	@echo "    In another shell: run Claude Code normally with hooks installed."
	@mkdir -p bin
	go run ./cmd/daemon

doctor:
	go run ./cmd/doctor

ne-ready:
	go run ./cmd/neready

ne-typecheck:
	xcrun swiftc -typecheck extension/AgentSnitchXPCProtocol.swift extension/AgentSnitchHostBridge.swift
	xcrun swiftc -typecheck extension/AgentSnitchXPCProtocol.swift extension/AgentSnitchNetworkExtension.swift

build-ui:
	@echo "==> Building Tauri UI (requires: cargo tauri, Rust, macOS SDK)"
	cd ui && cargo tauri build

install:
	@echo "==> Installing AgentSnitch Claude Code hooks"
	./scripts/install.sh

uninstall:
	@echo "==> Removing AgentSnitch Claude Code hooks"
	./scripts/uninstall.sh

clean:
	rm -rf bin/ target/ dist/ ui/src-tauri/target

test:
	@echo "==> Running tests"
	go test ./...

fmt:
	go fmt ./...
	# cargo fmt --manifest-path ui/src-tauri/Cargo.toml || true

lint:
	@echo "==> Linting (add golangci-lint, clippy, etc. when ready)"
	# golangci-lint run ./...

# Convenience target for daemon testing with real hook events.
dev-receiver:
	@echo "==> Use 'make run-daemon' (or AGENTSNITCH_SOCK=... make run-daemon) to start the correlator."
	@echo "    Then run Claude Code normally and use 'make doctor' to confirm real hook events are arriving."
	@echo "    AgentSnitch should not inject fabricated sensitive-read or network-flow evidence."

# Also provide a make alias matching the help text in older scaffolding
run-dev-receiver: dev-receiver
