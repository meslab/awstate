PREFIX ?= ~/.local/bin

rust-version:
	rustc --version 		# rustc compiler
	cargo --version 		# cargo package manager
	rustfmt --version 		# rust formatter
	rustup --version 		# rust toolchain manager
	clippy-driver --version	# rust linter

format:
	cargo fmt

lint:
	cargo clippy

test:
	cargo test

run:
	cargo run -r

build:
	cargo update
	cargo build

awstate:
	cargo update
	cargo build -r --bin awstate
	strip target/release/awstate

all:
	cargo build -r
	strip target/release/awstate

install: all
	cp target/release/awstate $(PREFIX)

clean:
	cargo clean
	rm -rf target

uninstall: clean
	rm -f $(PREFIX)/awstate

upgrade:
	rustup update
	for i in $$(cat Cargo.toml | grep '^aws-' | awk '{ print $$1 }'); do cargo remove $$i; cargo add $$i -F behavior-version-latest; done
	cargo update

.PHONY: rust-version format lint test run build awstate all install clean uninstall upgrade
