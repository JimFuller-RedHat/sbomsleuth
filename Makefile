build:
	cargo build
build-container:
	podman build -f Containerfile
run:
	RUST_LOG=debug cargo run etc/test-data/sbom_corpus/simple.json
test:build
	cargo test --all
clean:
	cargo clean
