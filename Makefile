githooks:
	@scripts/githooks.sh

update:
	cargo update --verbose

check:
	cargo check
	cargo shear

format:
	cargo fmt

lint:
	cargo clippy --all-features -- -W clippy::all

test:
	cargo nextest run

pre-commit: check update format lint test
