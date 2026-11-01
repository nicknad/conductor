# Fuzz targets

Coverage-guided (`libFuzzer`) targets for the upload endpoint and the parsers
it reaches. Each target asserts the invariant in its comment, so a crash is
either a panic or a violated security property.

| Target | Input | Oracle |
| --- | --- | --- |
| `http_upload` | Arbitrary request body as `multipart/form-data` with a valid bearer | Never a server error; transport headers and request id present; upload slot returned |
| `upload_workflow` | Arbitrary package bytes, signed by a fixed harness key | A verdict's digest equals the signed digest; identity/inventory non-empty |
| `archive_inspect` | Arbitrary ZIP bytes | Accepted listings are bounded, duplicate-free, normalized/confined |
| `manifest_parse` | Arbitrary manifest JSON | Accepted manifests have non-empty identity, bounded identity, non-empty files, declared entrypoint |
| `entry_path` | Arbitrary UTF-8 entry names | Symlinks always rejected; accepted paths confined, length-bounded, idempotent |

## Run locally

Requires the nightly toolchain and `cargo-fuzz`:

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

cargo fuzz build http_upload
cargo fuzz run http_upload -- -max_total_time=60
```

Repeat for any target. CI runs each target for 60 seconds on relevant pull
requests and weekly on a schedule; crash reproducers and the evolving corpus
are uploaded as artifacts.

## Seeding

The targets are useful from an empty corpus, but seeds from
`tests/testdata/` (hostile archives), `tests/package_validation.rs` (valid
packages), and `tests/upload_api.rs` (multipart bodies) speed up coverage.
Drop raw inputs into `fuzz/corpus/<target>/`; that directory is gitignored.
