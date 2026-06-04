# BIP-174 test vectors

The test vectors live in `tests/data/bip174.json` as plain data. The runner in
`tests/bip174.rs` reads them and does the work. Keeping the two separate means
you can edit vectors without touching Rust, cases run in parallel, and a broken
case is easy to pin down.

## How the runner works

The JSON file is loaded once. Each entry in `cases` becomes its own `#[test]`,
so `cargo test` output maps one line per vector - no guessing which assertion
belongs to which case.

Every case has a `task` field that tells the runner what to do: `create`,
`update`, `sign`, `combine`, `finalize`, `extract`, `deserialize`,
`fail_deserialize`, or `fail_sign`. The runner picks the matching handler and
executes it. Anything the handler needs — PSBTs, keys, scripts, expected output
— lives in the case's `supplementary` block. The full shape of that block is
the `Supplementary` struct in `tests/bip174.rs`.

Tests are grouped under `mod invalid`, `mod valid`, and `mod workflow`, matching
the prefix in each case's `description` field.

Because each vector is its own `#[test]`, isolating a broken case is as simple
as running `cargo test` with its name. The namespace grouping also lets you
target a whole category in one go — useful when you're only working on the
invalid vectors and don't want the rest of the suite in the way.

```sh
# Run a single case
cargo test --test bip174 missing_outputs

# Run every invalid case
cargo test --test bip174 bip174::invalid
```

## Looking things up with `jq`

The index in each `check_case(<idx>)` call is the position in the `cases` array.

Inspect a single case by index:
```sh
jq '.cases[<idx>]' tests/data/bip174.json
```

Find a case by a word in its description:
```sh
jq '[.cases | to_entries[] | select(.value.description | test("<substr>"; "i")) | .key]' tests/data/bip174.json
```

Find a case by its expected PSBT hex:
```sh
jq '[.cases | to_entries[] | select(.value.expected.hex == "<hex>") | .key]' tests/data/bip174.json
```

List all case indices grouped by category — handy when adding tests or keeping
the `mod {invalid, valid, workflow}` blocks in sync:
```sh
jq '[.cases | to_entries[] | {
       key: (.value.description | ascii_downcase
             | if startswith("valid:") then "valid"
               elif startswith("workflow") then "workflow"
               else "invalid"
               end),
       idx: .key
     }]
   | group_by(.key)
   | map({(.[0].key): map(.idx)})
   | add' tests/data/bip174.json
```

## Adding a new test

Only add cases when the upstream BIP-174 vectors gain a new one.

1. Append an entry to `cases` in `tests/data/bip174.json`:
   - `description` — start with `Valid:`, `Invalid:`, or `Workflow` so it lands
     in the right module.
   - `supplementary.task` — pick the handler that should run.
   - The fields that handler reads. The authoritative list is the `Supplementary`
     struct in `tests/bip174.rs`; only set what your case actually uses.
   - `expected.hex` — the resulting PSBT. Omit for `fail_*` tasks. For
     `extract`, put the expected transaction hex in `supplementary.tx` instead.

2. If your case needs data the runner doesn't yet understand, add a field to
   `Supplementary` and extend the relevant handler.

3. Find the new index with the category-grouping `jq` recipe above, then add a
   `#[test]` shim under the right module in `tests/bip174.rs`:
   ```rust
   #[test]
   fn my_new_case() { check_case(<idx>); }
   ```
