# Mutation results for `src/lib.rs`

Three runs on the same `lib.rs` (commit c6830e3 onward, unchanged), added together:

| run | tests | input | caught |
|---|---|---|---|
| `mutants.yml`, run 41503185796 | attack bench | all 562 testable mutants | 423 |
| `mutants-unit.yml`, run 41559154807 | `cargo test --lib`: exact values and fuzz | the 139 the bench missed | 133 |
| `mutants.yml`, run 41554949076 | attack bench, with a new `first_seen` check | 2 in `register` | 2 |

Total 558 caught, 4 missed. `caught.txt`, `missed.txt` and `unviable.txt` here are the first run; `mutants-unit.yml` starts from them. If `lib.rs` changes, this baseline is out of date and the full run has to be repeated.

The four survivors, `>` changed to `>=`, read by hand and not run:

| line | where | why it changes no balance |
|---|---|---|
| 530 | `register` | an earlier check already requires `deposit > fee`, so equality cannot be reached |
| 980 | `close` | with a zero refund the root vault gets +0 and `vault_total` gets -0 |
| 1721 | `enforce_recourse` | a debt means a stake entry exists, so paying 0 rewrites the same values |
| 1845 | `release_retained` | moves 0 and rewrites the same cell |

The last three can change the gas burnt, so they are not identical at the gas level.
