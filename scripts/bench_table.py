"""把 `cargo test --test bench -- --nocapture` 的 WRIT_BENCH 行轉成 README 用的 Markdown 表。
用法：cargo test ... 2>&1 | python3 scripts/bench_table.py > docs/bench.md"""
import sys
rows = [l.strip().split("|")[1:] for l in sys.stdin if l.startswith("WRIT_BENCH|")]
rows.sort(key=lambda r: r[0])
attacks = [r for r in rows if r[0].startswith("A")]
blocked = sum(1 for r in attacks if r[2].split(":")[-1] in r[3] or r[3] in r[2])
gain = sum(int(r[4]) for r in attacks)
print(f"**{len(attacks)} attacks, {blocked} blocked as expected, attacker gain {gain} yoctoNEAR.**\n")
print("| id | attack / scenario | expected | observed | attacker gain (yocto) |")
print("|---|---|---|---|---|")
for r in rows:
    print(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} |")
