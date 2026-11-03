// Deterministic tests: every money path is checked for the exact amount, every deadline to the nanosecond. Catches mutations that random fuzz and the attack bench miss.
mod exact {
    use super::*;
    use near_sdk::test_utils::get_logs;

    const U: u128 = UNIT;
    const S: u128 = CREDIT_STORAGE;
    const T0: u64 = 1_000_000 * NS;
    const VALID: u64 = T0 + 1_000_000 * NS;

    struct Opt { vault: u128, stake: u128, bond: u32, premium: u32, limit: u128, n: u32, daily: u32, maxl: u32, scope: Vec<AccountId>, max_tenor: u64, payer: FeePayer, cap: u32 }
    fn opt() -> Opt {
        Opt { vault: 100 * U, stake: 10 * U, bond: 0, premium: 0, limit: 1000 * U, n: 40, daily: 1000, maxl: 5, scope: vec![acc("s1.near"), acc("s2.near")], max_tenor: 1000, payer: FeePayer::Buyer, cap: 0 }
    }

    fn world(o: Opt) -> (Cx, u64) {
        let mut cx = Cx { snap: HashMap::new(), now: T0, bal: 5_000_000 * 1_000_000_000_000_000_000_000_000u128, rng: 1, pending: VecDeque::new(), cells: vec![], roots: vec![], credits: vec![], nextpk: 0, nextinv: 1, ok: Default::default(), fail: Default::default(), hits: Default::default(), log: vec![], sur: 0, last_err: String::new(), token: None, tbal: 0, tsur: 0, invs: vec![] };
        cx.up(&writ(), None, 0);
        let w = Contract::new(acc("owner.near"), None, Some(Windows { accept_ttl: U64(100), inspect: U64(50), grace: U64(50), recourse: U64(100), dispute_timeout: U64(200), unstake_delay: U64(30) }));
        env::state_write(&w);
        drop(w);
        cx.snap = near_sdk::mock::with_mocked_blockchain(|b| b.take_storage());
        let p = pk(0);
        cx.up(&writ(), None, 0);
        let ch = make_chain(o.n as usize, 7);
        let (w0, p2) = (ch[0].clone(), p.clone());
        let id = cx.run("init", &writ(), None, 0, |w| {
            let id = w.next_id; w.next_id += 1;
            w.cells.insert(id, Cell { amc_said: format!("E{}", id), issuer_aid: "A".into(), issuer_pk: "00".repeat(32), agent_pk: p2.clone(), verifier: acc("g.near"), funder: acc("funder.near"),
                lei_commit: "00".repeat(32), ecr_commit: "00".repeat(32), scope: o.scope.clone(), valid_until: U64(VALID), unit: U128(U), n: o.n, idx: 0, w_cur: w0.clone(),
                daily_links: o.daily, max_links: o.maxl, max_strikes: 100, day: T0 / NS_PER_DAY, day_used: 0, vault: U128(o.vault), unclaimed: U128(0), spends: 0, rejects: 0, strikes: 0, status: Status::Active, asset: None, root: id, parent: None, depth: 0, children: vec![], tree_size: 1, near_reserve: U128(0) });
            w.key_to_cell.insert(p2.clone(), id);
            w.used_keys.insert(p2.clone());
            w.vault_total += o.vault;
            w.terms.insert(id, CreditTerms { terms_ecr_commit: String::new(), args: CreditArgs { limit: U128(o.limit), bond_bps: o.bond, premium_bps: o.premium, min_tenor: U64(10), max_tenor: U64(o.max_tenor), terms_hash: "00".repeat(32), terms_sig: "00".repeat(64), entity_tag: "t".into(), arbiter: acc("arb.near"), fee_payer: o.payer, seller_cap_bps: o.cap, asset: None }, guarantor: acc("g.near"), outstanding: U128(0), bond_locked: U128(0), open_debts: 0 });
            id
        }).unwrap();
        cx.cells.push(CellH { id, pk: p, links: ch });
        cx.roots = vec![id];
        cx.run("init2", &writ(), None, 0, |w| { w.verifiers.insert(acc("g.near"), "00".repeat(32)); }).unwrap();
        if o.stake > 0 { cx.run("stake", &acc("g.near"), None, o.stake, |w| w.stake()).unwrap(); }
        (cx, id)
    }

    fn cell(cx: &Cx, id: u64) -> Cell { cx.peek(|w| w.cells.get(&id).cloned().unwrap()) }
    fn cred(cx: &Cx, k: u64) -> Credit { cx.peek(|w| w.credits.get(&k).cloned().unwrap()) }
    fn outstanding(cx: &Cx, r: u64) -> (u128, u128, u32) { cx.peek(|w| { let t = w.terms.get(&r).unwrap(); (t.outstanding.0, t.bond_locked.0, t.open_debts) }) }
    fn stake(cx: &Cx) -> Stake { cx.peek(|w| w.stake_get(&acc("g.near"), &None)) }
    fn claim(cx: &Cx, a: &str) -> Option<u128> { let a = acc(a); cx.peek(|w| w.claimable.get(&(a, None)).copied()) }
    fn total(cx: &Cx) -> u128 { cx.peek(|w| w.vault_total) }
    fn why(v: &Verdict) -> String { if let Verdict::Rejected { reason, .. } = v { reason.clone() } else { String::new() } }
    fn set_vault(cx: &mut Cx, id: u64, v: u128) {
        cx.run("poke", &writ(), None, 0, |w| { let mut c = w.cells.get(&id).cloned().unwrap(); w.vault_total = w.vault_total - c.vault.0 + v; c.vault = U128(v); w.cells.insert(id, c); }).unwrap();
    }
    fn link(cx: &Cx, id: u64, j: u32) -> String {
        let idx = cell(cx, id).idx as usize;
        cx.cells.iter().find(|c| c.id == id).unwrap().links.get(idx + j as usize).cloned().unwrap_or_else(|| "11".repeat(32))
    }
    fn key(cx: &Cx, id: u64) -> PublicKey { cx.cells.iter().find(|c| c.id == id).unwrap().pk.clone() }

    fn open_at(cx: &mut Cx, id: u64, j: u32, due: u64) -> Verdict {
        cx.nextinv += 1;
        let (p, k, inv) = (link(cx, id, j), key(cx, id), hex::encode(env_hash(cx.nextinv)));
        cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, j, acc("s1.near"), inv, U64(due))).expect("open_credit must not panic")
    }
    fn open(cx: &mut Cx, id: u64, j: u32) -> Verdict { let d = cx.now + 500 * NS; open_at(cx, id, j, d) }
    fn opened(v: Verdict) -> u64 { if let Verdict::CreditOpened { credit, .. } = v { credit.0 } else { panic!("not opened: {}", why(&v)) } }
    fn accept(cx: &mut Cx, k: u64) { cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k))).expect("accept"); }
    fn deliver(cx: &mut Cx, k: u64) { cx.run("deliver", &acc("s1.near"), None, 0, |w| w.mark_delivered(U64(k), "ab".repeat(32), None)).expect("deliver"); }
    fn deliver_final(cx: &mut Cx, k: u64, f: u128) -> bool { cx.run("deliver", &acc("s1.near"), None, 0, |w| w.mark_delivered(U64(k), "ab".repeat(32), Some(U128(f)))).is_some() }
    fn settle(cx: &mut Cx, id: u64, k: u64) -> bool { let p = key(cx, id); cx.run("settle", &writ(), Some(&p), 0, |w| { let _ = w.settle(U64(k)); }).is_some() }

    fn hire(cx: &mut Cx, parent: u64, j: u32, f: impl FnOnce(&mut HireArgs)) -> Verdict {
        cx.nextpk += 1;
        let np = cx.nextpk;
        cx.up(&writ(), None, 0);
        let ch = make_chain(j as usize, 100 + np as u64);
        let mut a = HireArgs { agent_pk: pk(np), w0: ch[0].clone(), scope: vec![acc("s1.near")], valid_until: U64(cx.now + 5000 * NS), daily_links: 100, max_links: 5 };
        f(&mut a);
        let (p, k, npk) = (link(cx, parent, j), key(cx, parent), a.agent_pk.clone());
        let v = cx.run("hire", &writ(), Some(&k), 0, |w| w.hire(p, j, a)).expect("hire must not panic");
        if let Verdict::Hired { child, .. } = &v { cx.cells.push(CellH { id: child.0, pk: npk, links: ch }); }
        v
    }
    fn hired(v: Verdict) -> u64 { if let Verdict::Hired { child, .. } = v { child.0 } else { panic!("not hired: {}", why(&v)) } }

    #[test]
    fn fee_and_entity_key_are_exact() {
        assert_eq!(hire_fee(3), 100_000_000_000_000_000_000_000 + 20_000_000_000_000_000_000_000 + 3 * 1_000_000_000_000_000_000_000);
        let (cx, _) = world(opt());
        cx.up(&writ(), None, 0);
        assert_eq!(Contract::entity_key(&acc("g.near"), &None, "t"), "g.near:near:t");
        assert_eq!(Contract::entity_key(&acc("g.near"), &Some(acc("usdc.near")), "t"), "g.near:usdc.near:t");
    }

    #[test]
    fn spend_expires_after_the_exact_nanosecond() {
        let (mut cx, r) = world(opt());
        cx.now = VALID;
        let (p, k) = (link(&cx, r, 1), key(&cx, r));
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), "aa".repeat(32), None); }).unwrap();
        assert_eq!(cell(&cx, r).idx, 1, "still valid at valid_until");
        cx.now = VALID + 1;
        let p = link(&cx, r, 1);
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), "bb".repeat(32), None); }).unwrap();
        assert!(get_logs().iter().any(|l| l.contains("EXPIRED")));
        assert_eq!(cell(&cx, r).idx, 1, "expired one nanosecond later");
        assert_eq!(cell(&cx, r).rejects, 1);
    }

    #[test]
    fn hire_books_are_exact() {
        let (mut cx, r) = world(opt());
        let (v0, t0) = (cell(&cx, r).vault.0, total(&cx));
        let before = cx.peek(|w| w.stats.cells);
        let v = hire(&mut cx, r, 2, |_| {});
        let Verdict::Hired { remaining_links, child, .. } = v else { panic!("not hired") };
        assert_eq!(remaining_links, 38);
        let fee = hire_fee(2);
        let rc = cell(&cx, r);
        assert_eq!(rc.vault.0, v0 - 2 * U - fee);
        assert_eq!(total(&cx), t0 - fee);
        assert_eq!(rc.idx, 2);
        assert_eq!(rc.day_used, 2);
        assert_eq!(rc.tree_size, 2);
        assert_eq!(cx.peek(|w| w.stats.cells), before + 1);
        let ch = cell(&cx, child.0);
        assert_eq!(ch.vault.0, 2 * U);
        assert_eq!(ch.max_strikes, 100, "a child inherits the parent's strike limit");
    }

    #[test]
    fn hire_rate_resets_only_on_a_new_day() {
        let mut o = opt(); o.daily = 2;
        let (mut cx, r) = world(o);
        hired(hire(&mut cx, r, 2, |a| a.daily_links = 2));
        assert_eq!(why(&hire(&mut cx, r, 1, |a| a.daily_links = 2)), "RATE");
        cx.now += NS_PER_DAY;
        hired(hire(&mut cx, r, 1, |a| a.daily_links = 2));
        assert_eq!(cell(&cx, r).day_used, 1);
    }

    #[test]
    fn hire_expiry_boundary() {
        let (mut cx, r) = world(opt());
        cx.now = VALID;
        assert_eq!(why(&hire(&mut cx, r, 1, |a| a.valid_until = U64(VALID))), "HIRE_TERMS", "not expired yet at valid_until");
        cx.now = VALID + 1;
        assert_eq!(why(&hire(&mut cx, r, 1, |a| a.valid_until = U64(VALID))), "EXPIRED");
    }

    #[test]
    fn every_bad_hire_term_is_refused_alone() {
        let bad: Vec<Box<dyn Fn(&mut HireArgs)>> = vec![
            Box::new(|a| a.valid_until = U64(VALID + 1)),
            Box::new(|a| a.valid_until = U64(T0)),
            Box::new(|a| a.daily_links = 0),
            Box::new(|a| a.daily_links = 1001),
            Box::new(|a| a.max_links = 0),
            Box::new(|a| a.max_links = 6),
            Box::new(|a| a.w0 = "zz".into()),
        ];
        for (i, f) in bad.iter().enumerate() {
            let (mut cx, r) = world(opt());
            assert_eq!(why(&hire(&mut cx, r, 1, |a| f(a))), "HIRE_TERMS", "case {}", i);
        }
    }

    #[test]
    fn hire_scope_can_be_exactly_the_maximum() {
        let many: Vec<AccountId> = (0..MAX_SCOPE).map(|i| acc(&format!("s{}.near", i))).collect();
        let mut o = opt(); o.scope = many.clone();
        let (mut cx, r) = world(o);
        hired(hire(&mut cx, r, 1, |a| a.scope = many.clone()));
    }

    #[test]
    fn hire_limit_boundaries() {
        let mut o = opt(); o.n = 3;
        let (mut cx, r) = world(o);
        assert_eq!(why(&hire(&mut cx, r, 0, |_| {})), "LIMIT");
        assert_eq!(why(&hire(&mut cx, r, 4, |_| {})), "LIMIT");
        hired(hire(&mut cx, r, 3, |_| {}));
    }

    #[test]
    fn child_hire_needs_both_budget_and_company_fee() {
        let (mut cx, r) = world(opt());
        let c = hired(hire(&mut cx, r, 3, |_| {}));
        let (rv, cv) = (cell(&cx, r).vault.0, cell(&cx, c).vault.0);
        set_vault(&mut cx, c, 0);
        assert_eq!(why(&hire(&mut cx, c, 1, |_| {})), "FUNDS", "no budget in the child");
        set_vault(&mut cx, c, cv);
        set_vault(&mut cx, r, 0);
        assert_eq!(why(&hire(&mut cx, c, 1, |_| {})), "FUNDS", "company cannot pay the fee");
        set_vault(&mut cx, r, rv);
        hired(hire(&mut cx, c, 1, |_| {}));
    }

    #[test]
    fn a_failed_transfer_is_retained_only_while_something_is_owed() {
        for (out, debts, retained) in [(1u128, 0u32, true), (0, 1, true), (0, 0, false)] {
            let (mut cx, r) = world(opt());
            set_vault(&mut cx, r, 0);
            cx.run("cb", &writ(), None, 0, |w| {
                let mut c = w.cells.get(&r).cloned().unwrap();
                c.status = Status::Revoked { by: acc("funder.near"), evidence: "x".into() };
                w.cells.insert(r, c);
                let mut t = w.terms.get(&r).cloned().unwrap();
                t.outstanding = U128(out); t.open_debts = debts;
                w.terms.insert(r, t);
                let _ = w.on_transfer(U64(r), U128(5), "00".repeat(32), acc("s1.near"), 1, 0, None, Err(PromiseError::Failed));
            }).unwrap();
            assert_eq!(cell(&cx, r).vault.0, if retained { 5 } else { 0 }, "out {} debts {}", out, debts);
            assert_eq!(cx.pending.is_empty(), retained, "out {} debts {}", out, debts);
        }
    }

    #[test]
    fn closing_passes_the_closer_down_and_pays_nothing_when_empty() {
        let (mut cx, r) = world(opt());
        let c = hired(hire(&mut cx, r, 1, |_| {}));
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        let Status::Revoked { by, .. } = cell(&cx, c).status else { panic!("child not closed") };
        assert_eq!(by, acc("funder.near"));

        let (mut cx, r) = world(opt());
        set_vault(&mut cx, r, 0);
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert!(cx.pending.is_empty(), "no refund transfer for an empty vault");
    }

    #[test]
    fn unstake_time_is_exact() {
        let (mut cx, _) = world(opt());
        cx.run("req", &acc("g.near"), None, 0, |w| w.request_unstake(None)).unwrap();
        assert_eq!(stake(&cx).unstake_at.0, T0 + 30 * NS);
    }

    #[test]
    fn open_credit_books_and_day_are_exact() {
        let mut o = opt(); o.daily = 2;
        let (mut cx, r) = world(o);
        let (v0, t0) = (cell(&cx, r).vault.0, total(&cx));
        opened(open(&mut cx, r, 2));
        let c = cell(&cx, r);
        assert_eq!((c.idx, c.day_used), (2, 2));
        assert_eq!(c.vault.0, v0 - S);
        assert_eq!(total(&cx), t0 - S);
        assert_eq!(why(&open(&mut cx, r, 1)), "RATE");
        cx.now += NS_PER_DAY;
        opened(open(&mut cx, r, 1));
        assert_eq!(cell(&cx, r).day_used, 1);
    }

    #[test]
    fn open_credit_boundaries() {
        // deadline
        let (mut cx, r) = world(opt());
        cx.now = VALID;
        opened(open(&mut cx, r, 1));
        cx.now = VALID + 1;
        assert_eq!(why(&open(&mut cx, r, 1)), "EXPIRED");
        // per-order cap
        let mut o = opt(); o.maxl = 2;
        let (mut cx, r) = world(o);
        assert_eq!(why(&open(&mut cx, r, 3)), "PER_TX");
        opened(open(&mut cx, r, 2));
        // chain length
        let mut o = opt(); o.n = 3; o.maxl = 10;
        let (mut cx, r) = world(o);
        assert_eq!(why(&open(&mut cx, r, 0)), "LIMIT");
        assert_eq!(why(&open(&mut cx, r, 4)), "LIMIT");
        opened(open(&mut cx, r, 3));
        // credit limit
        let mut o = opt(); o.limit = 2 * U;
        let (mut cx, r) = world(o);
        opened(open(&mut cx, r, 2));
        assert_eq!(why(&open(&mut cx, r, 1)), "CREDIT_LIMIT");
        // term
        let (mut cx, r) = world(opt());
        let n = cx.now;
        assert_eq!(why(&open_at(&mut cx, r, 1, n + 10 * NS - 1)), "TENOR");
        opened(open_at(&mut cx, r, 1, n + 10 * NS));
        assert_eq!(why(&open_at(&mut cx, r, 1, n + 1000 * NS + 1)), "TENOR");
        opened(open_at(&mut cx, r, 1, n + 1000 * NS));
    }

    #[test]
    fn a_childs_credit_storage_comes_from_the_company() {
        let (mut cx, r) = world(opt());
        let c = hired(hire(&mut cx, r, 2, |_| {}));
        let (rv, cv) = (cell(&cx, r).vault.0, cell(&cx, c).vault.0);
        opened(open(&mut cx, c, 1));
        assert_eq!(cell(&cx, r).vault.0, rv - S);
        assert_eq!(cell(&cx, c).vault.0, cv);
        set_vault(&mut cx, r, 0);
        assert_eq!(why(&open(&mut cx, c, 1)), "FUNDS", "the child's money does not count");
    }

    /// Two orders of 2U each, bond of 1U each, both accepted.
    fn two_bonded(vault: u128) -> (Cx, u64, u64, u64) {
        let mut o = opt(); o.vault = vault; o.bond = 5000;
        let (mut cx, r) = world(o);
        let a = opened(open(&mut cx, r, 2));
        let b = opened(open(&mut cx, r, 2));
        accept(&mut cx, a); accept(&mut cx, b);
        assert_eq!(outstanding(&cx, r).1, 2 * U);
        (cx, r, a, b)
    }

    /// The bond is a hard requirement: a vault short by 1 yocto gives BOND_SHORT and nothing moves; exactly enough stands.
    #[test]
    fn a_bond_is_hard_to_the_exact_yocto() {
        // 100% of 5U: vault minus receipt storage is exactly 5U minus 1
        let mut o = opt(); o.vault = 5 * U + S - 1; o.bond = 10_000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 5));
        let (v0, st0) = (cell(&cx, r).vault.0, stake(&cx));
        cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k)));
        assert_eq!(cred(&cx, k).status, CreditStatus::Open, "BOND_SHORT leaves the order open");
        assert_eq!((cell(&cx, r).vault.0, stake(&cx).exposure.0, st0.exposure.0, outstanding(&cx, r).1), (v0, 0, 0, 0));
        // Adding 1 yocto makes it just stand, and the exposure is only the part without a bond
        set_vault(&mut cx, r, v0 + 1);
        accept(&mut cx, k);
        let c = cred(&cx, k);
        assert_eq!((c.bond_locked.0, c.exposure.0), (5 * U, 0));
        // Fee is deducted first: the bond can only be computed from what is left after the fee
        let mut o = opt(); o.vault = 5 * U + S - 1; o.bond = 8000; o.premium = 2000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 5));
        cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k)));
        assert_eq!(cred(&cx, k).status, CreditStatus::Open, "1U fee + 4U bond is one yocto short");
    }

    /// Periods are counted at acceptance: 1 ns later means one more period.
    #[test]
    fn the_fee_is_per_started_thirty_days() {
        const P: u64 = 30 * 86_400 * NS;
        assert_eq!(NS_PER_PERIOD, P);
        assert_eq!(fee_periods(T0, T0), 1, "due now is still one period");
        assert_eq!(fee_periods(T0, T0 + 1), 1, "past due is still one period");
        assert_eq!(fee_periods(T0 + 1, T0), 1);
        assert_eq!(fee_periods(T0 + P, T0), 1);
        assert_eq!(fee_periods(T0 + P + 1, T0), 2);
        assert_eq!(fee_periods(T0 + 2 * P, T0), 2);
        assert_eq!(fee_periods(T0 + 2 * P + 1, T0), 3);
        assert_eq!(guarantee_fee(10_000, 150, 3), 450);
        assert_eq!(guarantee_fee(9_999, 1, 1), 0, "rounds down");
        for (extra, periods) in [(0u64, 1u128), (1, 2), (P, 2), (P + 1, 3)] {
            let mut o = opt(); o.premium = 100; o.max_tenor = 400 * 86_400;
            let (mut cx, r) = world(o);
            let due = cx.now + P + extra;
            let k = opened(open_at(&mut cx, r, 3, due));
            let v = cell(&cx, r).vault.0;
            accept(&mut cx, k);
            let fee = 3 * U / 100 * periods;
            assert_eq!(cell(&cx, r).vault.0, v - fee, "extra {}", extra);
            assert_eq!(stake(&cx).amount.0, 10 * U + fee);
            assert_eq!(stake(&cx).earned.0, fee);
        }
    }

    /// Periods count from the moment the seller accepts, not from when the order was opened: accepting late can mean one period fewer.
    #[test]
    fn the_periods_count_from_the_acceptance() {
        const P: u64 = 30 * 86_400 * NS;
        let mut o = opt(); o.premium = 100; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + P + 10 * NS;
        let k = opened(open_at(&mut cx, r, 3, due));
        cx.now += 9 * NS;
        let v = cell(&cx, r).vault.0;
        accept(&mut cx, k);
        assert_eq!(cell(&cx, r).vault.0, v - 2 * 3 * U / 100, "1 ns over the first period");
        let mut o = opt(); o.premium = 100; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + P + 10 * NS;
        let k = opened(open_at(&mut cx, r, 3, due));
        cx.now += 10 * NS;
        let v = cell(&cx, r).vault.0;
        accept(&mut cx, k);
        assert_eq!(cell(&cx, r).vault.0, v - 3 * U / 100, "exactly one period left");
        // Accepted after the due date has passed, it still collects only one period
        let mut o = opt(); o.premium = 100;
        let (mut cx, r) = world(o);
        let due = cx.now + 10 * NS;
        let k = opened(open_at(&mut cx, r, 3, due));
        cx.now += 50 * NS;
        let v = cell(&cx, r).vault.0;
        accept(&mut cx, k);
        assert_eq!(cell(&cx, r).vault.0, v - 3 * U / 100);
    }

    /// Seller pays: nothing is collected at acceptance, the fee is fixed on the order.
    fn seller_pays(premium: u32, vault: u128) -> (Cx, u64, u64, u128) {
        let mut o = opt(); o.premium = premium; o.payer = FeePayer::Seller; o.vault = vault;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 4));
        let (v, st) = (cell(&cx, r).vault.0, stake(&cx));
        accept(&mut cx, k);
        assert_eq!(cell(&cx, r).vault.0, v, "nothing is charged at accept");
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (st.amount.0, 0));
        (cx, r, k, 4 * U * premium as u128 / 10_000)
    }

    fn fee_went_to_the_guarantor(cx: &Cx, fee: u128) {
        assert_eq!(claim(cx, "s1.near"), Some(4 * U - fee));
        assert_eq!((stake(cx).amount.0, stake(cx).earned.0), (10 * U + fee, fee));
    }

    #[test]
    fn a_seller_paid_fee_comes_out_of_every_way_the_seller_is_paid() {
        // agent settles
        let (mut cx, r, k, fee) = seller_pays(500, 100 * U);
        assert_eq!(cred(&cx, k).fee.0, fee);
        let (v, t) = (cell(&cx, r).vault.0, total(&cx));
        assert!(settle(&mut cx, r, k));
        assert_eq!(cell(&cx, r).vault.0, v - 4 * U, "the buyer pays the invoice, no more");
        assert_eq!(total(&cx), t, "the fee moved between buckets");
        fee_went_to_the_guarantor(&cx, fee);
        // company settles from the vault
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        cx.run("sf", &acc("funder.near"), None, 0, |w| w.settle_by_funder(U64(k))).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
        // company settles with its own funds
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        cx.run("sf", &acc("funder.near"), None, 4 * U, |w| w.settle_by_funder(U64(k))).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
        // default, the vault pays
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
        // dispute ruled for the seller
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        cx.run("d", &acc("funder.near"), None, 4 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), true)).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
    }

    #[test]
    fn a_seller_paid_fee_on_a_guarantor_paid_default_nets_in_the_stake() {
        let (mut cx, r, k, fee) = seller_pays(500, 2 * U);
        deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        let v = cell(&cx, r).vault.0;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        let debt = 4 * U - v;
        assert_eq!(cred(&cx, k).debt.0, debt, "the company owes the whole amount it could not cover");
        assert_eq!(claim(&cx, "s1.near"), Some(4 * U - fee));
        assert_eq!(stake(&cx).amount.0, 10 * U - debt + fee);
        assert_eq!(stake(&cx).earned.0, fee);
    }

    #[test]
    fn a_cancelled_order_charges_a_seller_paying_nothing() {
        // dispute ruled for the company
        let (mut cx, _, k, _) = seller_pays(500, 100 * U);
        cx.run("d", &acc("funder.near"), None, 4 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), false)).unwrap();
        assert_eq!(claim(&cx, "s1.near"), None);
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (10 * U, 0));
        // accepted but nothing delivered, cancelled on expiry
        let (mut cx, _, k, _) = seller_pays(500, 100 * U);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("x", &acc("x.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert_eq!(cred(&cx, k).status, CreditStatus::Cancelled);
        assert_eq!(claim(&cx, "s1.near"), None);
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (10 * U, 0));
    }

    /// Fee exceeds the payment (very long term): deducted down to zero at most, never charged back to the seller.
    #[test]
    fn a_seller_paid_fee_stops_at_the_amount() {
        const P: u64 = 30 * 86_400 * NS;
        let mut o = opt(); o.premium = 2000; o.payer = FeePayer::Seller; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + 6 * P;
        let k = opened(open_at(&mut cx, r, 4, due));
        accept(&mut cx, k);
        assert_eq!(cred(&cx, k).fee.0, 4 * U, "six periods at 20% would be 120%; the fee stops at the amount");
        assert!(settle(&mut cx, r, k));
        assert_eq!(claim(&cx, "s1.near"), None, "no entry for zero");
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (14 * U, 4 * U));
    }

    #[test]
    fn a_buyer_paid_fee_is_recorded_and_never_taken_from_the_seller() {
        let mut o = opt(); o.premium = 500;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 4));
        accept(&mut cx, k);
        let fee = 4 * U / 20;
        assert_eq!(cred(&cx, k).fee.0, fee);
        assert!(settle(&mut cx, r, k));
        assert_eq!(claim(&cx, "s1.near"), Some(4 * U));
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (10 * U + fee, fee));
    }

    #[test]
    fn a_usage_order_shrinks_everything_to_the_promised_ratio() {
        let mut o = opt(); o.bond = 2500; o.premium = 100; o.limit = 6 * U;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 5));
        accept(&mut cx, k);
        let paid = 5 * U / 100;
        let (v, idx, st) = (cell(&cx, r).vault.0, cell(&cx, r).idx, stake(&cx));
        assert_eq!((outstanding(&cx, r).0, outstanding(&cx, r).1, st.exposure.0), (5 * U, 5 * U / 4, 5 * U * 3 / 4));
        assert!(deliver_final(&mut cx, k, 3 * U));
        assert!(get_logs().iter().any(|l| l.contains("credit_delivered") && l.contains(&format!("\"final_amount\":\"{}\"", 3 * U)) && l.contains(&format!("\"original_amount\":\"{}\"", 5 * U))));
        let c = cred(&cx, k);
        assert_eq!((c.amount.0, c.original_amount.0, c.bond_locked.0, c.exposure.0, c.fee.0), (3 * U, 5 * U, 3 * U / 4, 3 * U * 3 / 4, paid));
        assert_eq!(outstanding(&cx, r), (3 * U, 3 * U / 4, 0));
        assert_eq!(stake(&cx).exposure.0, 3 * U * 3 / 4);
        assert_eq!(stake(&cx).earned.0, paid, "a buyer-paid fee is not refunded");
        assert_eq!(cell(&cx, r).vault.0, v, "the released bond was never moved out of the vault");
        assert_eq!(cell(&cx, r).idx, idx, "the budget links stay spent");
        // Limit restored: under the 6U cap another 3U can still be opened
        opened(open(&mut cx, r, 3));
        assert_eq!(why(&open(&mut cx, r, 1)), "CREDIT_LIMIT");
        // The amount paid is the actual amount
        assert!(settle(&mut cx, r, k));
        assert_eq!(claim(&cx, "s1.near"), Some(3 * U));
        assert_eq!(cell(&cx, r).vault.0, v - S - 3 * U);
    }

    #[test]
    fn final_amount_boundaries() {
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        assert!(!deliver_final(&mut cx, k, 0), "zero");
        assert!(!deliver_final(&mut cx, k, 2 * U + 1), "more than ordered");
        assert_eq!(cred(&cx, k).status, CreditStatus::Accepted);
        assert!(deliver_final(&mut cx, k, 2 * U), "exactly the amount");
        assert_eq!((cred(&cx, k).amount.0, cred(&cx, k).exposure.0), (2 * U, 2 * U));
        // Not yet accepted, already disputed: the amount cannot be changed
        let k = opened(open(&mut cx, r, 2));
        assert!(!deliver_final(&mut cx, k, U), "not accepted");
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, 2 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        assert!(!deliver_final(&mut cx, k, U), "disputed");
        deliver(&mut cx, k);
        assert_eq!(cred(&cx, k).amount.0, 2 * U);
        // 1 yocto is enough: the bond rounds down to 0, exposure 1
        let mut o = opt(); o.bond = 2500;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        assert!(deliver_final(&mut cx, k, 1));
        assert_eq!((cred(&cx, k).bond_locked.0, cred(&cx, k).exposure.0), (0, 1));
        assert_eq!(outstanding(&cx, r), (1, 0, 0));
        assert_eq!(stake(&cx).exposure.0, 1);
    }

    #[test]
    fn a_seller_paid_fee_follows_the_final_amount() {
        const P: u64 = 30 * 86_400 * NS;
        let mut o = opt(); o.premium = 100; o.payer = FeePayer::Seller; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + P + 1;
        let k = opened(open_at(&mut cx, r, 4, due));
        accept(&mut cx, k);
        assert_eq!((cred(&cx, k).fee.0, cred(&cx, k).fee_periods), (4 * U * 2 / 100, 2));
        assert!(deliver_final(&mut cx, k, 3 * U));
        let fee = 3 * U * 2 / 100;
        assert_eq!(cred(&cx, k).fee.0, fee, "two periods on the final amount");
        assert!(settle(&mut cx, r, k));
        assert_eq!(claim(&cx, "s1.near"), Some(3 * U - fee));
        assert_eq!(stake(&cx).earned.0, fee);
    }

    #[test]
    fn a_default_on_a_usage_order_pays_only_the_final_amount() {
        let mut o = opt(); o.vault = U; o.bond = 5000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        accept(&mut cx, k);
        assert!(deliver_final(&mut cx, k, U / 2));
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        let v = cell(&cx, r).vault.0;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        assert_eq!(claim(&cx, "s1.near"), Some(U / 2));
        assert_eq!(cell(&cx, r).vault.0, v - U / 2);
        assert_eq!(cred(&cx, k).debt.0, 0);
        assert_eq!(stake(&cx).exposure.0, 0);
    }

    fn rule(max: u128, tenor: u64, bond: u32, defaults: u32, gs: &[&str]) -> SellerPolicy {
        SellerPolicy { max_amount: U128(max), max_tenor_secs: U64(tenor), min_bond_bps: bond, max_defaults: defaults, guarantors: gs.iter().map(|g| acc(g)).collect(), asset: None, max_fee_bps: 10_000, arbiters: vec![] }
    }
    fn set_rule(cx: &mut Cx, p: Option<SellerPolicy>, dep: u128) -> bool { cx.run("set", &acc("s1.near"), None, dep, |w| w.set_seller_policy(p)).is_some() }
    fn accept_err(cx: &mut Cx, k: u64) -> bool { cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k))).is_none() }
    fn check(cx: &Cx, k: u64, p: Option<SellerPolicy>) -> OrderCheck { cx.peek(|w| w.check_order(U64(k), p)) }

    #[test]
    fn a_policy_costs_a_deposit_once_and_the_excess_goes_straight_back() {
        let (mut cx, _) = world(opt());
        let p = || Some(rule(U, 100, 0, 0, &[]));
        assert!(!set_rule(&mut cx, p(), SELLER_POLICY_STORAGE - 1));
        assert!(cx.peek(|w| w.policies.get(&acc("s1.near")).is_none()));
        let (t, ok) = (total(&cx), set_rule(&mut cx, p(), SELLER_POLICY_STORAGE));
        assert!(ok);
        assert_eq!((total(&cx), claim(&cx, "s1.near")), (t, None), "the deposit pays for storage, it is nobody's money");
        assert!(set_rule(&mut cx, Some(rule(2 * U, 100, 0, 0, &[])), 0), "changing the rule costs nothing");
        assert_eq!(cx.peek(|w| w.seller_policy(acc("s1.near"))).unwrap().max_amount.0, 2 * U);
        let bal = cx.bal;
        assert!(set_rule(&mut cx, p(), 9));
        assert_eq!((total(&cx), claim(&cx, "s1.near"), cx.bal), (t, None, bal), "the excess is transferred back, no row");
        assert!(set_rule(&mut cx, None, 0));
        assert!(cx.peek(|w| w.seller_policy(acc("s1.near"))).is_none());
        assert!(!set_rule(&mut cx, p(), SELLER_POLICY_STORAGE - 1), "setting it again pays again");
        assert!(set_rule(&mut cx, p(), SELLER_POLICY_STORAGE));
        // cap and ratio
        let many: Vec<AccountId> = (0..MAX_POLICY_GUARANTORS).map(|i| acc(&format!("g{}.near", i))).collect();
        let mut q = rule(U, 1, 10_000, 0, &[]);
        q.guarantors = many.clone();
        assert!(set_rule(&mut cx, Some(q.clone()), 0), "exactly the maximum");
        q.guarantors.push(acc("gx.near"));
        assert!(!set_rule(&mut cx, Some(q), 0), "one more");
        assert!(!set_rule(&mut cx, Some(rule(U, 1, 10_001, 0, &[])), 0));
    }

    #[test]
    fn every_rule_refuses_at_its_exact_boundary() {
        // amount
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        assert!(set_rule(&mut cx, Some(rule(2 * U - 1, 10_000, 0, 9, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["ORDER_TOO_LARGE"]);
        assert!(accept_err(&mut cx, k));
        assert_eq!(cred(&cx, k).status, CreditStatus::Open);
        assert!(set_rule(&mut cx, Some(rule(2 * U, 10_000, 0, 9, &[])), 0));
        assert!(check(&cx, k, None).ok);
        accept(&mut cx, k);
        // term
        let (mut cx, r) = world(opt());
        let n = cx.now;
        let k = opened(open_at(&mut cx, r, 1, n + 100 * NS));
        assert!(set_rule(&mut cx, Some(rule(U, 99, 0, 9, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["TENOR_TOO_LONG"]);
        assert!(set_rule(&mut cx, Some(rule(U, 100, 0, 9, &[])), 0));
        assert!(check(&cx, k, None).ok);
        // bond
        let mut o = opt(); o.bond = 2500;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 2501, 9, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["BOND_TOO_LOW"]);
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 2500, 9, &[])), 0));
        assert!(check(&cx, k, None).ok);
        // default count
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 1));
        cx.run("rec", &writ(), None, 0, |w| { w.entities.insert("g.near:near:t".to_string(), EntityRecord { defaults: 2, ..Default::default() }); }).unwrap();
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 0, 1, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["TOO_MANY_DEFAULTS"]);
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 0, 2, &[])), 0));
        assert!(check(&cx, k, None).ok);
        // guarantor list
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 0, 2, &["other.near"])), 0));
        assert_eq!(check(&cx, k, None).reasons, vec!["GUARANTOR_NOT_APPROVED"]);
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 0, 2, &["other.near", "g.near"])), 0));
        assert!(check(&cx, k, None).ok);
    }

    #[test]
    fn check_order_reports_every_reason_and_accept_panics_with_the_first_rule() {
        let mut o = opt(); o.bond = 10_000; o.vault = U; o.stake = 0;
        let (mut cx, r) = world(o);
        let n = cx.now;
        let k = opened(open_at(&mut cx, r, 3, n + 100 * NS));
        cx.run("rec", &writ(), None, 0, |w| { w.entities.insert("g.near:near:t".to_string(), EntityRecord { defaults: 1, ..Default::default() }); }).unwrap();
        let strict = rule(U, 10, 20_000, 0, &["other.near"]);
        let c = check(&cx, k, Some(strict.clone()));
        assert!(!c.ok);
        assert_eq!(c.reasons, vec!["ORDER_TOO_LARGE", "TENOR_TOO_LONG", "BOND_TOO_LOW", "TOO_MANY_DEFAULTS", "GUARANTOR_NOT_APPROVED", "BOND_SHORT"]);
        assert_eq!(c.order["bond"], json_str(3 * U));
        assert_eq!(c.order["exposure"], json_str(0));
        assert_eq!(c.order["policy_applied"], true);
        // The rule passed in is only a query: nothing is stored, accept does not look at it
        assert!(cx.peek(|w| w.policies.get(&acc("s1.near")).is_none()));
        let g = cx.peek(|w| w.check_order(U64(k), None));
        assert_eq!((g.reasons, g.order["policy_applied"].clone()), (vec!["BOND_SHORT".to_string()], Value::Bool(false)));
        // Once stored, accept reports the first reason as an error
        assert!(set_rule(&mut cx, Some(rule(U, 10, 0, 9, &[])), SELLER_POLICY_STORAGE));
        assert!(accept_err(&mut cx, k));
        assert!(cx.last_err.contains("POLICY:ORDER_TOO_LARGE"), "{}", cx.last_err);
    }

    #[test]
    fn check_order_also_sees_what_the_money_and_the_state_would_refuse() {
        // no stake
        let mut o = opt(); o.stake = 0;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        assert_eq!(check(&cx, k, None).reasons, vec!["GUARANTOR_CAPACITY"]);
        // cannot afford the fee, cannot lock the bond
        let mut o = opt(); o.premium = 2000; o.vault = S + 1; o.bond = 5000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        assert_eq!(check(&cx, k, None).reasons, vec!["PREMIUM_SHORT", "BOND_SHORT"]);
        // expired quote, already accepted order
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 1));
        assert!(check(&cx, k, None).ok);
        accept(&mut cx, k);
        assert_eq!(check(&cx, k, None).reasons, vec!["NOT_OPEN"]);
        let k = opened(open(&mut cx, r, 1));
        cx.now += 101 * NS;
        assert_eq!(check(&cx, k, None).reasons, vec!["OFFER_EXPIRED"]);
    }

    fn json_str(v: u128) -> Value { Value::String(v.to_string()) }

    fn to_seller(cx: &Cx, s: &str) -> u128 { let s = acc(s); cx.peek(|w| w.seller_exposure_of(&acc("g.near"), &None, &s)) }
    fn open_to(cx: &mut Cx, id: u64, j: u32, seller: &str) -> u64 {
        cx.nextinv += 1;
        let (p, k, inv, due, s) = (link(cx, id, j), key(cx, id), hex::encode(env_hash(cx.nextinv)), cx.now + 500 * NS, acc(seller));
        opened(cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, j, s, inv, U64(due))).expect("open"))
    }

    #[test]
    fn the_seller_cap_is_exact_and_per_seller() {
        // stake 10U, cap 20%: at most 2U for the same seller
        let mut o = opt(); o.cap = 2000;
        let (mut cx, r) = world(o);
        let (a, b, c) = (open_to(&mut cx, r, 1, "s1.near"), open_to(&mut cx, r, 1, "s1.near"), open_to(&mut cx, r, 1, "s1.near"));
        accept(&mut cx, a);
        assert_eq!(to_seller(&cx, "s1.near"), U);
        accept(&mut cx, b);
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U, "exactly the cap is allowed");
        assert_eq!(check(&cx, c, None).reasons, vec!["SELLER_CONCENTRATION"]);
        assert!(accept_err(&mut cx, c));
        assert!(cx.last_err.contains("SELLER_CONCENTRATION"), "{}", cx.last_err);
        assert_eq!((to_seller(&cx, "s1.near"), stake(&cx).exposure.0), (2 * U, 2 * U));
        // other sellers are not affected
        let d = open_to(&mut cx, r, 2, "s2.near");
        cx.run("accept", &acc("s2.near"), None, 0, |w| w.accept_credit(U64(d))).expect("another seller has its own cap");
        assert_eq!(to_seller(&cx, "s2.near"), 2 * U);
        // settle one order, the limit comes back
        assert!(settle(&mut cx, r, a));
        assert_eq!(to_seller(&cx, "s1.near"), U);
        accept(&mut cx, c);
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U);

        // cap 0 = unlimited; an order with a 100% bond has no exposure and does not count toward the cap
        let mut o = opt(); o.cap = 0;
        let (mut cx, r) = world(o);
        let k = open_to(&mut cx, r, 5, "s1.near");
        accept(&mut cx, k);
        let mut o = opt(); o.cap = 1; o.bond = 10_000;
        let (mut cx, r) = world(o);
        let k = open_to(&mut cx, r, 5, "s1.near");
        accept(&mut cx, k);
        assert_eq!(to_seller(&cx, "s1.near"), 0);
        assert!(cx.peek(|w| !w.seller_exposure.contains_key(&(acc("g.near"), None, acc("s1.near")))), "no entry for zero");
    }

    #[test]
    fn the_seller_exposure_follows_every_way_an_order_ends() {
        // metered order shrinks
        let mut o = opt(); o.bond = 5000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 4));
        accept(&mut cx, k);
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U);
        assert!(deliver_final(&mut cx, k, 2 * U));
        assert_eq!(to_seller(&cx, "s1.near"), U);
        // default: exposure ends, the amount paid out is recorded on the debt
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 0);
        assert!(cx.peek(|w| !w.seller_exposure.contains_key(&(acc("g.near"), None, acc("s1.near")))));
        // accepted but nothing delivered, cancelled on expiry
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("x", &acc("x.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 0);
        // dispute ruled for the company
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, 2 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U, "still exposed during the dispute");
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), false)).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 0);
    }

    fn book(cx: &Cx) -> Value { cx.peek(|w| w.guarantor_book(acc("g.near"), None)).unwrap() }

    #[test]
    fn the_book_adds_up_through_a_default_and_a_repayment() {
        assert!({ let (cx, _) = world({ let mut o = opt(); o.stake = 0; o }); cx.peek(|w| w.guarantor_book(acc("g.near"), None)).is_none() }, "no stake, no book");
        let mut o = opt(); o.vault = U; o.premium = 1000;
        let (mut cx, r) = world(o);
        let b0 = book(&cx);
        assert_eq!(b0["loss_ratio_bps"], Value::Null, "nothing earned yet");
        assert_eq!((b0["stake"].clone(), b0["utilisation_bps"].clone()), (json_str(10 * U), Value::from(0)));
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        let fee = 2 * U / 10;
        deliver(&mut cx, k);
        let b = book(&cx);
        assert_eq!(b["earned"], json_str(fee));
        assert_eq!(b["exposure"], json_str(2 * U));
        assert_eq!(b["stake"], json_str(10 * U + fee));
        assert_eq!(b["utilisation_bps"], Value::from((2 * U * 10_000 / (10 * U + fee)) as u64));
        assert_eq!(b["loss_ratio_bps"], Value::from(0));
        assert_eq!(b["top_sellers"][0]["seller"], "s1.near");
        assert_eq!(b["top_sellers"][0]["exposure"], json_str(2 * U));
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        let v = cell(&cx, r).vault.0;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        let debt = 2 * U - v;
        let b = book(&cx);
        assert_eq!((b["claims_paid"].clone(), b["recovered"].clone(), b["net_loss"].clone()), (json_str(debt), json_str(0), json_str(debt)));
        assert_eq!(b["loss_ratio_bps"], Value::from((debt * 10_000 / fee) as u64));
        assert_eq!(b["exposure"], json_str(0));
        assert_eq!(b["top_sellers"], serde_json::json!([]), "no exposure left");
        // the company repays part from the vault (enforce), then repays the rest with its own funds
        set_vault(&mut cx, r, debt / 2);
        cx.now = cred(&cx, k).recourse_until.0 + 1;
        cx.run("e", &acc("g.near"), None, 0, |w| w.enforce_recourse(U64(k))).unwrap();
        let b = book(&cx);
        assert_eq!((b["recovered"].clone(), b["net_loss"].clone()), (json_str(debt / 2), json_str(debt - debt / 2)));
        let left = cred(&cx, k).debt.0;
        cx.run("re", &acc("funder.near"), None, left, |w| w.reimburse(U64(k))).unwrap();
        let b = book(&cx);
        assert_eq!((b["recovered"].clone(), b["net_loss"].clone(), b["loss_ratio_bps"].clone()), (json_str(debt), json_str(0), Value::from(0)));
        assert_eq!(b["stake"], json_str(10 * U + fee));
    }

    #[test]
    fn the_book_keeps_a_bounded_list_of_the_largest_sellers() {
        let (mut cx, _) = world(opt());
        let g = acc("g.near");
        let names: Vec<AccountId> = (0..MAX_BOOK_SELLERS).map(|i| acc(&format!("b{}.near", i))).collect();
        let (n2, g2) = (names.clone(), g.clone());
        let out = cx.run("book", &writ(), None, 0, move |w| {
            let mut st = Stake::default();
            for (i, s) in n2.iter().enumerate() {
                w.add_seller_exposure(&g2, &None, s, i as u128 + 2);
                w.note_seller(&mut st, &g2, &None, s);
            }
            w.note_seller(&mut st, &g2, &None, &n2[0]);
            assert_eq!(st.sellers.len(), MAX_BOOK_SELLERS, "no duplicate");
            // smaller than the smallest (2): no replacement
            w.add_seller_exposure(&g2, &None, &acc("tiny.near"), 1);
            w.note_seller(&mut st, &g2, &None, &acc("tiny.near"));
            assert!(!st.sellers.contains(&acc("tiny.near")));
            // equal size: no replacement either
            w.add_seller_exposure(&g2, &None, &acc("same.near"), 2);
            w.note_seller(&mut st, &g2, &None, &acc("same.near"));
            assert!(!st.sellers.contains(&acc("same.near")));
            // larger than the smallest: replaces the smallest
            w.add_seller_exposure(&g2, &None, &acc("big.near"), 100);
            w.note_seller(&mut st, &g2, &None, &acc("big.near"));
            assert_eq!(st.sellers.len(), MAX_BOOK_SELLERS);
            assert_eq!(st.sellers[0], acc("big.near"));
            st.amount = U128(1000);
            w.stakes.insert((g2.clone(), None), st);
        });
        assert!(out.is_some(), "{}", cx.last_err);
        let b = book(&cx);
        assert_eq!(b["top_sellers"].as_array().unwrap().len(), 5, "only the top five");
        assert_eq!(b["top_sellers"][0]["seller"], "big.near");
        assert_eq!(b["top_sellers"][1]["exposure"], json_str(MAX_BOOK_SELLERS as u128 + 1), "largest first");
    }

    // ---------------- Token tree: every money path checked again with tokens ----------------

    const R: u128 = 100 * CREDIT_STORAGE; // NEAR reserve used in tests

    /// Token world: the vault and the 10U stake are tokens, with R of NEAR reserve.
    fn tworld(mut o: Opt) -> (Cx, u64, Option<AccountId>) {
        o.stake = 0;
        let v = o.vault;
        o.vault = 0;
        let (mut cx, r) = world(o);
        let t = Some(acc("usdc.near"));
        cx.token = t.clone();
        let t2 = t.clone();
        cx.run("to_token", &writ(), None, 0, |w| {
            let mut c = w.cells.get(&r).cloned().unwrap();
            c.asset = t2.clone();
            c.near_reserve = U128(R);
            w.cells.insert(r, c);
            w.vault_total += R;
            let mut tm = w.terms.get(&r).cloned().unwrap();
            tm.args.asset = t2.clone();
            w.terms.insert(r, tm);
            w.stakes.insert((acc("g.near"), t2.clone()), Stake::default());
        }).unwrap();
        assert!(cx.ft("fund", &acc("funder.near"), v, format!("fund:{}", r)));
        assert!(cx.ft("stake", &acc("g.near"), 10 * U, "stake".into()));
        (cx, r, t)
    }
    fn tok() -> AccountId { acc("usdc.near") }
    fn ttotal(cx: &Cx) -> u128 { cx.peek(|w| w.token_total(tok()).0) }
    fn tstake(cx: &Cx) -> Stake { cx.peek(|w| w.stake_get(&acc("g.near"), &Some(tok()))) }
    fn tclaim(cx: &Cx, a: &str) -> u128 { let a = acc(a); cx.peek(|w| w.claimable_of(a, Some(tok())).0) }
    fn near_claim(cx: &Cx, a: &str) -> u128 { let a = acc(a); cx.peek(|w| w.claimable_of(a, None).0) }
    fn ft_err(cx: &mut Cx, from: &str, amount: u128, msg: String, code: &str) {
        assert!(!cx.ft("ft", &acc(from), amount, msg), "must refuse with {}", code);
        assert!(cx.last_err.contains(code), "{} vs {}", cx.last_err, code);
    }

    #[test]
    fn a_token_order_pays_storage_from_the_near_reserve_and_money_in_the_token() {
        let mut o = opt(); o.premium = 500; o.bond = 2500;
        let (mut cx, r, _) = tworld(o);
        let (v0, t0, near0) = (cell(&cx, r).vault.0, ttotal(&cx), total(&cx));
        assert_eq!(t0, 100 * U + 10 * U);
        let k = opened(open(&mut cx, r, 4));
        let c = cell(&cx, r);
        assert_eq!((c.vault.0, c.near_reserve.0), (v0, R - S), "storage comes out of the NEAR reserve");
        assert_eq!((total(&cx), ttotal(&cx)), (near0 - S, t0));
        assert_eq!(cred(&cx, k).asset, Some(tok()));
        accept(&mut cx, k);
        let fee = 4 * U / 20;
        assert_eq!(cell(&cx, r).vault.0, v0 - fee, "the buyer's fee is in the token");
        assert_eq!((tstake(&cx).amount.0, tstake(&cx).earned.0, tstake(&cx).exposure.0), (10 * U + fee, fee, 3 * U));
        assert_eq!(stake(&cx).amount.0, 0, "the NEAR stake is another book");
        assert_eq!(ttotal(&cx), t0);
        assert!(settle(&mut cx, r, k));
        assert_eq!(tclaim(&cx, "s1.near"), 4 * U);
        assert_eq!(claim(&cx, "s1.near"), None, "nothing in NEAR");
        assert_eq!(ttotal(&cx), t0);
        // Withdrawal goes through ft_transfer; if the books went down, the money went out
        cx.run("w", &acc("s1.near"), None, 0, |w| { let _ = w.withdraw(Some(tok())); }).unwrap();
        assert_eq!((tclaim(&cx, "s1.near"), ttotal(&cx)), (0, t0 - 4 * U));
        cx.resolve(false);
        assert_eq!((tclaim(&cx, "s1.near"), ttotal(&cx)), (0, t0 - 4 * U));
    }

    #[test]
    fn a_failed_token_withdrawal_is_credited_back_once() {
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        assert!(settle(&mut cx, r, k));
        let (t, bal) = (ttotal(&cx), cx.tbal);
        cx.run("w", &acc("s1.near"), None, 0, |w| { let _ = w.withdraw(Some(tok())); }).unwrap();
        assert_eq!((ttotal(&cx), cx.tbal), (t - 2 * U, bal - 2 * U));
        cx.run("w2", &acc("s1.near"), None, 0, |w| { let _ = w.withdraw(Some(tok())); });
        assert!(cx.last_err.contains("NOTHING_TO_WITHDRAW"), "cannot withdraw twice while it is in flight");
        cx.resolve(true);
        assert_eq!((tclaim(&cx, "s1.near"), ttotal(&cx), cx.tbal), (2 * U, t, bal));
        assert_eq!(claim(&cx, "s1.near"), None, "credited in the same asset");
        // A failed stake withdrawal is the same: recorded as withdrawable
        cx.run("r", &acc("g.near"), None, 0, |w| w.request_unstake(Some(tok()))).unwrap();
        cx.now += 31 * NS;
        let (t, st) = (ttotal(&cx), tstake(&cx).amount.0);
        cx.run("ws", &acc("g.near"), None, 0, |w| { let _ = w.withdraw_stake(U128(U), Some(tok())); }).unwrap();
        assert_eq!((tstake(&cx).amount.0, ttotal(&cx)), (st - U, t - U));
        cx.resolve(true);
        assert_eq!((tclaim(&cx, "g.near"), ttotal(&cx)), (U, t));
    }

    #[test]
    fn near_cannot_pay_a_token_order_and_a_token_cannot_pay_a_near_order() {
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        // 2U of yoctoNEAR equals 2U of tokens numerically; it must be rejected
        assert!(cx.run("x", &acc("funder.near"), None, 2 * U, |w| w.settle_by_funder(U64(k))).is_none());
        assert!(cx.last_err.contains("USE_FT_TRANSFER_CALL"), "{}", cx.last_err);
        assert!(cx.run("x", &acc("funder.near"), None, 2 * U, |w| w.dispute(U64(k), "cd".repeat(32))).is_none());
        assert!(cx.last_err.contains("USE_FT_TRANSFER_CALL"), "{}", cx.last_err);
        // a different token pretending to be it
        cx.token = Some(acc("fake.near"));
        ft_err(&mut cx, "funder.near", 2 * U, format!("settle:{}", k), "WRONG_ASSET");
        ft_err(&mut cx, "funder.near", 2 * U, format!("dispute:{}:{}", k, "cd".repeat(32)), "WRONG_ASSET");
        // a fake token cannot open a stake account: it cannot take storage for free
        ft_err(&mut cx, "g.near", U, "stake".into(), "STAKE_ASSET_UNKNOWN");
        assert!(cx.peek(|w| w.stakes.get(&(acc("g.near"), Some(acc("fake.near")))).is_none()));
        // non-verifier
        cx.token = Some(tok());
        ft_err(&mut cx, "x.near", U, "stake".into(), "NOT_A_VERIFIER");
        // stranger, wrong amount
        ft_err(&mut cx, "x.near", 2 * U, format!("settle:{}", k), "ONLY_FUNDER");
        ft_err(&mut cx, "funder.near", U, format!("settle:{}", k), "PARTIAL_DEPOSIT");
        ft_err(&mut cx, "funder.near", U, format!("dispute:{}:{}", k, "cd".repeat(32)), "ESCROW_FULL_AMOUNT");
        ft_err(&mut cx, "funder.near", U, "settle:notanumber".into(), "BAD_MSG");
        ft_err(&mut cx, "funder.near", U, format!("dispute:{}", k), "BAD_MSG");
        // an unreadable msg is fully refunded, no panic
        let (t, bal) = (ttotal(&cx), cx.tbal);
        assert!(cx.ft("ft", &acc("funder.near"), U, "hello".into()));
        assert_eq!((ttotal(&cx), cx.tbal), (t, bal));
        // a NEAR tree does not accept tokens
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        cx.token = Some(tok());
        ft_err(&mut cx, "funder.near", 2 * U, format!("settle:{}", k), "WRONG_ASSET");
        ft_err(&mut cx, "funder.near", 2 * U, format!("reimburse:{}", k), "WRONG_ASSET");
    }

    #[test]
    fn token_excess_comes_back_as_claimable_in_every_payable_path() {
        // settle
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        let t = ttotal(&cx);
        assert!(cx.ft("s", &acc("funder.near"), 2 * U + 7, format!("settle:{}", k)));
        assert_eq!((tclaim(&cx, "funder.near"), tclaim(&cx, "s1.near"), ttotal(&cx)), (7, 2 * U, t + 2 * U + 7));
        // a larger dispute deposit is refunded after the ruling
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        assert!(cx.ft("d", &acc("funder.near"), 2 * U + 3, format!("dispute:{}:{}", k, "cd".repeat(32))));
        assert_eq!(cred(&cx, k).dispute_escrow.0, 2 * U + 3);
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), true)).unwrap();
        assert_eq!((tclaim(&cx, "funder.near"), tclaim(&cx, "s1.near")), (3, 2 * U));
        // ruled for the company: the deposit is fully refunded to the company
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        assert!(cx.ft("d", &acc("funder.near"), 2 * U, format!("dispute:{}:{}", k, "cd".repeat(32))));
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), false)).unwrap();
        assert_eq!((tclaim(&cx, "funder.near"), tclaim(&cx, "s1.near")), (2 * U, 0));
    }

    #[test]
    fn a_token_default_pays_from_the_vault_then_the_token_stake_and_is_repaid_in_the_token() {
        let mut o = opt(); o.vault = U; o.payer = FeePayer::Seller; o.premium = 500;
        let (mut cx, r, _) = tworld(o);
        let k = opened(open(&mut cx, r, 4));
        accept(&mut cx, k);
        deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        let t = ttotal(&cx);
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        let (debt, fee) = (3 * U, 4 * U / 20);
        assert_eq!(cred(&cx, k).debt.0, debt);
        assert_eq!(tclaim(&cx, "s1.near"), 4 * U - fee);
        let st = tstake(&cx);
        assert_eq!((st.amount.0, st.earned.0, st.claims_paid.0, st.exposure.0), (10 * U - debt + fee, fee, debt, 0));
        assert_eq!(ttotal(&cx), t, "the money moved between books");
        // underpaying is not allowed; any overpayment is recorded as withdrawable
        ft_err(&mut cx, "funder.near", debt - 1, format!("reimburse:{}", k), "PAY_FULL_DEBT");
        assert!(cx.ft("re", &acc("funder.near"), debt + 5, format!("reimburse:{}", k)));
        assert_eq!(tclaim(&cx, "funder.near"), 5);
        let st = tstake(&cx);
        assert_eq!((st.amount.0, st.recovered.0), (10 * U + fee, debt));
        assert_eq!(ttotal(&cx), t + debt + 5);
        assert!(cred(&cx, k).status == CreditStatus::Reimbursed);
        let b = cx.peek(|w| w.guarantor_book(acc("g.near"), Some(tok()))).unwrap();
        assert_eq!((b["asset"].clone(), b["net_loss"].clone()), (Value::String("usdc.near".into()), json_str(0)));
    }

    #[test]
    fn closing_a_token_tree_retains_per_asset_and_returns_the_reserve() {
        // no open orders: tokens go back to the legal entity via ft_transfer, the reserve is recorded as NEAR withdrawable
        let (mut cx, r, _) = tworld(opt());
        let (v, t, n) = (cell(&cx, r).vault.0, ttotal(&cx), total(&cx));
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        let c = cell(&cx, r);
        assert_eq!((c.vault.0, c.near_reserve.0), (0, 0));
        assert_eq!((ttotal(&cx), total(&cx)), (t - v, n));
        assert_eq!(near_claim(&cx, "funder.near"), R);
        assert_eq!(cx.tbal, t - v, "the refund left in the token");
        // refund fails: recorded in unclaimed, claimed once
        cx.resolve(true);
        assert_eq!((cell(&cx, r).unclaimed.0, ttotal(&cx)), (v, t));
        cx.run("cr", &acc("funder.near"), None, 0, |w| w.claim_refund(U64(r))).unwrap();
        assert_eq!((cell(&cx, r).unclaimed.0, ttotal(&cx)), (0, t - v));
        cx.resolve(false);
        cx.run("w", &acc("funder.near"), None, 0, |w| { let _ = w.withdraw(None); }).unwrap();
        assert_eq!(total(&cx), n - R);

        // open orders exist: tokens stay in the root cell, the reserve is still refunded (it does not pay claims), released after settlement
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        let (v, t) = (cell(&cx, r).vault.0, ttotal(&cx));
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert_eq!((cell(&cx, r).vault.0, ttotal(&cx)), (v, t), "the tokens stay for the seller");
        assert_eq!(near_claim(&cx, "funder.near"), R - S);
        assert!(cx.pending.is_empty(), "no token refund yet");
        assert!(cx.ft("s", &acc("funder.near"), 2 * U, format!("settle:{}", k)));
        let c = cell(&cx, r);
        assert_eq!((c.vault.0, c.unclaimed.0), (0, v), "released once nothing is owed");
    }

    #[test]
    fn hiring_in_a_token_tree_pays_the_fee_from_the_reserve() {
        let (mut cx, r, _) = tworld(opt());
        let (v, n, t) = (cell(&cx, r).vault.0, total(&cx), ttotal(&cx));
        let c = hired(hire(&mut cx, r, 2, |_| {}));
        let fee = hire_fee(2);
        let rc = cell(&cx, r);
        assert_eq!((rc.vault.0, rc.near_reserve.0, total(&cx), ttotal(&cx)), (v - 2 * U, R - fee, n - fee, t));
        let ch = cell(&cx, c);
        assert_eq!((ch.vault.0, ch.asset.clone(), ch.near_reserve.0), (2 * U, Some(tok()), 0));
        // child cell hires again: budget from the child cell, fee still from the root cell's reserve
        let g = hired(hire(&mut cx, c, 1, |_| {}));
        assert_eq!(cell(&cx, r).near_reserve.0, R - fee - hire_fee(1));
        assert_eq!((cell(&cx, c).vault.0, cell(&cx, g).vault.0), (U, U));
        // child cell opens an order: storage from the root cell's reserve
        let rr = cell(&cx, r).near_reserve.0;
        opened(open(&mut cx, c, 1));
        assert_eq!(cell(&cx, r).near_reserve.0, rr - S);
        // reserve too small: RESERVE, money does not move
        cx.run("poke", &writ(), None, 0, |w| { let mut x = w.cells.get(&r).cloned().unwrap(); w.vault_total -= x.near_reserve.0 - (S - 1); x.near_reserve = U128(S - 1); w.cells.insert(r, x); }).unwrap();
        assert_eq!(why(&open(&mut cx, r, 1)), "RESERVE");
        assert_eq!(why(&hire(&mut cx, r, 1, |_| {})), "RESERVE");
        // top up the reserve: NEAR goes through top_up, the child cell does not accept it
        cx.run("top", &acc("funder.near"), None, S, |w| w.top_up(U64(r))).unwrap();
        assert_eq!(cell(&cx, r).near_reserve.0, 2 * S - 1);
        assert!(cx.run("top", &acc("funder.near"), None, S, |w| w.top_up(U64(c))).is_none());
        opened(open(&mut cx, r, 1));
        // a token cell without credit terms stays HIRE_TOKEN; one with terms no longer does
        let (mut cx, r, _) = tworld(opt());
        cx.run("poke", &writ(), None, 0, |w| { w.terms.remove(&r); }).unwrap();
        assert_eq!(why(&hire(&mut cx, r, 1, |_| {})), "HIRE_TOKEN");
    }

    #[test]
    fn a_token_transfer_that_fails_on_spend_goes_back_to_the_token_vault() {
        let (mut cx, r, _) = tworld(opt());
        let (p, k, t, bal) = (link(&cx, r, 1), key(&cx, r), ttotal(&cx), cx.tbal);
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), "aa".repeat(32), None); }).unwrap();
        assert_eq!((ttotal(&cx), cx.tbal), (t - U, bal - U));
        cx.resolve(true);
        assert_eq!((ttotal(&cx), cx.tbal, cell(&cx, r).vault.0), (t, bal, 100 * U));
        // fails during revocation, open orders remain: stays in the root cell
        let (mut cx, r, _) = tworld(opt());
        let (p, k2) = (link(&cx, r, 1), key(&cx, r));
        cx.run("spend", &writ(), Some(&k2), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), "aa".repeat(32), None); }).unwrap();
        let o = opened(open(&mut cx, r, 1));
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        let (v, t) = (cell(&cx, r).vault.0, ttotal(&cx));
        cx.resolve(true);
        assert_eq!((cell(&cx, r).vault.0, ttotal(&cx)), (v + U, t + U), "retained in the token");
        let _ = o;
    }

    #[test]
    fn risk_card_and_credit_report_the_asset_and_the_reserve() {
        let mut o = opt(); o.payer = FeePayer::Seller; o.cap = 4000;
        let (mut cx, r, _) = tworld(o);
        let card = cx.peek(|w| w.risk_card(U64(r))).unwrap();
        assert_eq!(card["asset"], "usdc.near");
        assert_eq!(card["near_reserve"], json_str(R));
        assert_eq!(card["fee_payer"], "Seller");
        assert_eq!(card["seller_cap_bps"], 4000);
        let k = opened(open(&mut cx, r, 1));
        assert_eq!(check(&cx, k, None).order["asset"], "usdc.near");
        let rc = cx.peek(|w| w.liability_receipt(U64(k))).unwrap();
        assert_eq!(rc["asset"], "usdc.near");
    }

    /// A new account with 1 yocto attached cannot take a storage row for free (F1).
    #[test]
    fn a_stranger_cannot_create_a_row_for_one_yocto() {
        let (mut cx, _) = world(opt());
        let (t, bal) = (total(&cx), cx.bal);
        cx.run("set", &acc("stranger.near"), None, 1, |w| w.set_seller_policy(None)).unwrap();
        assert_eq!(claim(&cx, "stranger.near"), None);
        assert!(cx.peek(|w| w.policies.get(&acc("stranger.near")).is_none()));
        assert_eq!((total(&cx), cx.bal), (t, bal));
    }

    /// A rule without an asset cannot open (F2).
    #[test]
    fn a_rule_must_name_its_asset() {
        let base = serde_json::json!({"max_amount": "1", "max_tenor_secs": "1", "min_bond_bps": 0, "max_defaults": 0, "guarantors": [], "max_fee_bps": 0, "arbiters": []});
        assert!(serde_json::from_value::<SellerPolicy>(base.clone()).is_err(), "missing asset");
        let mut near = base.clone();
        near["asset"] = Value::Null;
        assert_eq!(serde_json::from_value::<SellerPolicy>(near).unwrap().asset, None);
        let mut t = base;
        t["asset"] = Value::String("usdc.near".into());
        assert_eq!(serde_json::from_value::<SellerPolicy>(t).unwrap().asset, Some(tok()));
    }

    #[test]
    fn the_new_rules_refuse_the_asset_the_fee_and_the_arbiter_alone() {
        // different asset: the NEAR cap number does not apply to a token order, and the reverse is also true
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 1));
        assert_eq!(check(&cx, k, Some(rule(10 * U, 10_000, 0, 9, &[]))).reasons, vec!["ASSET_NOT_APPROVED"]);
        let mut q = rule(10 * U, 10_000, 0, 9, &[]);
        q.asset = Some(tok());
        assert!(check(&cx, k, Some(q)).ok);
        // fee: 5% rate, a rule of exactly 500 bps passes, 499 does not; counts whether buyer or seller pays
        for payer in [FeePayer::Buyer, FeePayer::Seller] {
            let mut o = opt(); o.premium = 500; o.payer = payer;
            let (mut cx, r) = world(o);
            let k = opened(open(&mut cx, r, 4));
            let mut q = rule(10 * U, 10_000, 0, 9, &[]);
            q.max_fee_bps = 499;
            assert_eq!(check(&cx, k, Some(q.clone())).reasons, vec!["FEE_TOO_HIGH"]);
            q.max_fee_bps = 500;
            assert!(check(&cx, k, Some(q)).ok);
        }
        // arbiter
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 1));
        let mut q = rule(10 * U, 10_000, 0, 9, &[]);
        q.arbiters = vec![acc("friend.near")];
        assert_eq!(check(&cx, k, Some(q.clone())).reasons, vec!["ARBITER_NOT_APPROVED"]);
        q.arbiters.push(acc("arb.near"));
        assert!(check(&cx, k, Some(q.clone())).ok);
        // list cap
        let (mut cx, _) = world(opt());
        q.arbiters = (0..MAX_POLICY_GUARANTORS).map(|i| acc(&format!("a{}.near", i))).collect();
        assert!(set_rule(&mut cx, Some(q.clone()), SELLER_POLICY_STORAGE));
        q.arbiters.push(acc("ax.near"));
        assert!(!set_rule(&mut cx, Some(q), 0));
        assert!(cx.last_err.contains("POLICY_TOO_LONG"), "{}", cx.last_err);
    }

    /// A fake token cannot inflate the record of a real asset; a full record does not block settlement (F3).
    #[test]
    fn the_entity_record_is_per_asset_and_cannot_overflow_a_settlement() {
        let (mut cx, r, _) = tworld(opt());
        let k = opened(open(&mut cx, r, 1));
        accept(&mut cx, k);
        let (a, b) = (Contract::entity_key(&acc("g.near"), &None, "t"), Contract::entity_key(&acc("g.near"), &Some(tok()), "t"));
        let b2 = b.clone();
        cx.run("poke", &writ(), None, 0, |w| { w.entities.insert(b2, EntityRecord { settled_amount: U128(u128::MAX - 1), ..Default::default() }); }).unwrap();
        assert!(settle(&mut cx, r, k), "a saturated record does not block a settlement");
        let rec = cx.peek(|w| w.entities.get(&b).cloned().unwrap());
        assert_eq!((rec.settled, rec.settled_amount.0), (1, u128::MAX));
        assert!(cx.peek(|w| w.entities.get(&a).is_none()), "the NEAR record is another record");
        assert_eq!(cx.peek(|w| w.risk_card(U64(r))).unwrap()["settled"], 1);
    }

    /// The fee paid by the buyer is at most the amount (F5).
    #[test]
    fn a_buyer_paid_fee_stops_at_the_amount() {
        const P: u64 = 30 * 86_400 * NS;
        let mut o = opt(); o.premium = 2000; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + 13 * P;
        let k = opened(open_at(&mut cx, r, 1, due));
        let v = cell(&cx, r).vault.0;
        accept(&mut cx, k);
        assert_eq!(cell(&cx, r).vault.0, v - U, "13 periods at 20% would be 2.6 times the order");
        assert_eq!((stake(&cx).earned.0, cred(&cx, k).fee.0), (U, U));
        assert_eq!(guarantee_fee(100, 2000, 5), 100);
        assert_eq!(guarantee_fee(100, 2000, 4), 80);
    }

    /// After removal from the allowlist no new orders are accepted; accepted ones end as usual (F7).
    #[test]
    fn a_delisted_guarantor_takes_no_new_orders() {
        let (mut cx, r) = world(opt());
        let (old, new) = (opened(open(&mut cx, r, 1)), opened(open(&mut cx, r, 1)));
        accept(&mut cx, old);
        cx.run("delist", &acc("owner.near"), None, 0, |w| w.set_verifier(acc("g.near"), None)).unwrap();
        assert_eq!(check(&cx, new, None).reasons, vec!["GUARANTOR_DELISTED"]);
        assert!(accept_err(&mut cx, new));
        assert!(cx.last_err.contains("GUARANTOR_DELISTED"), "{}", cx.last_err);
        assert!(settle(&mut cx, r, old), "what it already backs still ends normally");
    }

    /// The rule passed in is only a trial; would_accept looks at the stored rule; after acceptance it reports the values fixed on the order (F8).
    #[test]
    fn check_order_separates_what_if_from_what_accept_will_do() {
        const P: u64 = 30 * 86_400 * NS;
        let mut o = opt(); o.premium = 100; o.bond = 2500; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + P + 10 * NS;
        let k = opened(open_at(&mut cx, r, 4, due));
        assert!(set_rule(&mut cx, Some(rule(U, 90 * 86_400, 0, 9, &[])), SELLER_POLICY_STORAGE));
        let c = check(&cx, k, None);
        assert_eq!((c.ok, c.would_accept), (false, false));
        let c = check(&cx, k, Some(rule(10 * U, 90 * 86_400, 0, 9, &[])));
        assert_eq!((c.ok, c.would_accept), (true, false), "a lenient what-if does not promise an accept");
        assert!(accept_err(&mut cx, k));
        assert!(set_rule(&mut cx, Some(rule(10 * U, 90 * 86_400, 0, 9, &[])), 0));
        let c = check(&cx, k, Some(rule(U, 90 * 86_400, 0, 9, &[])));
        assert_eq!((c.ok, c.would_accept), (false, true), "a strict what-if does not stop an accept");
        let quoted = 4 * U * 2 / 100;
        assert_eq!(check(&cx, k, None).order["fee"], json_str(quoted));
        accept(&mut cx, k);
        // One period has passed, a fresh trial would charge less; what is reported is the order's
        cx.now += 11 * NS;
        let c = check(&cx, k, None);
        assert_eq!((c.order["fee"].clone(), c.order["fee_periods"].clone()), (json_str(quoted), Value::from(2)));
        assert_eq!((c.order["bond"].clone(), c.order["exposure"].clone()), (json_str(U), json_str(3 * U)));
        assert_eq!((c.ok, c.would_accept), (false, false));
    }

    /// Running out of reserve is not the agent's fault: no strike, the key is not deleted (F9).
    #[test]
    fn running_out_of_reserve_costs_no_strike() {
        let (mut cx, r, _) = tworld(opt());
        cx.run("poke", &writ(), None, 0, |w| { let mut x = w.cells.get(&r).cloned().unwrap(); w.vault_total -= x.near_reserve.0; x.near_reserve = U128(0); x.max_strikes = 1; w.cells.insert(r, x); }).unwrap();
        assert_eq!(why(&open(&mut cx, r, 1)), "RESERVE");
        assert_eq!(why(&hire(&mut cx, r, 1, |_| {})), "RESERVE");
        let c = cell(&cx, r);
        assert_eq!((c.strikes, c.rejects, c.status.clone()), (0, 2, Status::Active));
        // Insufficient token budget is still FUNDS, strike counted
        let mut o = opt(); o.vault = 0;
        let (mut cx, r, _) = tworld(o);
        assert_eq!(why(&hire(&mut cx, r, 1, |_| {})), "FUNDS");
        assert_eq!(cell(&cx, r).strikes, 1);
    }

    /// Called back during a transfer (malicious token): the signer is still the agent, but the caller is not the contract itself (F12).
    #[test]
    fn agent_methods_refuse_a_call_coming_from_another_contract() {
        let (mut cx, r) = world(opt());
        let c = hired(hire(&mut cx, r, 1, |_| {}));
        let k = opened(open(&mut cx, r, 1));
        accept(&mut cx, k);
        let (p, pk_, evil) = (link(&cx, r, 1), key(&cx, r), acc("usdc.near"));
        let before = cell(&cx, r).idx;
        let (p2, p3, p4) = (p.clone(), p.clone(), p.clone());
        assert!(cx.run("x", &evil, Some(&pk_), 0, |w| { let _ = w.spend(p2, 1, acc("s1.near"), "aa".repeat(32), None); }).is_none());
        assert!(cx.last_err.contains("NOT_AGENT_KEY"), "{}", cx.last_err);
        assert!(cx.run("x", &evil, Some(&pk_), 0, |w| { let _ = w.open_credit(p3, 1, acc("s1.near"), "ab".repeat(32), U64(T0 + 500 * NS)); }).is_none());
        assert!(cx.last_err.contains("NOT_AGENT_KEY"));
        assert!(cx.run("x", &evil, Some(&pk_), 0, |w| { let _ = w.settle(U64(k)); }).is_none());
        assert!(cx.last_err.contains("NOT_AGENT_KEY"));
        assert!(cx.run("x", &evil, Some(&pk_), 0, |w| w.dismiss(U64(c))).is_none());
        assert!(cx.last_err.contains("NOT_AGENT_KEY"));
        let args = HireArgs { agent_pk: pk(200), w0: "11".repeat(32), scope: vec![acc("s1.near")], valid_until: U64(T0 + 100 * NS), daily_links: 1, max_links: 1 };
        assert!(cx.run("x", &evil, Some(&pk_), 0, |w| { let _ = w.hire(p4, 1, args); }).is_none());
        assert!(cx.last_err.contains("NOT_AGENT_KEY"));
        assert_eq!(cell(&cx, r).idx, before);
        // The key signing directly (predecessor == signer == contract) works as usual
        assert!(settle(&mut cx, r, k));
    }

    #[test]
    fn settle_may_use_only_its_own_bond() {
        let (mut cx, r, a, _) = two_bonded(3 * U);
        assert!(!settle(&mut cx, r, a), "the other order's bond is not available");
        let (mut cx, r, a, _) = two_bonded(4 * U);
        assert!(settle(&mut cx, r, a));
        assert_eq!(cell(&cx, r).vault.0, 2 * U - 2 * S);
        assert_eq!(outstanding(&cx, r), (2 * U, U, 0));
        let rec = cx.peek(|w| w.entities.get("g.near:near:t").cloned().unwrap());
        assert_eq!(rec.settled_amount.0, 2 * U);
    }

    #[test]
    fn settle_by_funder_from_the_vault_uses_only_its_own_bond() {
        let (mut cx, _, a, _) = two_bonded(3 * U);
        assert!(cx.run("sf", &acc("funder.near"), None, 0, |w| w.settle_by_funder(U64(a))).is_none());
        let (mut cx, r, a, _) = two_bonded(4 * U);
        let t = total(&cx);
        cx.run("sf", &acc("funder.near"), None, 0, |w| w.settle_by_funder(U64(a))).unwrap();
        assert_eq!(cell(&cx, r).vault.0, 2 * U - 2 * S);
        assert_eq!(total(&cx), t);
        assert_eq!(claim(&cx, "s1.near"), Some(2 * U));
    }

    #[test]
    fn settle_by_funder_returns_exactly_the_excess() {
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        let t = total(&cx);
        cx.run("sf", &acc("funder.near"), None, 2 * U, |w| w.settle_by_funder(U64(k))).unwrap();
        assert_eq!(claim(&cx, "funder.near"), None, "no excess, no entry");
        assert_eq!(total(&cx), t + 2 * U);

        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        let t = total(&cx);
        cx.run("sf", &acc("funder.near"), None, 2 * U + 7, |w| w.settle_by_funder(U64(k))).unwrap();
        assert_eq!(claim(&cx, "funder.near"), Some(7));
        assert_eq!(total(&cx), t + 2 * U + 7);
    }

    #[test]
    fn a_failed_withdrawal_is_credited_back() {
        let (mut cx, _) = world(opt());
        let t = total(&cx);
        cx.run("cb", &writ(), None, 0, |w| w.on_withdraw(acc("s1.near"), U128(5), None, Ok(()))).unwrap();
        assert_eq!((claim(&cx, "s1.near"), total(&cx)), (None, t));
        cx.run("cb", &writ(), None, 0, |w| w.on_withdraw(acc("s1.near"), U128(5), None, Err(PromiseError::Failed))).unwrap();
        assert_eq!((claim(&cx, "s1.near"), total(&cx)), (Some(5), t + 5));
    }

    #[test]
    fn dispute_books_are_exact() {
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, 2 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        assert_eq!(cred(&cx, k).recourse_until.0, T0 + 200 * NS);
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), true)).unwrap();
        assert_eq!(claim(&cx, "funder.near"), None, "an exact escrow leaves nothing to return");
        assert_eq!(claim(&cx, "s1.near"), Some(2 * U));
    }

    #[test]
    fn guarantor_may_claim_only_after_the_due_date_window() {
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 1));
        accept(&mut cx, k); deliver(&mut cx, k);
        let due = cred(&cx, k).due_at.0;
        cx.now = due + 150 * NS;
        assert!(cx.run("c", &acc("g.near"), None, 0, |w| w.claim_default(U64(k))).is_none(), "not stale at the boundary");
        cx.now += 1;
        cx.run("c", &acc("g.near"), None, 0, |w| w.claim_default(U64(k))).expect("stale one nanosecond later");
        assert!(cred(&cx, k).status == CreditStatus::Defaulted);
    }

    #[test]
    fn guarantor_may_claim_only_after_the_delivery_window() {
        let (mut cx, r) = world(opt());
        let n = cx.now;
        let k = opened(open_at(&mut cx, r, 1, n + 10 * NS));
        accept(&mut cx, k);
        cx.now += 80 * NS;
        deliver(&mut cx, k);
        cx.now = T0 + 80 * NS + 150 * NS;
        assert!(cx.run("c", &acc("g.near"), None, 0, |w| w.claim_default(U64(k))).is_none(), "delivered too recently");
        cx.now += 1;
        cx.run("c", &acc("g.near"), None, 0, |w| w.claim_default(U64(k))).expect("stale one nanosecond later");
    }

    #[test]
    fn default_takes_the_child_first_then_the_company() {
        let (mut cx, r) = world(opt());
        let c = hired(hire(&mut cx, r, 2, |_| {}));
        let k = opened(open(&mut cx, c, 2));
        accept(&mut cx, k); deliver(&mut cx, k);
        set_vault(&mut cx, c, U);
        let (rv, st) = (cell(&cx, r).vault.0, stake(&cx).amount.0);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        assert_eq!(cell(&cx, c).vault.0, 0);
        assert_eq!(cell(&cx, r).vault.0, rv - U);
        assert_eq!(stake(&cx).amount.0, st);
        assert_eq!(cred(&cx, k).debt.0, 0);
    }

    #[test]
    fn default_uses_its_own_bond_but_not_the_other_orders() {
        let (mut cx, r, a, _) = two_bonded(4 * U);
        deliver(&mut cx, a);
        cx.now = cred(&cx, a).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(a))).unwrap();
        assert_eq!(cred(&cx, a).debt.0, 0);
        assert_eq!(cell(&cx, r).vault.0, 2 * U - 2 * S);
        // When the vault is short, the other order's 1U bond cannot be touched, the guarantor pays the difference
        let (mut cx, r, a, _) = two_bonded(3 * U);
        deliver(&mut cx, a);
        cx.now = cred(&cx, a).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(a))).unwrap();
        assert_eq!(cred(&cx, a).debt.0, 2 * S);
        assert_eq!(cell(&cx, r).vault.0, U, "the other order's bond stays");
        assert_eq!(outstanding(&cx, r).1, U);
    }

    #[test]
    fn cancelling_an_offer_does_not_invent_a_stake() {
        let mut o = opt(); o.stake = 0;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        cx.run("x", &acc("funder.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert!(cx.peek(|w| w.stakes.get(&(acc("g.near"), None)).is_none()), "a guarantor that never staked has no stake entry");
    }

    #[test]
    fn enforce_collects_the_childs_money_too() {
        let mut o = opt(); o.vault = 4 * U;
        let (mut cx, r) = world(o);
        let c = hired(hire(&mut cx, r, 2, |_| {}));
        let k = opened(open(&mut cx, r, 5));
        accept(&mut cx, k); deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        let (d, st) = (cred(&cx, k).debt.0, stake(&cx).amount.0);
        assert!(d > 2 * U);
        assert_eq!(cell(&cx, c).vault.0, 2 * U, "a default does not reach into a sibling's budget");
        cx.now = cred(&cx, k).recourse_until.0 + 1;
        cx.run("e", &acc("g.near"), None, 0, |w| w.enforce_recourse(U64(k))).unwrap();
        assert!(matches!(cell(&cx, c).status, Status::Revoked { .. }));
        assert_eq!(cell(&cx, c).vault.0, 0);
        assert_eq!(cell(&cx, r).vault.0, 0);
        assert_eq!(cred(&cx, k).debt.0, d - 2 * U);
        assert_eq!(stake(&cx).amount.0, st + 2 * U);
    }

    /// The vault is short, the guarantor paid 1U+S.
    fn in_debt() -> (Cx, u64, u64, u128) {
        let mut o = opt(); o.vault = U;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k); deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        let d = cred(&cx, k).debt.0;
        assert_eq!(d, U + S);
        assert_eq!(stake(&cx).amount.0, 10 * U - d);
        (cx, r, k, d)
    }

    #[test]
    fn reimburse_uses_the_free_vault_then_the_deposit() {
        let (mut cx, r, k, _) = in_debt();
        set_vault(&mut cx, r, U);
        let t = total(&cx);
        cx.run("re", &acc("funder.near"), None, S + 7, |w| w.reimburse(U64(k))).unwrap();
        assert_eq!(cell(&cx, r).vault.0, 0);
        assert_eq!(stake(&cx).amount.0, 10 * U);
        assert_eq!(claim(&cx, "funder.near"), Some(7));
        assert_eq!(total(&cx), t + S + 7);
        assert_eq!(outstanding(&cx, r).2, 0);
        assert!(cred(&cx, k).status == CreditStatus::Reimbursed);
    }

    #[test]
    fn reimburse_with_the_exact_deposit_leaves_no_entry() {
        let (mut cx, _, k, d) = in_debt();
        cx.run("re", &acc("funder.near"), None, d, |w| w.reimburse(U64(k))).unwrap();
        assert_eq!(claim(&cx, "funder.near"), None);
    }

    #[test]
    fn enforce_collects_what_is_left_in_the_tree() {
        let (mut cx, r, k, d) = in_debt();
        set_vault(&mut cx, r, U);
        cx.now = cred(&cx, k).recourse_until.0 + 1;
        cx.run("e", &acc("g.near"), None, 0, |w| w.enforce_recourse(U64(k))).unwrap();
        assert!(get_logs().iter().any(|l| l.contains("credit_enforced")));
        assert_eq!(cell(&cx, r).vault.0, 0);
        assert_eq!(cred(&cx, k).debt.0, d - U);
        assert!(cred(&cx, k).status == CreditStatus::Enforced);
        assert_eq!(outstanding(&cx, r).2, 1);
        assert_eq!(stake(&cx).amount.0, 10 * U - d + U);
    }

    #[test]
    fn enforce_that_repays_in_full_closes_the_debt() {
        let (mut cx, r, k, d) = in_debt();
        set_vault(&mut cx, r, d + 3);
        cx.now = cred(&cx, k).recourse_until.0 + 1;
        cx.run("e", &acc("g.near"), None, 0, |w| w.enforce_recourse(U64(k))).unwrap();
        assert!(get_logs().iter().any(|l| l.contains("credit_reimbursed")));
        assert_eq!(cred(&cx, k).debt.0, 0);
        assert!(cred(&cx, k).status == CreditStatus::Reimbursed);
        assert_eq!(outstanding(&cx, r).2, 0);
        assert_eq!(stake(&cx).amount.0, 10 * U);
        let c = cell(&cx, r);
        assert_eq!((c.vault.0, c.unclaimed.0), (0, 3), "what is left becomes refundable");
    }

    fn open_inv(cx: &mut Cx, id: u64, inv: &str) -> Verdict {
        let (p, k, due) = (link(cx, id, 1), key(cx, id), cx.now + 500 * NS);
        let inv = inv.to_string();
        cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, 1, acc("s1.near"), inv, U64(due))).expect("open_credit must not panic")
    }
    fn paid(cx: &Cx, r: u64, inv: &str) -> bool { let inv = inv.to_string(); cx.peek(|w| w.invoice_paid(U64(r), inv)) }

    #[test]
    fn an_invoice_counts_as_paid_only_when_money_moved() {
        let inv = "aa".repeat(32);
        // open order, accept: not paid yet
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        assert!(!paid(&cx, r, &inv), "an open order is not a payment");
        accept(&mut cx, k);
        assert!(!paid(&cx, r, &inv));
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE", "but it cannot be ordered twice");
        // settle: paid, and cannot be opened again
        assert!(settle(&mut cx, r, k));
        assert!(paid(&cx, r, &inv));
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE");

        // cancel: nobody received money, the invoice is put back
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        cx.run("x", &acc("funder.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert!(!paid(&cx, r, &inv));
        opened(open_inv(&mut cx, r, &inv));

        // default: the seller got the money
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        accept(&mut cx, k); deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        assert!(paid(&cx, r, &inv), "the seller was paid");
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE");

        // dispute ruled for the company: nobody received money
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), false)).unwrap();
        assert!(!paid(&cx, r, &inv));
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE", "a ruling against the seller keeps blocking the invoice");
    }

    #[test]
    fn an_unruled_timeout_without_delivery_frees_the_invoice() {
        let inv = "cc".repeat(32);
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        cx.now = cred(&cx, k).recourse_until.0 + 1;
        cx.run("t", &acc("x.near"), None, 0, |w| w.resolve_timeout(U64(k))).unwrap();
        assert!(!paid(&cx, r, &inv));
        opened(open_inv(&mut cx, r, &inv));
        // A timeout with delivery counts as the seller winning: the invoice counts as paid
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        deliver(&mut cx, k);
        cx.now = cred(&cx, k).recourse_until.0 + 1;
        cx.run("t", &acc("x.near"), None, 0, |w| w.resolve_timeout(U64(k))).unwrap();
        assert!(paid(&cx, r, &inv));
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE");
    }

    #[test]
    fn a_spend_counts_as_paid_only_after_the_transfer_lands() {
        let inv = "bb".repeat(32);
        let (mut cx, r) = world(opt());
        let (p, k) = (link(&cx, r, 1), key(&cx, r));
        let i2 = inv.clone();
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i2, None); }).unwrap();
        assert!(!paid(&cx, r, &inv), "still in flight");
        cx.resolve(false);
        assert!(paid(&cx, r, &inv), "the transfer landed");

        let (mut cx, r) = world(opt());
        let (p, k) = (link(&cx, r, 1), key(&cx, r));
        let i2 = inv.clone();
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i2, None); }).unwrap();
        cx.resolve(true);
        assert!(!paid(&cx, r, &inv), "the transfer failed");
        let (p, i2) = (link(&cx, r, 1), inv.clone());
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i2, None); }).unwrap();
        assert_eq!(cell(&cx, r).spends, 1, "and the invoice can be paid again");
    }

    #[test]
    fn the_revoked_event_says_whether_money_was_returned() {
        let (mut cx, r) = world(opt());
        let v = cell(&cx, r).vault.0;
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert!(get_logs().iter().any(|l| l.contains("revoked") && l.contains(&format!("\"refund\":\"{}\"", v)) && l.contains("\"retained\":\"0\"")));

        let (mut cx, r) = world(opt());
        opened(open(&mut cx, r, 1));
        let v = cell(&cx, r).vault.0;
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert!(get_logs().iter().any(|l| l.contains("revoked") && l.contains("\"refund\":\"0\"") && l.contains(&format!("\"retained\":\"{}\"", v))));
    }

    #[test]
    fn retained_money_is_released_only_after_the_last_order() {
        let (mut cx, r, a, b) = two_bonded(10 * U);
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        let v = cell(&cx, r).vault.0;
        assert_eq!(v, 10 * U - 2 * S);
        cx.run("sf", &acc("funder.near"), None, 2 * U, |w| w.settle_by_funder(U64(a))).unwrap();
        let c = cell(&cx, r);
        assert_eq!((c.vault.0, c.unclaimed.0), (v, 0), "one order is still open");
        cx.run("sf", &acc("funder.near"), None, 2 * U, |w| w.settle_by_funder(U64(b))).unwrap();
        let c = cell(&cx, r);
        assert_eq!((c.vault.0, c.unclaimed.0), (0, v), "everything is settled, the rest is refundable");
    }

    // ---------------- Cover: who pays when the agent was fooled ----------------
    // Numbered comments refer to the required list in the design review.
    mod cover {
    use super::*;
    use near_sdk::test_utils::get_logs;

    const DAY: u64 = 86_400;

    /// Puts a cover on the root, as register would. Default world: dispute_timeout 200 s.
    fn offer(cx: &mut Cx, r: u64, limit: u128, ded: u32, fee: u32, window: u64) {
        let at = cx.now;
        cx.run("offer", &writ(), None, 0, |w| {
            w.covers.insert(r, Cover { args: CoverArgs { limit: U128(limit), deductible_bps: ded, premium_bps: fee, claim_window: U64(window), arbiter: acc("arb.near"), terms_hash: "00".repeat(32) }, guarantor: acc("g.near"), state: CoverState::Offered, premium: U128(0), paid: U128(0), locked: U128(0), open_claim: None, needs_clear: false, upheld: 0, denied: 0, timed_out: 0, offered_at: U64(at) });
        }).unwrap();
    }
    fn activate(cx: &mut Cx, r: u64) -> bool { cx.run("activate", &acc("g.near"), None, 0, |w| w.activate_cover(U64(r))).is_some() }
    /// A world with cover already active: limit 8 units, 20% deductible, no fee, window 1000 s.
    fn active() -> (Cx, u64) {
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, 8 * U, 2000, 0, 1000);
        assert!(activate(&mut cx, r));
        (cx, r)
    }
    fn inv(n: u64) -> String { hex::encode(env_hash(1_000_000 + n)) }
    fn try_pay(cx: &mut Cx, id: u64, j: u32, n: u64, context: Option<String>) -> Option<Verdict> {
        let (p, k, i) = (link(cx, id, j), key(cx, id), inv(n));
        let root = cell(cx, id).root;
        cx.invs.push((root, i.clone()));
        let v = cx.run("spend", &writ(), Some(&k), 0, |w| match w.spend(p, j, acc("s1.near"), i, context) { PromiseOrValue::Value(v) => Some(v), _ => None }).expect("spend must not panic");
        while !cx.pending.is_empty() { cx.resolve(false); }
        v
    }
    fn pay(cx: &mut Cx, id: u64, j: u32, n: u64) { let v = try_pay(cx, id, j, n, None); assert!(v.is_none(), "refused: {}", v.map(|x| why(&x)).unwrap()); }
    fn refused(cx: &mut Cx, id: u64, n: u64) -> String { why(&try_pay(cx, id, 1, n, None).expect("not refused")) }
    fn file(cx: &mut Cx, r: u64, n: u64) -> bool { let i = inv(n); cx.run("file", &acc("funder.near"), None, 0, |w| w.file_claim(U64(r), i, "ef".repeat(32))).is_some() }
    fn rule(cx: &mut Cx, r: u64, n: u64, ruling: Ruling) -> bool { let i = inv(n); cx.run("rule", &acc("arb.near"), None, 0, |w| w.resolve_claim(U64(r), i, ruling, "ab".repeat(32))).is_some() }
    fn uphold(cx: &mut Cx, r: u64, n: u64, loss: u128) -> bool { rule(cx, r, n, Ruling::Uphold { loss: U128(loss) }) }
    fn clear(cx: &mut Cx, r: u64) -> bool { cx.run("clear", &acc("funder.near"), None, 0, |w| w.clear_agent(U64(r))).is_some() }
    fn cover(cx: &Cx, r: u64) -> Cover { cx.peek(|w| w.covers.get(&r).cloned().unwrap()) }
    fn rec(cx: &Cx, id: u64, n: u64) -> Option<PaymentRecord> { let i = inv(n); cx.peek(|w| w.payment_of(U64(id), i)) }
    fn drop_credit(cx: &mut Cx, r: u64) { cx.run("poke", &writ(), None, 0, |w| { w.terms.remove(&r); }).unwrap(); }
    #[track_caller]
    fn err(cx: &Cx, code: &str) { assert!(cx.last_err.contains(code), "{} vs {}", cx.last_err, code); }

    #[test]
    fn cover_payout_rounds_down_and_cannot_overflow() {
        assert_eq!(cover_payout(10_000, 2000), 8000);
        assert_eq!(cover_payout(9_999, 2000), 7999);
        assert_eq!(cover_payout(1, 9000), 0);
        assert_eq!(cover_payout(u128::MAX, 1000), u128::MAX / 10_000 * 9000 + (u128::MAX % 10_000) * 9000 / 10_000);
    }

    #[test]
    fn activation_moves_the_fee_and_locks_the_limit_exactly() {
        let (mut cx, r) = world(opt());
        // 2% per 30 days on 8 units, valid for 1e6 s: one period
        offer(&mut cx, r, 8 * U, 2000, 200, 1000);
        let t0 = total(&cx);
        let v0 = cell(&cx, r).vault.0;
        assert!(activate(&mut cx, r));
        let fee = 8 * U * 200 / 10_000;
        assert_eq!(cell(&cx, r).vault.0, v0 - fee);
        let st = stake(&cx);
        assert_eq!((st.amount.0, st.exposure.0, st.earned.0), (10 * U + fee, 8 * U, fee));
        let c = cover(&cx, r);
        assert_eq!((c.state.clone(), c.premium.0, c.locked.0, c.paid.0), (CoverState::Active, fee, 8 * U, 0));
        assert_eq!(total(&cx), t0, "the fee moves inside the books");
        assert!(!activate(&mut cx, r));
        err(&cx, "COVER_NOT_OFFERED");
        // A longer mandate pays by the period, and never more than the limit
        let (mut cx, r) = world(opt());
        cx.run("poke", &writ(), None, 0, |w| { let mut c = w.cells.get(&r).cloned().unwrap(); c.valid_until = U64(T0 + 61 * DAY * NS); w.cells.insert(r, c); }).unwrap();
        offer(&mut cx, r, 8 * U, 2000, 200, 1000);
        assert!(activate(&mut cx, r));
        assert_eq!(cover(&cx, r).premium.0, 3 * (8 * U * 200 / 10_000), "61 days is three periods");
        // Only the named, still-listed guarantor, on a live mandate
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, U, 2000, 0, 1000);
        assert!(cx.run("x", &acc("funder.near"), None, 0, |w| w.activate_cover(U64(r))).is_none());
        err(&cx, "ONLY_GUARANTOR");
        cx.run("poke", &writ(), None, 0, |w| { w.verifiers.remove(&acc("g.near")); }).unwrap();
        assert!(!activate(&mut cx, r));
        err(&cx, "GUARANTOR_DELISTED");
        cx.run("poke", &writ(), None, 0, |w| { w.verifiers.insert(acc("g.near"), "00".repeat(32)); }).unwrap();
        cx.now = VALID + 1;
        assert!(!activate(&mut cx, r));
        err(&cx, "MANDATE_EXPIRED");
        // Too late well before expiry: the first half of the term, to the nanosecond
        let half = T0 + (VALID - T0) / 2;
        cx.now = VALID;
        assert!(!activate(&mut cx, r));
        err(&cx, "ACTIVATION_TOO_LATE");
        cx.now = half + 1;
        assert!(!activate(&mut cx, r));
        err(&cx, "ACTIVATION_TOO_LATE");
        assert_eq!(cover(&cx, r).state, CoverState::Offered);
        cx.now = half;
        assert!(activate(&mut cx, r), "the last moment");
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, U, 2000, 0, 1000);
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert!(!activate(&mut cx, r));
        err(&cx, "NOT_ACTIVE");
        // No cover at all
        let (mut cx, r) = world(opt());
        assert!(!activate(&mut cx, r));
        err(&cx, "NO_COVER");
    }

    #[test]
    fn a_payment_is_recorded_only_under_live_cover() {
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, 8 * U, 2000, 0, 1000);
        pay(&mut cx, r, 1, 1);
        assert!(rec(&cx, r, 1).is_none(), "cover only offered: no record");
        assert!(activate(&mut cx, r));
        assert!(!file(&mut cx, r, 1));
        err(&cx, "NO_PAYMENT");
        let ctx = "AB".repeat(32);
        assert!(try_pay(&mut cx, r, 2, 2, Some(ctx)).is_none());
        let p = rec(&cx, r, 2).unwrap();
        assert_eq!((p.cell.0, p.to.clone(), p.amount.0, p.paid_at.0, p.context_hash.clone(), p.claim.clone()), (r, acc("s1.near"), 2 * U, T0, Some("ab".repeat(32)), ClaimState::None));
        // Bad context hash: refused with a strike, like a bad invoice hash
        let idx = cell(&cx, r).idx;
        assert_eq!(why(&try_pay(&mut cx, r, 1, 3, Some("zz".into())).unwrap()), "INVOICE");
        assert_eq!(why(&try_pay(&mut cx, r, 1, 3, Some("ab".repeat(31))).unwrap()), "INVOICE");
        assert_eq!(cell(&cx, r).idx, idx, "no link spent");
        assert_eq!(cell(&cx, r).strikes, 2);
        // A failed transfer leaves no record: nobody lost money
        let (p2, k, i) = (link(&cx, r, 1), key(&cx, r), inv(4));
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p2, 1, acc("s1.near"), i, None); }).unwrap();
        cx.resolve(true);
        assert!(rec(&cx, r, 4).is_none(), "a bounced transfer cannot be claimed");
        // No cover: the mandate behaves as before and keeps no records
        let (mut cx, r) = world(opt());
        pay(&mut cx, r, 1, 1);
        assert!(rec(&cx, r, 1).is_none());
        assert!(cx.peek(|w| w.cover_of(U64(r)).is_none()));
    }

    // 1. M2: the stop is on the root, so a dismissed sub-agent's payment still stops the whole tree
    #[test]
    fn a_claim_on_a_dismissed_sub_agent_still_stops_the_whole_tree() {
        let (mut cx, r) = active();
        let child = hired(hire(&mut cx, r, 4, |_| {}));
        let sib = hired(hire(&mut cx, r, 4, |_| {}));
        pay(&mut cx, child, 2, 1);
        let k = key(&cx, r);
        cx.run("dismiss", &writ(), Some(&k), 0, |w| w.dismiss(U64(child))).unwrap();
        assert!(matches!(cell(&cx, child).status, Status::Revoked { .. }));
        assert!(rec(&cx, r, 1).is_some(), "the record is on the tree");
        assert!(file(&mut cx, r, 1));
        assert_eq!(refused(&mut cx, r, 2), "UNDER_CLAIM", "root stops");
        assert_eq!(refused(&mut cx, sib, 3), "UNDER_CLAIM", "sibling stops");
        assert_eq!(why(&hire(&mut cx, r, 1, |_| {})), "UNDER_CLAIM", "hiring stops");
        assert_eq!(cx.peek(|w| { let c = w.cover_of(U64(sib)).unwrap(); (c["open_claim"].clone(), c["root"].clone()) }), (Value::from(inv(1)), Value::from(r.to_string())), "any cell finds the cover");
        assert!(uphold(&mut cx, r, 1, 2 * U));
        assert_eq!(refused(&mut cx, sib, 4), "NOT_CLEARED", "and stays stopped until the company clears");
        assert_eq!(why(&hire(&mut cx, r, 1, |_| {})), "NOT_CLEARED");
        assert!(clear(&mut cx, r));
        pay(&mut cx, sib, 1, 5);
        cx.check(1, "m2");
    }

    // 2. M1: the loss is what is repaid, not the payment
    #[test]
    fn the_loss_is_repaid_not_the_payment() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 3, 1);
        assert!(file(&mut cx, r, 1));
        let st0 = stake(&cx);
        assert!(!uphold(&mut cx, r, 1, 3 * U + 1));
        err(&cx, "BAD_LOSS");
        assert!(!uphold(&mut cx, r, 1, 0));
        err(&cx, "BAD_LOSS");
        assert!(uphold(&mut cx, r, 1, U), "the invoice was 2, the agent paid 3: the loss is 1");
        let want = U * 8 / 10;
        assert!(get_logs().iter().any(|l| l.contains("claim_upheld") && l.contains(&format!("\"payout\":\"{}\"", want)) && l.contains("\"retained\":false")));
        let st = stake(&cx);
        assert_eq!((st.amount.0, st.exposure.0), (st0.amount.0 - want, st0.exposure.0 - want));
        assert_eq!((st.claims_paid.0, st.cover_paid.0), (want, want));
        assert_eq!(claim(&cx, "funder.near"), Some(want));
        let c = cover(&cx, r);
        assert_eq!((c.paid.0, c.locked.0, c.upheld, c.needs_clear, c.open_claim.clone()), (want, 8 * U - want, 1, true, None));
        assert!(matches!(rec(&cx, r, 1).unwrap().claim, ClaimState::Upheld { loss, payout, .. } if loss.0 == U && payout.0 == want));
        // The whole amount is the most it can be
        assert!(clear(&mut cx, r));
        pay(&mut cx, r, 2, 2);
        assert!(file(&mut cx, r, 2));
        assert!(uphold(&mut cx, r, 2, 2 * U));
        assert_eq!(cover(&cx, r).paid.0, want + 2 * want);
        cx.check(1, "m1");
    }

    #[test]
    fn the_last_payout_stops_at_what_is_locked() {
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, 5 * U, 1000, 0, 1000);
        assert!(activate(&mut cx, r));
        for (n, want_paid) in [(1u64, 45 * U / 10), (2, 5 * U)] {
            pay(&mut cx, r, 5, n);
            assert!(file(&mut cx, r, n));
            assert!(uphold(&mut cx, r, n, 5 * U));
            assert_eq!(cover(&cx, r).paid.0, want_paid);
            assert!(clear(&mut cx, r));
        }
        assert_eq!((cover(&cx, r).locked.0, stake(&cx).exposure.0), (0, 0));
        // Nothing is left to pay, so no more claims
        pay(&mut cx, r, 1, 3);
        assert!(!file(&mut cx, r, 3));
        err(&cx, "COVER_EXHAUSTED");
        cx.check(1, "cap");
    }

    // 3. M3: only one way out for the lock
    #[test]
    fn revoking_does_not_bring_the_release_forward() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        // The guarantor is the verifier: it can revoke and keep its fee, but not take its lock back
        cx.run("revoke", &acc("g.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        let release = |cx: &mut Cx| cx.run("release", &acc("g.near"), None, 0, |w| w.release_cover(U64(r))).is_some();
        cx.now = T0 + 10_000 * NS;
        assert!(!release(&mut cx));
        err(&cx, "TOO_EARLY");
        // And the company can still claim after a revocation
        cx.now = T0;
        assert!(file(&mut cx, r, 1));
        assert!(rule(&mut cx, r, 1, Ruling::Deny));
        let end = VALID + 1000 * NS;
        cx.now = end;
        assert!(!release(&mut cx));
        err(&cx, "TOO_EARLY");
        assert!(cx.run("x", &acc("funder.near"), None, 0, |w| w.release_cover(U64(r))).is_none());
        err(&cx, "ONLY_GUARANTOR");
        cx.now = end + 1;
        // A delisted guarantor can still get out
        cx.run("poke", &writ(), None, 0, |w| { w.verifiers.remove(&acc("g.near")); }).unwrap();
        assert!(release(&mut cx));
        assert!(get_logs().iter().any(|l| l.contains("cover_released") && l.contains(&format!("\"released\":\"{}\"", 8 * U))));
        let c = cover(&cx, r);
        assert_eq!((c.state.clone(), c.locked.0), (CoverState::Released, 0));
        assert_eq!(stake(&cx).exposure.0, 0);
        assert!(!release(&mut cx));
        err(&cx, "COVER_NOT_ACTIVE");
    }

    #[test]
    fn an_open_claim_blocks_the_release_and_the_window_closes_when_it_opens() {
        let (mut cx, r) = active();
        cx.now = VALID - 10 * NS;
        pay(&mut cx, r, 1, 1);
        // The payment's window is counted from valid_until at the latest: a late callback cannot outlast the release
        cx.run("poke", &writ(), None, 0, |w| { let k = Contract::invoice_key(r, &inv(1)).unwrap(); let mut p = w.payments.get(&k).cloned().unwrap(); p.paid_at = U64(VALID + 5 * NS); w.payments.insert(k, p); }).unwrap();
        cx.now = VALID + 1000 * NS + 1;
        assert!(!file(&mut cx, r, 1));
        err(&cx, "WINDOW_CLOSED");
        cx.now = VALID + 1000 * NS;
        assert!(file(&mut cx, r, 1), "open at the exact nanosecond");
        cx.now = VALID + 1000 * NS + 1;
        assert!(cx.run("release", &acc("g.near"), None, 0, |w| w.release_cover(U64(r))).is_none());
        err(&cx, "CLAIM_OPEN");
        assert!(uphold(&mut cx, r, 1, U), "the claim filed in time can still be ruled on");
        assert!(cx.run("release", &acc("g.near"), None, 0, |w| w.release_cover(U64(r))).is_some());
        assert_eq!(stake(&cx).exposure.0, 0);
        assert_eq!(cover(&cx, r).paid.0, U * 8 / 10);
    }

    // 4. M4: a callback in flight when the lock goes
    #[test]
    fn a_callback_after_release_or_void_writes_nothing() {
        for void in [false, true] {
            let (mut cx, r) = active();
            pay(&mut cx, r, 1, 1);
            let (p, k, i) = (link(&cx, r, 1), key(&cx, r), inv(2));
            if void {
                assert!(file(&mut cx, r, 1));
                assert!(rule(&mut cx, r, 1, Ruling::Deny));
                let i0 = inv(1);
                cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i, None); }).unwrap();
                cx.run("void", &acc("arb.near"), None, 0, |w| w.void_cover(U64(r), i0)).unwrap();
            } else {
                cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i, None); }).unwrap();
                cx.now = VALID + 1000 * NS + 1;
                cx.run("release", &acc("g.near"), None, 0, |w| w.release_cover(U64(r))).unwrap();
            }
            cx.resolve(false);
            assert!(rec(&cx, r, 2).is_none(), "no record, so no claim on stake that is no longer locked");
            assert!(cx.peek(|w| w.invoice_paid(U64(r), inv(2))), "the payment itself still counts");
            assert!(!file(&mut cx, r, 2));
            err(&cx, "COVER_NOT_ACTIVE");
            cx.check(1, "m4");
        }
    }

    #[test]
    fn a_record_is_never_overwritten() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        assert!(file(&mut cx, r, 1));
        assert!(rule(&mut cx, r, 1, Ruling::Deny));
        cx.run("cb", &writ(), None, 0, |w| { let _ = w.on_transfer(U64(r), U128(9 * U), inv(1), acc("s2.near"), 1, 0, Some("cd".repeat(32)), Ok(())); }).unwrap();
        let p = rec(&cx, r, 1).unwrap();
        assert_eq!((p.amount.0, p.to.clone()), (U, acc("s1.near")));
        assert!(matches!(p.claim, ClaimState::Denied { .. }));
    }

    // 5. M5: repayment cannot get around what the tree owes
    #[test]
    fn a_payout_stays_in_the_vault_while_the_company_owes() {
        // A debt to the guarantor
        let (mut cx, r) = active();
        pay(&mut cx, r, 2, 1);
        assert!(file(&mut cx, r, 1));
        cx.run("poke", &writ(), None, 0, |w| { let mut t = w.terms.get(&r).cloned().unwrap(); t.open_debts = 1; w.terms.insert(r, t); }).unwrap();
        let v0 = cell(&cx, r).vault.0;
        assert!(uphold(&mut cx, r, 1, 2 * U));
        assert!(get_logs().iter().any(|l| l.contains("claim_upheld") && l.contains("\"retained\":true")));
        assert_eq!(cell(&cx, r).vault.0, v0 + 16 * U / 10, "in the root's vault");
        assert_eq!(claim(&cx, "funder.near"), None, "nothing the company can withdraw");
        assert!(cx.run("w", &acc("funder.near"), None, 0, |w| { let _ = w.withdraw(None); }).is_none());
        err(&cx, "NOTHING_TO_WITHDRAW");
        // Open credit, even with no debt yet
        let (mut cx, r) = active();
        let order = opened(open(&mut cx, r, 1));
        cx.credits.push(order);
        pay(&mut cx, r, 2, 1);
        assert!(file(&mut cx, r, 1));
        let v0 = cell(&cx, r).vault.0;
        assert!(uphold(&mut cx, r, 1, 2 * U));
        assert_eq!(cell(&cx, r).vault.0, v0 + 16 * U / 10);
        assert_eq!(claim(&cx, "funder.near"), None);
        cx.check(1, "m5");
        // Nothing owed: claimable, and it goes out in the mandate's asset
        let (mut cx, r) = active();
        pay(&mut cx, r, 2, 1);
        assert!(file(&mut cx, r, 1));
        assert!(uphold(&mut cx, r, 1, 2 * U));
        assert_eq!(claim(&cx, "funder.near"), Some(16 * U / 10));
        let t0 = total(&cx);
        cx.run("w", &acc("funder.near"), None, 0, |w| { let _ = w.withdraw(None); }).unwrap();
        assert_eq!(total(&cx), t0 - 16 * U / 10);
    }

    // 6. M6: cover with no credit terms works, in NEAR and in a token
    #[test]
    fn a_guarantor_that_revokes_returns_only_the_periods_not_started() {
        const P: u64 = 30 * DAY * 1_000_000_000;
        let world3 = || {
            let (mut cx, r) = world(opt());
            drop_credit(&mut cx, r);
            let until = cx.now + 3 * P;
            cx.run("poke", &writ(), None, 0, |w| { let mut c = w.cells.get(&r).cloned().unwrap(); c.valid_until = U64(until); w.cells.insert(r, c); }).unwrap();
            offer(&mut cx, r, 8 * U, 2000, 100, 1000);
            assert!(activate(&mut cx, r));
            (cx, r)
        };
        let f = 8 * U / 100;
        // one period started and a nanosecond into the second: two kept, one back
        let (mut cx, r) = world3();
        let (a0, e0) = (stake(&cx).amount.0, stake(&cx).earned.0);
        assert_eq!(cover(&cx, r).premium.0, 3 * f);
        let v0 = cell(&cx, r).vault.0;
        cx.now += P + 1;
        cx.run("revoke", &acc("g.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert!(get_logs().iter().any(|l| l.contains("cover_fee_returned") && l.contains(&format!("\"amount\":\"{}\"", f))));
        assert!(get_logs().iter().any(|l| l.contains("\"revoked\"") && l.contains(&format!("\"refund\":\"{}\"", v0 + f))));
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (a0 - f, e0 - f));
        assert_eq!(cover(&cx, r).premium.0, 2 * f);
        assert_eq!(stake(&cx).exposure.0, 8 * U, "the lock stays");
        // the same moment: nothing started beyond the first period
        let (mut cx, r) = world3();
        let a0 = stake(&cx).amount.0;
        cx.run("revoke", &acc("g.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert_eq!(stake(&cx).amount.0, a0 - 2 * f);
        // in the last period, nothing comes back
        let (mut cx, r) = world3();
        let a0 = stake(&cx).amount.0;
        cx.now += 2 * P;
        cx.run("revoke", &acc("g.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert_eq!(stake(&cx).amount.0, a0);
        assert!(!get_logs().iter().any(|l| l.contains("cover_fee_returned")));
        // the company revoking its own mandate keeps nothing back
        let (mut cx, r) = world3();
        let a0 = stake(&cx).amount.0;
        cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert_eq!(stake(&cx).amount.0, a0);
        // only free stake can come back
        let (mut cx, r) = world3();
        let st = stake(&cx);
        let free = f / 2;
        cx.run("poke", &writ(), None, 0, |w| { let mut s = st.clone(); s.exposure = U128(s.amount.0 - free); w.stakes.insert((acc("g.near"), None), s); }).unwrap();
        cx.run("revoke", &acc("g.near"), None, 0, |w| w.revoke(U64(r), "x".into())).unwrap();
        assert_eq!(stake(&cx).amount.0, st.amount.0 - free);
        // revoked twice: refused, and nothing moves
        let a1 = stake(&cx).amount.0;
        assert!(cx.run("revoke", &acc("g.near"), None, 0, |w| w.revoke(U64(r), "x".into())).is_none());
        err(&cx, "ALREADY_CLOSED");
        assert_eq!(stake(&cx).amount.0, a1);
    }

    #[test]
    fn cover_alone_works_in_near_and_in_a_token() {
        let (mut cx, r) = world(opt());
        drop_credit(&mut cx, r);
        offer(&mut cx, r, 8 * U, 2000, 100, 1000);
        assert!(activate(&mut cx, r));
        pay(&mut cx, r, 2, 1);
        assert!(file(&mut cx, r, 1));
        assert!(uphold(&mut cx, r, 1, 2 * U));
        assert_eq!(claim(&cx, "funder.near"), Some(16 * U / 10));
        assert!(clear(&mut cx, r));
        assert!(cx.peek(|w| w.risk_card(U64(r)).is_none()), "the credit card is untouched");
        assert_eq!(cx.peek(|w| w.cover_of(U64(r)).unwrap()["state"].clone()), "Active");

        let (mut cx, r, _) = tworld(opt());
        drop_credit(&mut cx, r);
        offer(&mut cx, r, 8 * U, 2000, 100, 1000);
        let (v0, t0) = (cell(&cx, r).vault.0, ttotal(&cx));
        assert!(activate(&mut cx, r));
        let fee = 8 * U / 100;
        assert_eq!(cell(&cx, r).vault.0, v0 - fee);
        assert_eq!((tstake(&cx).amount.0, tstake(&cx).exposure.0), (10 * U + fee, 8 * U));
        assert_eq!(ttotal(&cx), t0, "the fee moves inside the token's books");
        pay(&mut cx, r, 2, 1);
        assert!(file(&mut cx, r, 1));
        assert!(uphold(&mut cx, r, 1, 2 * U));
        assert_eq!(tclaim(&cx, "funder.near"), 16 * U / 10);
        assert_eq!(near_claim(&cx, "funder.near"), 0, "paid in the mandate's asset, never in NEAR");
        assert_eq!((tstake(&cx).cover_paid.0, tstake(&cx).exposure.0), (16 * U / 10, 8 * U - 16 * U / 10));
        assert_eq!(stake(&cx).amount.0, 0, "the NEAR stake is not touched");
        cx.check(1, "m6");
    }

    #[test]
    fn a_stake_in_the_wrong_asset_does_not_back_cover() {
        let (mut cx, r, _) = tworld(opt());
        drop_credit(&mut cx, r);
        offer(&mut cx, r, 50 * U, 2000, 0, 1000);
        cx.run("stake", &acc("g.near"), None, 100 * U, |w| w.stake()).unwrap();
        assert!(!activate(&mut cx, r));
        err(&cx, "GUARANTOR_CAPACITY");
    }

    // 8. One open claim at a time, one claim per payment, inside the window
    #[test]
    fn one_open_claim_one_claim_per_payment_inside_the_window() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        pay(&mut cx, r, 1, 2);
        assert!(!file(&mut cx, r, 9));
        err(&cx, "NO_PAYMENT");
        let (a, e) = (inv(1), "ef".repeat(32));
        assert!(cx.run("x", &acc("s1.near"), None, 0, |w| w.file_claim(U64(r), a, e)).is_none());
        err(&cx, "ONLY_FUNDER");
        let a = inv(1);
        assert!(cx.run("x", &acc("funder.near"), None, 0, |w| w.file_claim(U64(r), a, "zz".into())).is_none());
        err(&cx, "BAD_HEX:evidence_hash");
        assert!(file(&mut cx, r, 1));
        assert!(get_logs().iter().any(|l| l.contains("claim_filed") && l.contains(&"ef".repeat(32))));
        assert!(!file(&mut cx, r, 2));
        err(&cx, "CLAIM_OPEN");
        assert!(!file(&mut cx, r, 1));
        err(&cx, "CLAIM_OPEN");
        assert!(rule(&mut cx, r, 1, Ruling::Deny));
        assert!(!file(&mut cx, r, 1));
        err(&cx, "ALREADY_CLAIMED");
        // Uppercase hex is the same invoice
        let up = inv(2).to_uppercase();
        cx.run("x", &acc("funder.near"), None, 0, |w| w.file_claim(U64(r), up, "ef".repeat(32))).unwrap();
        assert_eq!(cover(&cx, r).open_claim, Some(inv(2)));
        assert!(uphold(&mut cx, r, 2, U));
        assert!(!file(&mut cx, r, 2));
        err(&cx, "ALREADY_CLAIMED");
        // Window, to the nanosecond
        assert!(clear(&mut cx, r));
        pay(&mut cx, r, 1, 3);
        cx.now = T0 + 1000 * NS + 1;
        assert!(!file(&mut cx, r, 3));
        err(&cx, "WINDOW_CLOSED");
        cx.now = T0 + 1000 * NS;
        assert!(file(&mut cx, r, 3));
        // And nothing happens to a tree with no cover
        let (mut cx, r) = world(opt());
        assert!(!file(&mut cx, r, 1));
        err(&cx, "NO_COVER");
    }

    // 9. Timeout: no pay, no denial, can file again; neither side can act on the other's side of the deadline
    #[test]
    fn a_timed_out_claim_can_be_filed_again() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        let timeout = |cx: &mut Cx| cx.run("to", &acc("x.near"), None, 0, |w| w.claim_timeout(U64(r))).is_some();
        assert!(!timeout(&mut cx));
        err(&cx, "NO_OPEN_CLAIM");
        assert!(file(&mut cx, r, 1));
        cx.now = T0 + 200 * NS;
        assert!(!timeout(&mut cx));
        err(&cx, "ARBITER_STILL_HAS_TIME");
        cx.now = T0 + 200 * NS + 1;
        assert!(!rule(&mut cx, r, 1, Ruling::Deny));
        err(&cx, "RULING_TOO_LATE");
        assert!(!uphold(&mut cx, r, 1, U));
        err(&cx, "RULING_TOO_LATE");
        let st0 = stake(&cx);
        assert!(timeout(&mut cx));
        let c = cover(&cx, r);
        assert_eq!((c.timed_out, c.denied, c.upheld, c.open_claim.clone(), c.needs_clear), (1, 0, 0, None, false));
        assert_eq!(rec(&cx, r, 1).unwrap().claim, ClaimState::None);
        assert_eq!(stake(&cx).amount.0, st0.amount.0, "nothing paid");
        pay(&mut cx, r, 1, 2);
        // Filed again, inside the window; timeouts add up
        assert!(file(&mut cx, r, 1));
        cx.now += 201 * NS;
        assert!(timeout(&mut cx));
        assert_eq!(cover(&cx, r).timed_out, 2);
        assert!(file(&mut cx, r, 1));
        assert!(rule(&mut cx, r, 1, Ruling::Deny), "the arbiter can rule on the new filing");
        assert_eq!(cover(&cx, r).denied, 1);
    }

    #[test]
    fn only_the_arbiter_rules_and_only_on_the_open_claim() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        pay(&mut cx, r, 1, 2);
        assert!(!rule(&mut cx, r, 1, Ruling::Deny));
        err(&cx, "NO_OPEN_CLAIM");
        assert!(file(&mut cx, r, 1));
        for who in ["funder.near", "g.near", "owner.near"] {
            let i = inv(1);
            assert!(cx.run("x", &acc(who), None, 0, |w| w.resolve_claim(U64(r), i, Ruling::Uphold { loss: U128(U) }, "ab".repeat(32))).is_none());
            err(&cx, "ONLY_ARBITER");
        }
        assert!(!rule(&mut cx, r, 2, Ruling::Deny));
        err(&cx, "NO_OPEN_CLAIM");
        let i = inv(1);
        assert!(cx.run("x", &acc("arb.near"), None, 0, |w| w.resolve_claim(U64(r), i, Ruling::Deny, "ab".into())).is_none());
        err(&cx, "BAD_LEN:ruling_hash");
        let st0 = stake(&cx);
        assert!(rule(&mut cx, r, 1, Ruling::Deny));
        let st = stake(&cx);
        assert_eq!((st.amount.0, st.exposure.0, st.cover_paid.0), (st0.amount.0, st0.exposure.0, 0), "a denial moves nothing");
        let c = cover(&cx, r);
        assert_eq!((c.denied, c.needs_clear, c.open_claim.clone(), c.locked.0), (1, false, None, 8 * U));
        assert_eq!(rec(&cx, r, 1).unwrap().claim, ClaimState::Denied { ruling_hash: "ab".repeat(32) });
        pay(&mut cx, r, 1, 3);
    }

    // 10. Void needs a denied record, and ends everything
    #[test]
    fn void_needs_a_denied_claim_and_ends_the_records() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        pay(&mut cx, r, 1, 2);
        let void = |cx: &mut Cx, n: u64| { let i = inv(n); cx.run("void", &acc("arb.near"), None, 0, |w| w.void_cover(U64(r), i)).is_some() };
        assert!(!void(&mut cx, 1));
        err(&cx, "NOT_DENIED");
        assert!(!void(&mut cx, 9));
        err(&cx, "NOT_DENIED");
        assert!(file(&mut cx, r, 1));
        assert!(!void(&mut cx, 1));
        err(&cx, "CLAIM_OPEN");
        assert!(uphold(&mut cx, r, 1, U));
        assert!(!void(&mut cx, 1));
        err(&cx, "NOT_DENIED");
        assert!(clear(&mut cx, r));
        assert!(file(&mut cx, r, 2));
        assert!(rule(&mut cx, r, 2, Ruling::Deny));
        let i = inv(2);
        assert!(cx.run("x", &acc("g.near"), None, 0, |w| w.void_cover(U64(r), i)).is_none());
        err(&cx, "ONLY_ARBITER");
        let (st0, fee0) = (stake(&cx), cover(&cx, r).premium.0);
        let paid = cover(&cx, r).paid.0;
        assert!(void(&mut cx, 2));
        assert!(get_logs().iter().any(|l| l.contains("cover_voided") && l.contains(&format!("\"released\":\"{}\"", 8 * U - paid))));
        let c = cover(&cx, r);
        assert_eq!((c.state.clone(), c.locked.0, c.needs_clear, c.premium.0), (CoverState::Voided, 0, false, fee0));
        let st = stake(&cx);
        assert_eq!((st.amount.0, st.exposure.0), (st0.amount.0, 0), "lock released, stake and fee kept");
        assert!(!void(&mut cx, 2));
        err(&cx, "COVER_NOT_ACTIVE");
        // After void: payments keep working but are not recorded and cannot be claimed
        pay(&mut cx, r, 1, 3);
        assert!(rec(&cx, r, 3).is_none());
        assert!(!file(&mut cx, r, 3));
        err(&cx, "COVER_NOT_ACTIVE");
        cx.check(1, "void");
    }

    // 11. The stop costs no strikes, leaves settlement open, and blocks sellers
    #[test]
    fn a_stop_costs_no_strike_settle_works_and_a_seller_cannot_accept() {
        let (mut cx, r) = active();
        let accepted = opened(open(&mut cx, r, 1));
        accept(&mut cx, accepted);
        deliver(&mut cx, accepted);
        let waiting = opened(open(&mut cx, r, 1));
        pay(&mut cx, r, 1, 1);
        cx.run("poke", &writ(), None, 0, |w| { let mut c = w.cells.get(&r).cloned().unwrap(); c.max_strikes = 2; w.cells.insert(r, c); }).unwrap();
        assert!(file(&mut cx, r, 1));
        for n in 10..20 { assert_eq!(refused(&mut cx, r, n), "UNDER_CLAIM"); }
        let c = cell(&cx, r);
        assert_eq!((c.strikes, c.status.clone(), c.rejects), (0, Status::Active, 10), "ten refusals, no strike, the key stays");
        let k = key(&cx, r);
        let (p, i) = (link(&cx, r, 1), inv(21));
        let due = U64(cx.now + 500 * NS);
        let v = cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, 1, acc("s1.near"), i, due)).unwrap();
        assert_eq!(why(&v), "UNDER_CLAIM");
        assert_eq!(cell(&cx, r).strikes, 0);
        // A seller cannot take on the guarantor's money now
        assert!(cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(waiting))).is_none());
        err(&cx, "UNDER_CLAIM");
        let reasons = cx.peek(|w| w.check_order(U64(waiting), None).reasons);
        assert!(reasons.contains(&"UNDER_CLAIM".to_string()));
        // Settling is not stopped: that would manufacture a default
        assert!(settle(&mut cx, r, accepted));
        assert_eq!(cred(&cx, accepted).status, CreditStatus::Settled);
        assert!(uphold(&mut cx, r, 1, U));
        for n in 30..40 { assert_eq!(refused(&mut cx, r, n), "NOT_CLEARED"); }
        assert_eq!(cell(&cx, r).strikes, 0);
        assert!(cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(waiting))).is_none());
        err(&cx, "UNDER_CLAIM");
        assert!(clear(&mut cx, r));
        accept(&mut cx, waiting);
    }

    #[test]
    fn clearing_needs_an_upheld_claim_and_the_company() {
        let (mut cx, r) = active();
        assert!(!clear(&mut cx, r));
        err(&cx, "NOTHING_TO_CLEAR");
        pay(&mut cx, r, 1, 1);
        pay(&mut cx, r, 1, 2);
        assert!(file(&mut cx, r, 1));
        assert!(uphold(&mut cx, r, 1, U));
        assert!(cx.run("x", &acc("g.near"), None, 0, |w| w.clear_agent(U64(r))).is_none());
        err(&cx, "ONLY_FUNDER");
        // A stopped tree can still file another claim on a payment already made, and cannot be cleared under it
        assert!(file(&mut cx, r, 2));
        assert!(!clear(&mut cx, r));
        err(&cx, "CLAIM_OPEN");
        assert_eq!(refused(&mut cx, r, 3), "UNDER_CLAIM");
        assert!(rule(&mut cx, r, 2, Ruling::Deny));
        assert_eq!(refused(&mut cx, r, 3), "NOT_CLEARED", "the upheld claim still has to be cleared");
        assert!(clear(&mut cx, r));
        assert!(get_logs().iter().any(|l| l.contains("agent_cleared")));
        pay(&mut cx, r, 1, 3);
    }

    // 12. Cover and credit share one stake
    #[test]
    fn cover_and_credit_share_the_stake_both_ways() {
        // Cover takes all of it: a seller's order finds no capacity
        let mut o = opt(); o.stake = 8 * U;
        let (mut cx, r) = world(o);
        offer(&mut cx, r, 8 * U, 2000, 0, 1000);
        assert!(activate(&mut cx, r));
        let k = opened(open(&mut cx, r, 1));
        assert!(cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k))).is_none());
        err(&cx, "GUARANTOR_CAPACITY");
        // The stake cannot leave either
        cx.run("req", &acc("g.near"), None, 0, |w| w.request_unstake(None)).unwrap();
        cx.now += 31 * NS;
        assert!(cx.run("x", &acc("g.near"), None, 0, |w| { let _ = w.withdraw_stake(U128(1), None); }).is_none());
        err(&cx, "STAKE_EXPOSED");
        // An order takes it first: the cover cannot lock
        let mut o = opt(); o.stake = 2 * U;
        let (mut cx, r) = world(o);
        offer(&mut cx, r, 2 * U, 2000, 0, 1000);
        let k = opened(open(&mut cx, r, 1));
        accept(&mut cx, k);
        assert_eq!(stake(&cx).exposure.0, U);
        assert!(!activate(&mut cx, r));
        err(&cx, "GUARANTOR_CAPACITY");
        assert_eq!(cover(&cx, r).state, CoverState::Offered);
        // The fee does not count toward what it can lock: its own stake must back the limit, to the yocto
        let mut o = opt(); o.stake = 2 * U;
        let (mut cx, r) = world(o);
        offer(&mut cx, r, 2 * U + 1, 2000, 100, 1000);
        assert!(!activate(&mut cx, r));
        err(&cx, "GUARANTOR_CAPACITY");
        let mut o = opt(); o.stake = 2 * U;
        let (mut cx, r) = world(o);
        offer(&mut cx, r, 2 * U, 2000, 100, 1000);
        assert!(activate(&mut cx, r));
        assert!(stake(&cx).amount.0 >= stake(&cx).exposure.0);
        // No stake at all: a fee as large as the limit cannot stand in for it
        let mut o = opt(); o.stake = 0;
        let (mut cx, r) = world(o);
        cx.run("poke", &writ(), None, 0, |w| { let mut c = w.cells.get(&r).cloned().unwrap(); c.valid_until = U64(T0 + 151 * DAY * NS); w.cells.insert(r, c); }).unwrap();
        offer(&mut cx, r, 2 * U, 2000, 2000, 1000);
        assert!(!activate(&mut cx, r));
        err(&cx, "GUARANTOR_CAPACITY");
    }

    // 13. One invoice, one record
    #[test]
    fn a_cancelled_order_then_a_spend_leaves_one_record_and_a_paid_invoice_cannot_be_ordered() {
        let (mut cx, r) = active();
        let (p, k, i) = (link(&cx, r, 1), key(&cx, r), inv(1));
        let due = U64(cx.now + 500 * NS);
        let v = cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, 1, acc("s1.near"), i, due)).unwrap();
        let order = opened(v);
        assert_eq!(refused(&mut cx, r, 1), "DUPLICATE", "an open order holds the invoice");
        assert!(rec(&cx, r, 1).is_none(), "credit keeps no payment record");
        cx.run("cancel", &acc("funder.near"), None, 0, |w| w.cancel_open(U64(order))).unwrap();
        pay(&mut cx, r, 1, 1);
        let first = rec(&cx, r, 1).unwrap();
        assert_eq!(first.amount.0, U);
        assert_eq!(refused(&mut cx, r, 1), "DUPLICATE");
        let (p, i) = (link(&cx, r, 1), inv(1));
        let due = U64(cx.now + 500 * NS);
        let v = cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, 1, acc("s1.near"), i, due)).unwrap();
        assert_eq!(why(&v), "DUPLICATE");
        assert_eq!(rec(&cx, r, 1).unwrap().paid_at.0, first.paid_at.0, "still the same record");
        assert_eq!(cred(&cx, order).status, CreditStatus::Cancelled);
    }

    // 14. The fee is all or nothing, and never comes out of a seller's bond
    #[test]
    fn a_short_vault_changes_nothing_and_a_bond_does_not_pay_the_fee() {
        // fee 2% of 8 units = 0.16 unit, vault one yocto short
        let mut o = opt(); o.bond = 10_000;
        let (mut cx, r) = world(o);
        offer(&mut cx, r, 8 * U, 2000, 200, 1000);
        let k = opened(open(&mut cx, r, 1));
        accept(&mut cx, k);
        assert_eq!(outstanding(&cx, r).1, U, "the whole order is bonded");
        let fee = 8 * U * 200 / 10_000;
        set_vault(&mut cx, r, U + fee - 1);
        let st0 = stake(&cx);
        let t0 = total(&cx);
        assert!(!activate(&mut cx, r));
        err(&cx, "PREMIUM_SHORT");
        let c = cover(&cx, r);
        assert_eq!((c.state.clone(), c.premium.0, c.locked.0), (CoverState::Offered, 0, 0), "still only offered");
        assert_eq!(cell(&cx, r).vault.0, U + fee - 1);
        assert_eq!((stake(&cx).amount.0, stake(&cx).exposure.0, total(&cx)), (st0.amount.0, st0.exposure.0, t0));
        assert_eq!(outstanding(&cx, r).1, U, "the bond is untouched");
        set_vault(&mut cx, r, U + fee);
        assert!(activate(&mut cx, r));
        assert_eq!(cell(&cx, r).vault.0, U, "exactly the bond is left");
        assert_eq!(outstanding(&cx, r).1, U);
        // And a guarantor that owes nothing is not paid by a frozen company
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, U, 2000, 0, 1000);
        cx.run("poke", &writ(), None, 0, |w| { let mut t = w.terms.get(&r).cloned().unwrap(); t.open_debts = 1; w.terms.insert(r, t); }).unwrap();
        assert!(!activate(&mut cx, r));
        err(&cx, "COMPANY_FROZEN");
    }

    #[test]
    fn present_says_cover_only_while_money_backs_it() {
        let say = |cx: &Cx, r: u64| cx.peek(|w| w.present(U64(r)).unwrap()["cover"].clone());
        let (mut cx, r) = world(opt());
        assert_eq!(say(&cx, r), false, "no cover");
        offer(&mut cx, r, 8 * U, 2000, 0, 1000);
        assert_eq!(say(&cx, r), false, "offered: nothing is locked");
        assert!(activate(&mut cx, r));
        assert_eq!(say(&cx, r), true);
        pay(&mut cx, r, 1, 1);
        let child = hired(hire(&mut cx, r, 2, |_| {}));
        assert_eq!(say(&cx, child), true, "the whole tree");
        assert!(file(&mut cx, r, 1));
        assert!(rule(&mut cx, r, 1, Ruling::Deny));
        let i = inv(1);
        cx.run("void", &acc("arb.near"), None, 0, |w| w.void_cover(U64(r), i)).unwrap();
        assert_eq!(say(&cx, r), false, "voided");
        let (mut cx, r) = active();
        cx.now = VALID + 1000 * NS + 1;
        cx.run("release", &acc("g.near"), None, 0, |w| w.release_cover(U64(r))).unwrap();
        assert_eq!(say(&cx, r), false, "released");
    }

    #[test]
    fn windows_and_the_price_before_activation_can_be_read() {
        let (mut cx, r) = world(opt());
        offer(&mut cx, r, 8 * U, 2000, 200, 1000);
        let w0 = cx.peek(|w| w.windows());
        assert_eq!((w0.dispute_timeout.0, w0.accept_ttl.0, w0.inspect.0, w0.grace.0, w0.recourse.0, w0.unstake_delay.0), (200, 100, 50, 50, 100, 30));
        let fee = 8 * U * 200 / 10_000;
        let v = cx.peek(|w| w.cover_of(U64(r)).unwrap());
        assert_eq!(v["premium_if_activated_now"], json_str(fee), "the price shows before it is charged");
        assert_eq!(v["premium"], json_str(0));
        assert_eq!(v["dispute_timeout"], Value::from("200"));
        assert_eq!(v["root_valid_until"], Value::from(VALID.to_string()));
        assert_eq!(v["activate_by"], Value::from((T0 + (VALID - T0) / 2).to_string()));
        assert!(activate(&mut cx, r));
        let v = cx.peek(|w| w.cover_of(U64(r)).unwrap());
        assert_eq!((v["premium"].clone(), v["premium_if_activated_now"].clone()), (json_str(fee), Value::Null));
    }

    // F5: a ruling that pays nothing must not use up the claim
    #[test]
    fn an_upheld_loss_that_pays_nothing_is_refused_and_the_claim_stays_open() {
        let (mut cx, r) = active();
        pay(&mut cx, r, 1, 1);
        assert!(file(&mut cx, r, 1));
        assert!(!uphold(&mut cx, r, 1, 1));
        err(&cx, "BAD_LOSS");
        assert!(matches!(rec(&cx, r, 1).unwrap().claim, ClaimState::Open { .. }));
        let c = cover(&cx, r);
        assert_eq!((c.upheld, c.needs_clear, c.open_claim.clone()), (0, false, Some(inv(1))));
        // The smallest loss that pays: one unit of payout, to the yocto
        assert!(!uphold(&mut cx, r, 1, 1));
        assert!(uphold(&mut cx, r, 1, 2), "2 x 80% rounds down to 1");
        assert_eq!(cover(&cx, r).paid.0, 1);
    }

    // F6: the fee cannot overflow, and agrees with the plain formula where that fits
    #[test]
    fn the_guarantee_fee_cannot_overflow() {
        assert_eq!(guarantee_fee(u128::MAX, 2000, 4), u128::MAX / 10_000 * 8000 + (u128::MAX % 10_000) * 8000 / 10_000);
        assert_eq!(guarantee_fee(u128::MAX, 2000, 5), u128::MAX, "100% is the cap");
        assert_eq!(guarantee_fee(u128::MAX, u32::MAX, u128::MAX), u128::MAX);
        assert_eq!(guarantee_fee(1_390_000_000_000_000_000_000_000_000_000_000, 2000, 122), 1_390_000_000_000_000_000_000_000_000_000_000);
        for (a, b, p) in [(10_000u128, 200u32, 1u128), (9_999, 200, 3), (1, 9_999, 1), (12_345_678, 1_234, 7), (7, 0, 9)] {
            assert_eq!(guarantee_fee(a, b, p), (a * b as u128 * p / 10_000).min(a));
        }
    }

    #[test]
    fn views_and_books_show_cover_separately() {
        let (mut cx, r) = active();
        assert_eq!(cx.peek(|w| w.present(U64(r)).unwrap()["cover"].clone()), true);
        pay(&mut cx, r, 2, 1);
        assert!(file(&mut cx, r, 1));
        assert!(uphold(&mut cx, r, 1, 2 * U));
        let v = cx.peek(|w| w.cover_of(U64(r)).unwrap());
        let want = 16 * U / 10;
        assert_eq!(v["state"], "Active");
        assert_eq!(v["guarantor"], "g.near");
        assert_eq!(v["arbiter"], "arb.near");
        assert_eq!(v["limit"], json_str(8 * U));
        assert_eq!(v["remaining"], json_str(8 * U - want));
        assert_eq!(v["paid"], json_str(want));
        assert_eq!(v["deductible_bps"], 2000);
        assert_eq!((v["upheld"].clone(), v["denied"].clone(), v["timed_out"].clone(), v["needs_clear"].clone()), (Value::from(1), Value::from(0), Value::from(0), Value::from(true)));
        assert_eq!(v["guarantor_stake"], json_str(10 * U - want));
        assert_eq!(v["guarantor_exposure"], json_str(8 * U - want));
        let b = cx.peek(|w| w.guarantor_book(acc("g.near"), None).unwrap());
        assert_eq!((b["cover_paid"].clone(), b["claims_paid"].clone()), (json_str(want), json_str(want)));
        // A view asked about a stranger's cell or a bad hash answers null
        assert!(cx.peek(|w| w.cover_of(U64(99)).is_none()));
        assert!(cx.peek(|w| w.payment_of(U64(r), "zz".into()).is_none()));
    }

    // Register's rules for cover, with a real signature, to the exact boundary
    fn signed(cx: &mut Cx, f: impl FnOnce(&mut RegisterArgs)) -> Option<u64> {
        // The attestation is checked by ed25519_verify, so sign with a real key
        let (pk2, signer) = sign_key(&[42; 32]);
        cx.nextpk += 1;
        let np = cx.nextpk;
        let mut a = RegisterArgs {
            amc_said: format!("EAMC{}", np), issuer_aid: "A".into(), issuer_pk: "00".repeat(32), agent_pk: pk(np), w0: "00".repeat(32), n: 100, unit: U128(U),
            scope: vec![acc("s1.near")], valid_until: U64(cx.now + 1000 * NS), daily_links: 10, max_links: 5, max_strikes: 3, lei_commit: "00".repeat(32), ecr_commit: "00".repeat(32),
            verifier: acc("g.near"), attested_at: U64(cx.now), signature: String::new(), asset: None, credit: None,
            cover: Some(CoverArgs { limit: U128(50 * U), deductible_bps: 2000, premium_bps: 100, claim_window: U64(400), arbiter: acc("arb.near"), terms_hash: "cd".repeat(32) }),
        };
        f(&mut a);
        let g = a.verifier.clone();
        cx.run("poke", &writ(), None, 0, |w| { w.verifiers.insert(g, pk2); }).unwrap();
        cx.up(&writ(), None, 0);
        a.signature = hex::encode(signer(attestation_message(&a, &acc("funder.near"), &writ()).as_bytes()));
        let dep = register_fee(a.n) + a.n as u128 * COVER_STORAGE_PER_LINK + U;
        cx.run("register", &acc("funder.near"), None, dep, |w| w.register(a).0)
    }
    fn sign_key(secret: &[u8; 32]) -> (String, impl Fn(&[u8]) -> Vec<u8>) {
        use ed25519_dalek::{Signer, SigningKey};
        let k = SigningKey::from_bytes(secret);
        (hex::encode(k.verifying_key().to_bytes()), move |m: &[u8]| k.sign(m).to_bytes().to_vec())
    }

    // 16. register refuses every bad term on its own, and takes the exact boundary
    #[test]
    fn register_checks_every_cover_term_at_its_boundary() {
        let (mut cx, _) = world(opt());
        let bad = |cx: &mut Cx, f: fn(&mut RegisterArgs), code: &str| {
            assert!(signed(cx, f).is_none(), "must refuse {}", code);
            assert!(cx.last_err.contains(code), "{} vs {}", cx.last_err, code);
        };
        bad(&mut cx, |a| a.cover.as_mut().unwrap().limit = U128(0), "COVER_LIMIT_ZERO");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().limit = U128(50 * UNIT - 1), "COVER_LIMIT_THIN");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().limit = U128(100 * UNIT + 1), "COVER_LIMIT_HIGH");
        bad(&mut cx, |a| a.max_links = u32::MAX, "COVER_LIMIT_THIN");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().deductible_bps = 999, "COVER_DEDUCTIBLE");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().deductible_bps = 9001, "COVER_DEDUCTIBLE");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().premium_bps = 2001, "COVER_PREMIUM");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().claim_window = U64(399), "COVER_WINDOW");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().claim_window = U64(MAX_TENOR_SECS + 1), "COVER_WINDOW");
        bad(&mut cx, |a| { a.valid_until = U64(T0 + MAX_TENOR_SECS * NS + 1); a.cover.as_mut().unwrap().premium_bps = 0; }, "COVER_TENOR");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().arbiter = acc("g.near"), "COVER_ARBITER");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().arbiter = acc("funder.near"), "COVER_ARBITER");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().arbiter = acc("owner.near"), "COVER_ARBITER");
        bad(&mut cx, |a| a.scope.push(acc("funder.near")), "COVER_SCOPE");
        bad(&mut cx, |a| a.scope.push(acc("g.near")), "COVER_SCOPE");
        bad(&mut cx, |a| a.scope.push(acc("arb.near")), "COVER_SCOPE");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().arbiter = acc("writ.near"), "COVER_ARBITER");
        bad(&mut cx, |a| a.scope.push(acc("writ.near")), "COVER_SCOPE");
        // The company is the guarantor: named as both, attested for this funder
        bad(&mut cx, |a| a.verifier = acc("funder.near"), "COVER_GUARANTOR");
        // The fee must leave one maximum payment under what the cover can pay.
        // Limit 50, 5 per payment: the cap is 45 units. 20% for 5 periods is the whole limit
        bad(&mut cx, |a| { a.cover.as_mut().unwrap().premium_bps = 2000; a.valid_until = U64(T0 + 121 * DAY * NS); }, "COVER_PREMIUM");
        // 90% share of 100 links: it can pay 10 at most, so the cap is 5 units, whatever the limit
        bad(&mut cx, |a| { let c = a.cover.as_mut().unwrap(); c.deductible_bps = 9000; c.premium_bps = 1001; }, "COVER_PREMIUM");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().terms_hash = "zz".into(), "BAD_HEX:cover_terms_hash");
        bad(&mut cx, |a| a.cover.as_mut().unwrap().terms_hash = "ab".into(), "BAD_LEN:cover_terms_hash");
        // Exactly on each boundary it opens, and stays only offered
        let good: [fn(&mut RegisterArgs); 9] = [
            // Exactly at the fee cap: 45 of a 50 limit, and 5 of the 10 a 90% share can pay
            |a| { a.cover.as_mut().unwrap().premium_bps = 1800; a.valid_until = U64(T0 + 150 * DAY * NS); },
            |a| { let c = a.cover.as_mut().unwrap(); c.deductible_bps = 9000; c.premium_bps = 1000; },
            |_| {},
            |a| a.cover.as_mut().unwrap().limit = U128(100 * UNIT),
            |a| a.cover.as_mut().unwrap().deductible_bps = 1000,
            |a| a.cover.as_mut().unwrap().deductible_bps = 9000,
            |a| a.cover.as_mut().unwrap().premium_bps = 2000,
            |a| a.cover.as_mut().unwrap().claim_window = U64(MAX_TENOR_SECS),
            |a| { a.valid_until = U64(T0 + MAX_TENOR_SECS * NS); a.cover.as_mut().unwrap().premium_bps = 0; },
        ];
        for f in good {
            let id = signed(&mut cx, f).unwrap_or_else(|| panic!("refused: {}", cx.last_err));
            assert_eq!(cover(&cx, id).state, CoverState::Offered);
            assert_eq!(cover(&cx, id).guarantor, acc("g.near"));
        }
        // Its opening fee carries the records: one yocto under the fee is refused
        let d = |cx: &mut Cx, n: u32, extra: i8| {
            let dep = (register_fee(n) + n as u128 * COVER_STORAGE_PER_LINK) as i128 + extra as i128;
            let (pk2, signer) = sign_key(&[42; 32]);
            let g = acc("g.near");
            cx.run("poke", &writ(), None, 0, |w| { w.verifiers.insert(g, pk2); }).unwrap();
            cx.nextpk += 1;
            let np = cx.nextpk;
            let mut a = RegisterArgs { amc_said: format!("EFEE{}", np), issuer_aid: "A".into(), issuer_pk: "00".repeat(32), agent_pk: pk(np), w0: "00".repeat(32), n, unit: U128(U), scope: vec![acc("s1.near")], valid_until: U64(cx.now + 1000 * NS), daily_links: 10, max_links: 1, max_strikes: 3, lei_commit: "00".repeat(32), ecr_commit: "00".repeat(32), verifier: acc("g.near"), attested_at: U64(cx.now), signature: String::new(), asset: None, credit: None, cover: Some(CoverArgs { limit: U128(10 * U), deductible_bps: 2000, premium_bps: 100, claim_window: U64(400), arbiter: acc("arb.near"), terms_hash: "cd".repeat(32) }) };
            cx.up(&writ(), None, 0);
            a.signature = hex::encode(signer(attestation_message(&a, &acc("funder.near"), &writ()).as_bytes()));
            cx.run("register", &acc("funder.near"), None, dep as u128, |w| w.register(a).0)
        };
        assert!(d(&mut cx, 10, 0).is_none());
        assert!(cx.last_err.contains("DEPOSIT_BELOW_FEE"));
        let id = d(&mut cx, 10, 1).expect("one yocto above the fee opens");
        assert_eq!(cell(&cx, id).vault.0, 1);
    }

    // 15. Every cover field is signed
    #[test]
    fn the_attestation_covers_every_cover_field() {
        let (cx, _) = world(opt());
        cx.up(&writ(), None, 0);
        let args = |c: Option<CoverArgs>| RegisterArgs { amc_said: "E".into(), issuer_aid: "A".into(), issuer_pk: "00".repeat(32), agent_pk: pk(1), w0: "00".repeat(32), n: 1, unit: U128(1), scope: vec![acc("s1.near")], valid_until: U64(1), daily_links: 1, max_links: 1, max_strikes: 1, lei_commit: "00".repeat(32), ecr_commit: "00".repeat(32), verifier: acc("g.near"), attested_at: U64(1), signature: String::new(), asset: None, credit: None, cover: c };
        let base = CoverArgs { limit: U128(7), deductible_bps: 2000, premium_bps: 100, claim_window: U64(400), arbiter: acc("arb.near"), terms_hash: "cd".repeat(32) };
        let msg = |c: Option<CoverArgs>| attestation_message(&args(c), &acc("funder.near"), &writ());
        assert!(msg(None).starts_with("writ:attest:v7\n"));
        assert!(msg(None).ends_with("\ncredit=none\ncover=none"), "{}", msg(None));
        assert!(msg(Some(base.clone())).ends_with(&format!("\ncover=7,2000,100,400,arb.near,{}", "cd".repeat(32))));
        let mut seen = vec![msg(None), msg(Some(base.clone()))];
        let edits: [fn(&mut CoverArgs); 6] = [
            |c| c.limit = U128(8),
            |c| c.deductible_bps = 2001,
            |c| c.premium_bps = 101,
            |c| c.claim_window = U64(401),
            |c| c.arbiter = acc("other.near"),
            |c| c.terms_hash = "ce".repeat(32),
        ];
        for f in edits {
            let mut c = base.clone();
            f(&mut c);
            let m = msg(Some(c));
            assert!(!seen.contains(&m));
            seen.push(m);
        }
    }

    #[test]
    fn a_token_mandate_with_cover_alone_opens_a_stake_account_and_refunds_extra_near() {
        let (mut cx, _) = world(opt());
        let id = signed(&mut cx, |a| { a.asset = Some(acc("usdc.near")); }).unwrap_or_else(|| panic!("{}", cx.last_err));
        cx.token = Some(acc("usdc.near"));
        assert!(cx.peek(|w| w.stakes.contains_key(&(acc("g.near"), Some(acc("usdc.near"))))), "cover alone opens the stake account");
        assert_eq!(cell(&cx, id).near_reserve.0, 0);
        assert_eq!(cell(&cx, id).vault.0, 0);
        assert!(cx.ft("stake", &acc("g.near"), 100 * U, "stake".into()), "{}", cx.last_err);
        // A cover in a token nobody signed still cannot open a stake
        cx.token = Some(acc("fake.near"));
        assert!(!cx.ft("stake", &acc("g.near"), U, "stake".into()));
        assert!(cx.last_err.contains("STAKE_ASSET_UNKNOWN"));
    }
    }
}
