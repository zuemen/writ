// 確定性測試：每條錢路核對精確金額，每個期限核對到奈秒。隨機 fuzz 和攻擊台抓不到的突變靠這裡。
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
        let mut cx = Cx { snap: HashMap::new(), now: T0, bal: 5_000_000 * 1_000_000_000_000_000_000_000_000u128, rng: 1, pending: VecDeque::new(), cells: vec![], roots: vec![], credits: vec![], nextpk: 0, nextinv: 1, ok: Default::default(), fail: Default::default(), hits: Default::default(), log: vec![], sur: 0, last_err: String::new() };
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
                daily_links: o.daily, max_links: o.maxl, max_strikes: 100, day: T0 / NS_PER_DAY, day_used: 0, vault: U128(o.vault), unclaimed: U128(0), spends: 0, rejects: 0, strikes: 0, status: Status::Active, asset: None, root: id, parent: None, depth: 0, children: vec![], tree_size: 1 });
            w.key_to_cell.insert(p2.clone(), id);
            w.used_keys.insert(p2.clone());
            w.vault_total += o.vault;
            w.terms.insert(id, CreditTerms { terms_ecr_commit: String::new(), args: CreditArgs { limit: U128(o.limit), bond_bps: o.bond, premium_bps: o.premium, min_tenor: U64(10), max_tenor: U64(o.max_tenor), terms_hash: "00".repeat(32), terms_sig: "00".repeat(64), entity_tag: "t".into(), arbiter: acc("arb.near"), fee_payer: o.payer, seller_cap_bps: o.cap }, guarantor: acc("g.near"), outstanding: U128(0), bond_locked: U128(0), open_debts: 0 });
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
    fn stake(cx: &Cx) -> Stake { cx.peek(|w| w.stakes.get(&acc("g.near")).cloned().unwrap_or_default()) }
    fn claim(cx: &Cx, a: &str) -> Option<u128> { let a = acc(a); cx.peek(|w| w.claimable.get(&a).copied()) }
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
        assert_eq!(Contract::entity_key(&acc("g.near"), "t"), "g.near:t");
    }

    #[test]
    fn spend_expires_after_the_exact_nanosecond() {
        let (mut cx, r) = world(opt());
        cx.now = VALID;
        let (p, k) = (link(&cx, r, 1), key(&cx, r));
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), "aa".repeat(32)); }).unwrap();
        assert_eq!(cell(&cx, r).idx, 1, "still valid at valid_until");
        cx.now = VALID + 1;
        let p = link(&cx, r, 1);
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), "bb".repeat(32)); }).unwrap();
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
                let _ = w.on_transfer(U64(r), U128(5), "00".repeat(32), acc("s1.near"), 1, 0, Err(PromiseError::Failed));
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
        cx.run("req", &acc("g.near"), None, 0, |w| w.request_unstake()).unwrap();
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
        // 期限
        let (mut cx, r) = world(opt());
        cx.now = VALID;
        opened(open(&mut cx, r, 1));
        cx.now = VALID + 1;
        assert_eq!(why(&open(&mut cx, r, 1)), "EXPIRED");
        // 單筆上限
        let mut o = opt(); o.maxl = 2;
        let (mut cx, r) = world(o);
        assert_eq!(why(&open(&mut cx, r, 3)), "PER_TX");
        opened(open(&mut cx, r, 2));
        // 鏈長
        let mut o = opt(); o.n = 3; o.maxl = 10;
        let (mut cx, r) = world(o);
        assert_eq!(why(&open(&mut cx, r, 0)), "LIMIT");
        assert_eq!(why(&open(&mut cx, r, 4)), "LIMIT");
        opened(open(&mut cx, r, 3));
        // 信用額度
        let mut o = opt(); o.limit = 2 * U;
        let (mut cx, r) = world(o);
        opened(open(&mut cx, r, 2));
        assert_eq!(why(&open(&mut cx, r, 1)), "CREDIT_LIMIT");
        // 天期
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

    /// 兩筆各 2U、保證金各 1U 都已接受。
    fn two_bonded(vault: u128) -> (Cx, u64, u64, u64) {
        let mut o = opt(); o.vault = vault; o.bond = 5000;
        let (mut cx, r) = world(o);
        let a = opened(open(&mut cx, r, 2));
        let b = opened(open(&mut cx, r, 2));
        accept(&mut cx, a); accept(&mut cx, b);
        assert_eq!(outstanding(&cx, r).1, 2 * U);
        (cx, r, a, b)
    }

    /// 保證金是硬性要求：金庫少 1 yocto 就 BOND_SHORT，什麼都不動；剛好夠才成立。
    #[test]
    fn a_bond_is_hard_to_the_exact_yocto() {
        // 5U 的 100%：金庫扣掉單據儲存後剛好 5U 減 1
        let mut o = opt(); o.vault = 5 * U + S - 1; o.bond = 10_000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 5));
        let (v0, st0) = (cell(&cx, r).vault.0, stake(&cx));
        cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k)));
        assert_eq!(cred(&cx, k).status, CreditStatus::Open, "BOND_SHORT leaves the order open");
        assert_eq!((cell(&cx, r).vault.0, stake(&cx).exposure.0, st0.exposure.0, outstanding(&cx, r).1), (v0, 0, 0, 0));
        // 補 1 yocto 就剛好成立，曝險只有沒押保證金的部分
        set_vault(&mut cx, r, v0 + 1);
        accept(&mut cx, k);
        let c = cred(&cx, k);
        assert_eq!((c.bond_locked.0, c.exposure.0), (5 * U, 0));
        // 費用先扣：付完費用剩下的才算得上保證金
        let mut o = opt(); o.vault = 5 * U + S - 1; o.bond = 8000; o.premium = 2000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 5));
        cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k)));
        assert_eq!(cred(&cx, k).status, CreditStatus::Open, "1U fee + 4U bond is one yocto short");
    }

    /// 接受時才算期數：差 1 奈秒就多一期。
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

    /// 期數從賣方接受那一刻算，不是開單那一刻：晚接受可能少一期。
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
        // 到期日已過才接受，也只收一期
        let mut o = opt(); o.premium = 100;
        let (mut cx, r) = world(o);
        let due = cx.now + 10 * NS;
        let k = opened(open_at(&mut cx, r, 3, due));
        cx.now += 50 * NS;
        let v = cell(&cx, r).vault.0;
        accept(&mut cx, k);
        assert_eq!(cell(&cx, r).vault.0, v - 3 * U / 100);
    }

    /// 賣方付費：接受時什麼都不收，費用定在單上。
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
        // agent 結清
        let (mut cx, r, k, fee) = seller_pays(500, 100 * U);
        assert_eq!(cred(&cx, k).fee.0, fee);
        let (v, t) = (cell(&cx, r).vault.0, total(&cx));
        assert!(settle(&mut cx, r, k));
        assert_eq!(cell(&cx, r).vault.0, v - 4 * U, "the buyer pays the invoice, no more");
        assert_eq!(total(&cx), t, "the fee moved between buckets");
        fee_went_to_the_guarantor(&cx, fee);
        // 公司從金庫結清
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        cx.run("sf", &acc("funder.near"), None, 0, |w| w.settle_by_funder(U64(k))).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
        // 公司帶錢結清
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        cx.run("sf", &acc("funder.near"), None, 4 * U, |w| w.settle_by_funder(U64(k))).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
        // 違約，金庫賠
        let (mut cx, _, k, fee) = seller_pays(500, 100 * U);
        deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        fee_went_to_the_guarantor(&cx, fee);
        // 爭議判賣方勝
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
        // 爭議判公司勝
        let (mut cx, _, k, _) = seller_pays(500, 100 * U);
        cx.run("d", &acc("funder.near"), None, 4 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), false)).unwrap();
        assert_eq!(claim(&cx, "s1.near"), None);
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (10 * U, 0));
        // 接受了沒交貨，過期取消
        let (mut cx, _, k, _) = seller_pays(500, 100 * U);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("x", &acc("x.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert_eq!(cred(&cx, k).status, CreditStatus::Cancelled);
        assert_eq!(claim(&cx, "s1.near"), None);
        assert_eq!((stake(&cx).amount.0, stake(&cx).earned.0), (10 * U, 0));
    }

    /// 費用超過貨款（天期很長）：最多扣到零，不會倒扣賣方。
    #[test]
    fn a_seller_paid_fee_stops_at_the_amount() {
        const P: u64 = 30 * 86_400 * NS;
        let mut o = opt(); o.premium = 2000; o.payer = FeePayer::Seller; o.max_tenor = 400 * 86_400;
        let (mut cx, r) = world(o);
        let due = cx.now + 6 * P;
        let k = opened(open_at(&mut cx, r, 4, due));
        accept(&mut cx, k);
        assert_eq!(cred(&cx, k).fee.0, 4 * U * 12 / 10);
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
        // 額度放回去了：6U 上限還能再開 3U
        opened(open(&mut cx, r, 3));
        assert_eq!(why(&open(&mut cx, r, 1)), "CREDIT_LIMIT");
        // 付的是實際金額
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
        // 尚未接受、已爭議：都不能改金額
        let k = opened(open(&mut cx, r, 2));
        assert!(!deliver_final(&mut cx, k, U), "not accepted");
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, 2 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        assert!(!deliver_final(&mut cx, k, U), "disputed");
        deliver(&mut cx, k);
        assert_eq!(cred(&cx, k).amount.0, 2 * U);
        // 1 yocto 也行，保證金取整到 0，曝險 1
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
        SellerPolicy { max_amount: U128(max), max_tenor_secs: U64(tenor), min_bond_bps: bond, max_defaults: defaults, guarantors: gs.iter().map(|g| acc(g)).collect() }
    }
    fn set_rule(cx: &mut Cx, p: Option<SellerPolicy>, dep: u128) -> bool { cx.run("set", &acc("s1.near"), None, dep, |w| w.set_seller_policy(p)).is_some() }
    fn accept_err(cx: &mut Cx, k: u64) -> bool { cx.run("accept", &acc("s1.near"), None, 0, |w| w.accept_credit(U64(k))).is_none() }
    fn check(cx: &Cx, k: u64, p: Option<SellerPolicy>) -> OrderCheck { cx.peek(|w| w.check_order(U64(k), p)) }

    #[test]
    fn a_policy_costs_a_deposit_once_and_the_excess_is_claimable() {
        let (mut cx, _) = world(opt());
        let p = || Some(rule(U, 100, 0, 0, &[]));
        assert!(!set_rule(&mut cx, p(), SELLER_POLICY_STORAGE - 1));
        assert!(cx.peek(|w| w.policies.get(&acc("s1.near")).is_none()));
        let (t, ok) = (total(&cx), set_rule(&mut cx, p(), SELLER_POLICY_STORAGE));
        assert!(ok);
        assert_eq!((total(&cx), claim(&cx, "s1.near")), (t, None), "the deposit pays for storage, it is nobody's money");
        assert!(set_rule(&mut cx, Some(rule(2 * U, 100, 0, 0, &[])), 0), "changing the rule costs nothing");
        assert_eq!(cx.peek(|w| w.seller_policy(acc("s1.near"))).unwrap().max_amount.0, 2 * U);
        assert!(set_rule(&mut cx, p(), 9));
        assert_eq!((total(&cx), claim(&cx, "s1.near")), (t + 9, Some(9)));
        assert!(set_rule(&mut cx, None, 0));
        assert!(cx.peek(|w| w.seller_policy(acc("s1.near"))).is_none());
        assert!(!set_rule(&mut cx, p(), SELLER_POLICY_STORAGE - 1), "setting it again pays again");
        assert!(set_rule(&mut cx, p(), SELLER_POLICY_STORAGE));
        // 上限與比例
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
        // 金額
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        assert!(set_rule(&mut cx, Some(rule(2 * U - 1, 10_000, 0, 9, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["ORDER_TOO_LARGE"]);
        assert!(accept_err(&mut cx, k));
        assert_eq!(cred(&cx, k).status, CreditStatus::Open);
        assert!(set_rule(&mut cx, Some(rule(2 * U, 10_000, 0, 9, &[])), 0));
        assert!(check(&cx, k, None).ok);
        accept(&mut cx, k);
        // 天期
        let (mut cx, r) = world(opt());
        let n = cx.now;
        let k = opened(open_at(&mut cx, r, 1, n + 100 * NS));
        assert!(set_rule(&mut cx, Some(rule(U, 99, 0, 9, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["TENOR_TOO_LONG"]);
        assert!(set_rule(&mut cx, Some(rule(U, 100, 0, 9, &[])), 0));
        assert!(check(&cx, k, None).ok);
        // 保證金
        let mut o = opt(); o.bond = 2500;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 2501, 9, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["BOND_TOO_LOW"]);
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 2500, 9, &[])), 0));
        assert!(check(&cx, k, None).ok);
        // 違約數
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 1));
        cx.run("rec", &writ(), None, 0, |w| { w.entities.insert("g.near:t".to_string(), EntityRecord { defaults: 2, ..Default::default() }); }).unwrap();
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 0, 1, &[])), SELLER_POLICY_STORAGE));
        assert_eq!(check(&cx, k, None).reasons, vec!["TOO_MANY_DEFAULTS"]);
        assert!(set_rule(&mut cx, Some(rule(U, 10_000, 0, 2, &[])), 0));
        assert!(check(&cx, k, None).ok);
        // 保證人清單
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
        cx.run("rec", &writ(), None, 0, |w| { w.entities.insert("g.near:t".to_string(), EntityRecord { defaults: 1, ..Default::default() }); }).unwrap();
        let strict = rule(U, 10, 20_000, 0, &["other.near"]);
        let c = check(&cx, k, Some(strict.clone()));
        assert!(!c.ok);
        assert_eq!(c.reasons, vec!["ORDER_TOO_LARGE", "TENOR_TOO_LONG", "BOND_TOO_LOW", "TOO_MANY_DEFAULTS", "GUARANTOR_NOT_APPROVED", "BOND_SHORT"]);
        assert_eq!(c.order["bond"], json_str(3 * U));
        assert_eq!(c.order["guarantor_exposure"], json_str(0));
        assert_eq!(c.order["policy_applied"], true);
        // 傳入的規則只是問問：沒有存，accept 不看它
        assert!(cx.peek(|w| w.policies.get(&acc("s1.near")).is_none()));
        let g = cx.peek(|w| w.check_order(U64(k), None));
        assert_eq!((g.reasons, g.order["policy_applied"].clone()), (vec!["BOND_SHORT".to_string()], Value::Bool(false)));
        // 存了之後 accept 用第一條理由報錯
        assert!(set_rule(&mut cx, Some(rule(U, 10, 0, 9, &[])), SELLER_POLICY_STORAGE));
        assert!(accept_err(&mut cx, k));
        assert!(cx.last_err.contains("POLICY:ORDER_TOO_LARGE"), "{}", cx.last_err);
    }

    #[test]
    fn check_order_also_sees_what_the_money_and_the_state_would_refuse() {
        // 沒質押
        let mut o = opt(); o.stake = 0;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        assert_eq!(check(&cx, k, None).reasons, vec!["GUARANTOR_CAPACITY"]);
        // 付不起費用，也鎖不起保證金
        let mut o = opt(); o.premium = 2000; o.vault = S + 1; o.bond = 5000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 1));
        assert_eq!(check(&cx, k, None).reasons, vec!["PREMIUM_SHORT", "BOND_SHORT"]);
        // 過期的報價、已接受的單
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

    fn to_seller(cx: &Cx, s: &str) -> u128 { let s = acc(s); cx.peek(|w| w.seller_exposure_of(&acc("g.near"), &s)) }
    fn open_to(cx: &mut Cx, id: u64, j: u32, seller: &str) -> u64 {
        cx.nextinv += 1;
        let (p, k, inv, due, s) = (link(cx, id, j), key(cx, id), hex::encode(env_hash(cx.nextinv)), cx.now + 500 * NS, acc(seller));
        opened(cx.run("open", &writ(), Some(&k), 0, |w| w.open_credit(p, j, s, inv, U64(due))).expect("open"))
    }

    #[test]
    fn the_seller_cap_is_exact_and_per_seller() {
        // 質押 10U，上限 20%：同一個賣方最多 2U
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
        // 別的賣方不受影響
        let d = open_to(&mut cx, r, 2, "s2.near");
        cx.run("accept", &acc("s2.near"), None, 0, |w| w.accept_credit(U64(d))).expect("another seller has its own cap");
        assert_eq!(to_seller(&cx, "s2.near"), 2 * U);
        // 結清一筆，額度回來
        assert!(settle(&mut cx, r, a));
        assert_eq!(to_seller(&cx, "s1.near"), U);
        accept(&mut cx, c);
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U);

        // 上限 0 = 不限；保證金 100% 的單沒有曝險，不佔上限
        let mut o = opt(); o.cap = 0;
        let (mut cx, r) = world(o);
        let k = open_to(&mut cx, r, 5, "s1.near");
        accept(&mut cx, k);
        let mut o = opt(); o.cap = 1; o.bond = 10_000;
        let (mut cx, r) = world(o);
        let k = open_to(&mut cx, r, 5, "s1.near");
        accept(&mut cx, k);
        assert_eq!(to_seller(&cx, "s1.near"), 0);
        assert!(cx.peek(|w| !w.seller_exposure.contains_key(&(acc("g.near"), acc("s1.near")))), "no entry for zero");
    }

    #[test]
    fn the_seller_exposure_follows_every_way_an_order_ends() {
        // 用量單縮小
        let mut o = opt(); o.bond = 5000;
        let (mut cx, r) = world(o);
        let k = opened(open(&mut cx, r, 4));
        accept(&mut cx, k);
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U);
        assert!(deliver_final(&mut cx, k, 2 * U));
        assert_eq!(to_seller(&cx, "s1.near"), U);
        // 違約：曝險結束，賠多少記在債上
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 0);
        assert!(cx.peek(|w| !w.seller_exposure.contains_key(&(acc("g.near"), acc("s1.near")))));
        // 接受了沒交貨，過期取消
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("x", &acc("x.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 0);
        // 爭議判公司勝
        let (mut cx, r) = world(opt());
        let k = opened(open(&mut cx, r, 2));
        accept(&mut cx, k);
        cx.run("d", &acc("funder.near"), None, 2 * U, |w| w.dispute(U64(k), "cd".repeat(32))).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 2 * U, "still exposed during the dispute");
        cx.run("r", &acc("arb.near"), None, 0, |w| w.resolve_dispute(U64(k), false)).unwrap();
        assert_eq!(to_seller(&cx, "s1.near"), 0);
    }

    #[test]
    fn settle_may_use_only_its_own_bond() {
        let (mut cx, r, a, _) = two_bonded(3 * U);
        assert!(!settle(&mut cx, r, a), "the other order's bond is not available");
        let (mut cx, r, a, _) = two_bonded(4 * U);
        assert!(settle(&mut cx, r, a));
        assert_eq!(cell(&cx, r).vault.0, 2 * U - 2 * S);
        assert_eq!(outstanding(&cx, r), (2 * U, U, 0));
        let rec = cx.peek(|w| w.entities.get("g.near:t").cloned().unwrap());
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
        cx.run("cb", &writ(), None, 0, |w| w.on_withdraw(acc("s1.near"), U128(5), Ok(()))).unwrap();
        assert_eq!((claim(&cx, "s1.near"), total(&cx)), (None, t));
        cx.run("cb", &writ(), None, 0, |w| w.on_withdraw(acc("s1.near"), U128(5), Err(PromiseError::Failed))).unwrap();
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
        // 金庫不夠時，別筆的 1U 保證金不能動，差額由保證人賠
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
        assert!(cx.peek(|w| w.stakes.get(&acc("g.near")).is_none()), "a guarantor that never staked has no stake entry");
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

    /// 金庫不夠，保證人賠了 1U+S。
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
        // 開單、接受：還沒付
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        assert!(!paid(&cx, r, &inv), "an open order is not a payment");
        accept(&mut cx, k);
        assert!(!paid(&cx, r, &inv));
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE", "but it cannot be ordered twice");
        // 結清：付了，也不能再開
        assert!(settle(&mut cx, r, k));
        assert!(paid(&cx, r, &inv));
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE");

        // 取消：沒人收到錢，發票放回去
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        cx.run("x", &acc("funder.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap();
        assert!(!paid(&cx, r, &inv));
        opened(open_inv(&mut cx, r, &inv));

        // 違約：賣方拿到錢了
        let (mut cx, r) = world(opt());
        let k = opened(open_inv(&mut cx, r, &inv));
        accept(&mut cx, k); deliver(&mut cx, k);
        cx.now = cred(&cx, k).due_at.0 + 51 * NS;
        cx.run("c", &acc("s1.near"), None, 0, |w| w.claim_default(U64(k))).unwrap();
        assert!(paid(&cx, r, &inv), "the seller was paid");
        assert_eq!(why(&open_inv(&mut cx, r, &inv)), "DUPLICATE");

        // 爭議判給公司：沒人收到錢
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
        // 有交貨的逾時算賣方贏：發票算已付
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
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i2); }).unwrap();
        assert!(!paid(&cx, r, &inv), "still in flight");
        cx.resolve(false);
        assert!(paid(&cx, r, &inv), "the transfer landed");

        let (mut cx, r) = world(opt());
        let (p, k) = (link(&cx, r, 1), key(&cx, r));
        let i2 = inv.clone();
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i2); }).unwrap();
        cx.resolve(true);
        assert!(!paid(&cx, r, &inv), "the transfer failed");
        let (p, i2) = (link(&cx, r, 1), inv.clone());
        cx.run("spend", &writ(), Some(&k), 0, |w| { let _ = w.spend(p, 1, acc("s1.near"), i2); }).unwrap();
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
}
