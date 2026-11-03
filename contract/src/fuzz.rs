// 隨機序列不變量測試：隨機呼叫加隨機 callback 失敗，每步核對總帳。SEEDS、STEPS 可調。
#[cfg(test)]
mod fuzz {
    use super::*;
    use near_sdk::mock::MockAction;
    use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
    use near_sdk::{MockedBlockchain, RuntimeFeesConfig};
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const NS: u64 = 1_000_000_000;
    const UNIT: u128 = 100_000_000_000_000_000_000_000; // 0.1 NEAR

    fn acc(s: &str) -> AccountId { s.parse().unwrap() }
    fn writ() -> AccountId { acc("writ.near") }
    fn pk(i: u8) -> PublicKey { let mut v = vec![0u8]; v.extend_from_slice(&[i + 1; 32]); PublicKey::try_from(v).unwrap() }

    struct CellH { id: u64, pk: PublicKey, links: Vec<String> }
    struct Cb { method: String, args: Value }

    struct Cx {
        snap: HashMap<Vec<u8>, Vec<u8>>,
        now: u64,
        bal: u128,
        rng: u64,
        pending: VecDeque<Cb>,
        cells: Vec<CellH>,
        roots: Vec<u64>,
        credits: Vec<u64>,
        nextpk: u8,
        nextinv: u64,
        ok: BTreeMap<String, u64>,
        fail: BTreeMap<String, u64>,
        hits: BTreeMap<String, u64>,
        log: Vec<String>,
        sur: u128,
    }

    impl Cx {
        fn r(&mut self, n: u64) -> u64 {
            let mut x = self.rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.rng = x; x % n
        }
        fn up(&self, pred: &AccountId, signer: Option<&PublicKey>, dep: u128) {
            let mut b = VMContextBuilder::new();
            b.current_account_id(writ()).predecessor_account_id(pred.clone()).signer_account_id(if signer.is_some() { writ() } else { pred.clone() })
                .attached_deposit(NearToken::from_yoctonear(dep)).block_timestamp(self.now)
                .account_balance(NearToken::from_near(10_000_000)).prepaid_gas(Gas::from_tgas(1000));
            if let Some(p) = signer { b.signer_account_pk(p.clone()); }
            let mb = MockedBlockchain::new(b.build(), near_sdk::test_vm_config(), RuntimeFeesConfig::test(), vec![], self.snap.clone(), Default::default(), None);
            near_sdk::env::set_blockchain_interface(mb);
        }
        fn peek<R>(&self, f: impl FnOnce(&Contract) -> R) -> R {
            self.up(&writ(), None, 0);
            let w: Contract = env::state_read().unwrap();
            let r = f(&w);
            std::mem::forget(w);
            r
        }
        fn run<R>(&mut self, name: &str, pred: &AccountId, signer: Option<&PublicKey>, dep: u128, f: impl FnOnce(&mut Contract) -> R) -> Option<R> {
            self.up(pred, signer, dep);
            let res = catch_unwind(AssertUnwindSafe(|| {
                let mut w: Contract = env::state_read().unwrap();
                let r = f(&mut w);
                env::state_write(&w);
                drop(w);
                r
            }));
            match res {
                Ok(r) => {
                    *self.ok.entry(name.to_string()).or_default() += 1;
                    self.bal += dep;
                    for rc in get_created_receipts() {
                        for a in rc.actions.iter() {
                            match a {
                                MockAction::Transfer { deposit, .. } => { self.bal -= deposit.as_yoctonear(); }
                                MockAction::FunctionCallWeight { method_name, args, .. } => {
                                    let m = String::from_utf8(method_name.clone()).unwrap();
                                    if m.starts_with("on_") {
                                        self.pending.push_back(Cb { method: m, args: serde_json::from_slice(args).unwrap() });
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    self.snap = near_sdk::mock::with_mocked_blockchain(|b| b.take_storage());
                    self.log.push(format!("{} ok", name));
                    Some(r)
                }
                Err(_) => { *self.fail.entry(name.to_string()).or_default() += 1; None }
            }
        }
        fn resolve(&mut self, fail: bool) {
            let Some(cb) = self.pending.pop_front() else { return };
            let amt: u128 = cb.args["amount"].as_str().unwrap().parse().unwrap();
            if fail { self.bal += amt; }
            let r: Result<(), PromiseError> = if fail { Err(PromiseError::Failed) } else { Ok(()) };
            let a = cb.args.clone();
            match cb.method.as_str() {
                "on_transfer" => {
                    self.run("cb_on_transfer", &writ(), None, 0, |w| {
                        let _ = w.on_transfer(U64(a["cell"].as_str().unwrap().parse().unwrap()), U128(amt), a["invoice_hash"].as_str().unwrap().to_string(), a["to"].as_str().unwrap().parse().unwrap(), a["idx"].as_u64().unwrap() as u32, a["remaining"].as_u64().unwrap() as u32, r);
                    }).expect("on_transfer must not panic");
                }
                "on_refund" => { self.run("cb_on_refund", &writ(), None, 0, |w| w.on_refund(U64(a["cell"].as_str().unwrap().parse().unwrap()), U128(amt), r)).expect("on_refund must not panic"); }
                "on_withdraw" => { self.run("cb_on_withdraw", &writ(), None, 0, |w| w.on_withdraw(a["who"].as_str().unwrap().parse().unwrap(), U128(amt), r)).expect("on_withdraw must not panic"); }
                m => panic!("unknown cb {}", m),
            }
        }
        fn hit(&mut self, s: &str) { *self.hits.entry(s.to_string()).or_default() += 1; }

        fn check(&mut self, seed: u64, op: &str) {
            let cells: Vec<u64> = self.cells.iter().map(|c| c.id).collect();
            let roots = self.roots.clone();
            let credits = self.credits.clone();
            let bal = self.bal;
            let errs: Vec<String> = self.peek(|w| {
                let mut e = vec![];
                let mut sum = 0u128;
                for id in &cells { let c = w.cells.get(id).unwrap(); sum += c.vault.0 + c.unclaimed.0; }
                let g = acc("g.near");
                let st = w.stakes.get(&g).cloned().unwrap_or_default();
                sum += st.amount.0;
                for a in ["s1.near", "s2.near", "funder.near", "g.near", "arb.near"] { sum += w.claimable.get(&acc(a)).copied().unwrap_or(0); }
                let mut exp = 0u128;
                for r in &roots {
                    let Some(t) = w.terms.get(r) else { continue };
                    let (mut o, mut b, mut d) = (0u128, 0u128, 0u32);
                    for k in &credits {
                        let c = w.credits.get(k).unwrap();
                        if c.root.0 != *r { continue; }
                        if matches!(c.status, CreditStatus::Open | CreditStatus::Accepted | CreditStatus::Delivered | CreditStatus::Disputed) {
                            o += c.amount.0; b += c.bond_locked.0; exp += c.exposure.0;
                        }
                        if c.debt.0 > 0 { d += 1; if !matches!(c.status, CreditStatus::Defaulted | CreditStatus::Enforced) { e.push(format!("debt in status {:?}", c.status)); } }
                        if c.status == CreditStatus::Disputed { if c.dispute_escrow.0 < c.amount.0 { e.push("escrow<amount".into()); } } else if c.dispute_escrow.0 != 0 { e.push("escrow left".into()); }
                    }
                    if t.outstanding.0 != o { e.push(format!("outstanding {} vs {}", t.outstanding.0, o)); }
                    if t.bond_locked.0 != b { e.push(format!("bond_locked {} vs {}", t.bond_locked.0, b)); }
                    if t.open_debts != d { e.push(format!("open_debts {} vs {}", t.open_debts, d)); }
                    let rc = w.cells.get(r).unwrap();
                    if rc.vault.0 < t.bond_locked.0 { e.push(format!("root vault {} < bond {}", rc.vault.0, t.bond_locked.0)); }
                    if matches!(rc.status, Status::Revoked { .. }) && t.outstanding.0 == 0 && t.open_debts == 0 && rc.vault.0 > 0 { e.push(format!("closed root stuck vault {}", rc.vault.0)); }
                }
                for k in &credits { let c = w.credits.get(k).unwrap(); if c.status == CreditStatus::Disputed { sum += c.dispute_escrow.0; } }
                if st.exposure.0 != exp { e.push(format!("exposure {} vs {}", st.exposure.0, exp)); }
                if st.amount.0 < st.exposure.0 { e.push("stake<exposure".into()); }
                for id in &cells {
                    let c = w.cells.get(id).unwrap();
                    if c.root != *id && matches!(c.status, Status::Revoked { .. }) && c.vault.0 > 0 { e.push(format!("closed child holds vault {}", id)); }
                }
                if sum != w.vault_total { e.push(format!("vault_total {} vs buckets {}", w.vault_total, sum)); }
                if bal < w.vault_total { e.push(format!("balance {} < vault_total {}", bal, w.vault_total)); }
                std::mem::forget(e.clone());
                e
            });
            let vt = self.peek(|w| w.vault_total);
            let mut errs = errs;
            let sur = bal - vt;
            if sur < self.sur { errs.push(format!("surplus fell {} -> {}", self.sur, sur)); }
            self.sur = sur;
            if !errs.is_empty() {
                let tail = self.log[self.log.len().saturating_sub(25)..].join(" | ");
                panic!("INVARIANT seed={} op={} errs={:?}\ntail: {}", seed, op, errs, tail);
            }
        }
    }

    fn make_chain(n: usize, seed: u64) -> Vec<String> {
        let mut v = vec![String::new(); n + 1];
        let mut cur = env::sha256(&seed.to_le_bytes());
        v[n] = hex::encode(&cur);
        for k in (0..n).rev() { cur = env::sha256(&cur); v[k] = hex::encode(&cur); }
        v
    }

    fn new_world(seed: u64) -> Cx {
        let mut cx = Cx { snap: HashMap::new(), now: 1_000_000 * NS, bal: 5_000 * 1_000_000_000_000_000_000_000_000u128, rng: seed.wrapping_mul(0x9E3779B97F4A7C15) | 1, pending: VecDeque::new(), cells: vec![], roots: vec![], credits: vec![], nextpk: 0, nextinv: 1, ok: Default::default(), fail: Default::default(), hits: Default::default(), log: vec![], sur: 0 };
        cx.up(&writ(), None, 0);
        let w = Contract::new(acc("owner.near"), None, Some(Windows { accept_ttl: U64(100), inspect: U64(50), grace: U64(50), recourse: U64(100), dispute_timeout: U64(200), unstake_delay: U64(30) }));
        env::state_write(&w);
        drop(w);
        cx.snap = near_sdk::mock::with_mocked_blockchain(|b| b.take_storage());
        let vaults = [(cx.r(4) as u128 + 1) * UNIT, (cx.r(3) as u128 + 1) * UNIT, 10 * UNIT];
        let stake = (cx.r(25) as u128 + 6) * UNIT;
        let bps = [0u32, 2000, 5000, 10000][cx.r(4) as usize];
        let now = cx.now;
        let mut roots = vec![];
        for i in 0..3u8 {
            let p = pk(i);
            let ch = { cx.up(&writ(), None, 0); make_chain(40, seed + i as u64) };
            let w0 = ch[0].clone();
            let v = vaults[i as usize];
            let p2 = p.clone();
            let id = cx.run("init", &writ(), None, 0, |w| {
                let id = w.next_id; w.next_id += 1;
                w.cells.insert(id, Cell { amc_said: format!("E{}", id), issuer_aid: "A".into(), issuer_pk: "00".repeat(32), agent_pk: p2.clone(), verifier: acc("g.near"), funder: acc("funder.near"),
                    lei_commit: "00".repeat(32), ecr_commit: "00".repeat(32), scope: vec![acc("s1.near"), acc("s2.near")], valid_until: U64(now + 20000 * NS), unit: U128(UNIT), n: 40, idx: 0, w_cur: w0.clone(),
                    daily_links: 1000, max_links: 5, max_strikes: 8, day: now / NS_PER_DAY, day_used: 0, vault: U128(v), unclaimed: U128(0), spends: 0, rejects: 0, strikes: 0, status: Status::Active, asset: None, root: id, parent: None, depth: 0, children: vec![], tree_size: 1 });
                w.key_to_cell.insert(p2.clone(), id);
                w.used_keys.insert(p2.clone());
                w.vault_total += v;
                if i < 2 {
                    w.terms.insert(id, CreditTerms { terms_ecr_commit: String::new(), args: CreditArgs { limit: U128(20 * UNIT), bond_bps: bps, premium_bps: 150, min_tenor: U64(10), max_tenor: U64(1000), terms_hash: "00".repeat(32), terms_sig: "00".repeat(64), entity_tag: format!("t{}", i), arbiter: acc("arb.near") }, guarantor: acc("g.near"), outstanding: U128(0), bond_locked: U128(0), open_debts: 0 });
                }
                id
            }).unwrap();
            cx.cells.push(CellH { id, pk: p, links: ch });
            roots.push(id);
            cx.nextpk += 1;
        }
        cx.roots = roots;
        cx.run("init2", &writ(), None, 0, |w| { w.verifiers.insert(acc("g.near"), "00".repeat(32)); });
        if stake > 0 { cx.bal += 0; cx.run("stake", &acc("g.near"), None, stake, |w| w.stake()); }
        cx
    }

    fn tree_vault(cx: &Cx, root: u64) -> u128 {
        let ids: Vec<u64> = cx.cells.iter().map(|c| c.id).collect();
        cx.peek(|w| ids.iter().filter_map(|i| w.cells.get(i)).filter(|c| c.root == root).map(|c| c.vault.0).sum())
    }

    fn step(cx: &mut Cx, seed: u64) -> String {
        let n = cx.cells.len() as u64;
        let ci = cx.r(n) as usize;
        let (cid, cpk) = (cx.cells[ci].id, cx.cells[ci].pk.clone());
        let links = cx.cells[ci].links.clone();
        let op = cx.r(26);
        let all: Vec<Credit> = { let ids = cx.credits.clone(); cx.peek(|w| ids.iter().map(|k| w.credits.get(k).cloned().unwrap()).collect()) };
        let want = |c: &Credit| -> bool { use CreditStatus::*; match op {
            7 | 8 => c.status == Open, 9 | 10 => matches!(c.status, Accepted | Disputed), 11 | 12 | 13 => matches!(c.status, Accepted | Delivered),
            14 | 15 => c.status == Disputed, 16 | 17 => c.status == Delivered, 18 | 19 => c.debt.0 > 0, 20 => matches!(c.status, Open | Accepted), _ => true } };
        let fit: Vec<Credit> = all.iter().filter(|c| want(c)).cloned().collect();
        let info: Option<Credit> = if cx.r(10) == 0 || fit.is_empty() {
            if all.is_empty() { None } else { let k = cx.r(all.len() as u64) as usize; Some(all[k].clone()) }
        } else { let k = cx.r(fit.len() as u64) as usize; Some(fit[k].clone()) };
        let (idx, rootid) = cx.peek(|w| { let c = w.cells.get(&cid).unwrap(); (c.idx as usize, c.root) });
        let j = cx.r(3) as u32 + 1;
        let good = idx + j as usize <= links.len() - 1 && cx.r(50) != 0;
        let pre = if good { links[idx + j as usize].clone() } else { "11".repeat(32) };
        let inv = { cx.nextinv += 1; hex::encode(env_hash(cx.nextinv)) };
        let seller = if cx.r(2) == 0 { acc("s1.near") } else { acc("s2.near") };
        let funder = acc("funder.near"); let g = acc("g.near"); let arb = acc("arb.near");
        let writ_ = writ();
        let owes_before: BTreeMap<u64, u32> = { let rs = cx.roots.clone(); cx.peek(|w| rs.iter().filter_map(|r| w.terms.get(r).map(|t| (*r, t.open_debts))).collect()) };
        let tv_before: BTreeMap<u64, u128> = { let rs = cx.roots.clone(); rs.iter().filter(|r| owes_before.get(r).copied().unwrap_or(0) > 0).map(|r| (*r, tree_vault(cx, *r))).collect() };
        let opname: String = match op {
            0 | 1 => { let now = cx.now; let _ = now; let (p, s) = (pre.clone(), seller.clone()); cx.run("spend", &writ_, Some(&cpk), 0, |w| { let _ = w.spend(p, j, s, inv); }); "spend".into() }
            2 => {
                cx.nextpk = cx.nextpk.wrapping_add(1); let np = cx.nextpk;
                if np > 200 { return "skip".into(); }
                cx.up(&writ_, None, 0);
                let ch = make_chain(j as usize, seed * 1000 + np as u64);
                let w0 = ch[0].clone(); let npk = pk(np);
                let vu = cx.now + 15000 * NS;
                let p = pre.clone(); let npk2 = npk.clone();
                let v = cx.run("hire", &writ_, Some(&cpk), 0, |w| w.hire(p, j, HireArgs { agent_pk: npk2, w0, scope: vec![acc("s1.near"), acc("s2.near")], valid_until: U64(vu), daily_links: 100, max_links: 5 }));
                if let Some(Verdict::Hired { child, .. }) = v { cx.cells.push(CellH { id: child.0, pk: npk, links: ch }); }
                "hire".into()
            }
            3 => {
                let kids = cx.peek(|w| w.cells.get(&cid).unwrap().children.clone());
                if kids.is_empty() { return "skip".into(); }
                let k = kids[cx.r(kids.len() as u64) as usize];
                cx.run("dismiss", &writ_, Some(&cpk), 0, |w| w.dismiss(U64(k))); "dismiss".into()
            }
            4 | 5 | 6 => {
                let due = cx.now + (cx.r(300) + 10) * NS; let (p, s) = (pre.clone(), seller.clone());
                let v = cx.run("open_credit", &writ_, Some(&cpk), 0, |w| w.open_credit(p, j, s, inv, U64(due)));
                if let Some(Verdict::CreditOpened { credit, .. }) = v { cx.credits.push(credit.0); }
                "open_credit".into()
            }
            7 | 8 => { let Some(c) = &info else { return "skip".into() }; let s = c.seller.clone(); let k = c.id; cx.run("accept", &s, None, 0, |w| w.accept_credit(k)); "accept".into() }
            9 | 10 => { let Some(c) = &info else { return "skip".into() }; let s = c.seller.clone(); let k = c.id; cx.run("deliver", &s, None, 0, |w| w.mark_delivered(k, "ab".repeat(32))); "deliver".into() }
            11 => {
                let Some(c) = &info else { return "skip".into() }; let k = c.id; let cc = c.cell.0;
                let akey = cx.cells.iter().find(|x| x.id == cc).unwrap().pk.clone();
                let owes = cx.peek(|w| w.owes_guarantor(c.root.0));
                let v = cx.run("settle", &writ_, Some(&akey), 0, |w| { let _ = w.settle(k); });
                if v.is_some() && owes { cx.hit("AGENT_SETTLE_WHILE_FROZEN"); }
                "settle".into()
            }
            12 => {
                let Some(c) = &info else { return "skip".into() }; let k = c.id;
                let d = match cx.r(3) { 0 => 0, 1 => c.amount.0, _ => c.amount.0 + 7 };
                cx.run("settle_by_funder", &funder, None, d, |w| w.settle_by_funder(k)); "settle_by_funder".into()
            }
            13 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let d = if cx.r(2) == 0 { c.amount.0 } else { c.amount.0 + 3 }; cx.run("dispute", &funder, None, d, |w| w.dispute(k, "cd".repeat(32))); "dispute".into() }
            14 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let b = cx.r(2) == 0; cx.run("resolve", &arb, None, 0, |w| w.resolve_dispute(k, b)); "resolve".into() }
            15 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; cx.run("resolve_timeout", &g, None, 0, |w| w.resolve_timeout(k)); "resolve_timeout".into() }
            16 | 17 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let who = if cx.r(4) == 0 { g.clone() } else { c.seller.clone() }; cx.run("claim_default", &who, None, 0, |w| w.claim_default(k)); "claim_default".into() }
            18 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let d = match cx.r(3) { 0 => 0, 1 => c.debt.0, _ => c.debt.0 + 5 }; cx.run("reimburse", &funder, None, d, |w| w.reimburse(k)); "reimburse".into() }
            19 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; cx.run("enforce", &g, None, 0, |w| w.enforce_recourse(k)); "enforce".into() }
            20 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let who = [funder.clone(), g.clone(), c.seller.clone()][cx.r(3) as usize].clone(); cx.run("cancel", &who, None, 0, |w| w.cancel_open(k)); "cancel".into() }
            21 => { let who = [acc("s1.near"), acc("s2.near"), funder.clone(), g.clone()][cx.r(4) as usize].clone(); cx.run("withdraw", &who, None, 0, |w| { let _ = w.withdraw(); }); "withdraw".into() }
            22 => {
                match cx.r(9) {
                    0 => { cx.run("revoke", &funder, None, 0, |w| w.revoke(U64(cid), "manual".into())); "revoke".to_string() }
                    1 => { cx.run("claim_refund", &funder, None, 0, |w| w.claim_refund(U64(cid))); "claim_refund".to_string() }
                    2 => { let d = UNIT; cx.run("top_up", &funder, None, d, |w| w.top_up(U64(cid))); "top_up".to_string() }
                    3 => { let d = DEFAULT_ALLOWANCE.as_yoctonear(); cx.run("reinstate", &funder, None, d, |w| w.reinstate(U64(cid))); "reinstate".to_string() }
                    4 => { let a = UNIT; cx.run("stake", &g, None, a, |w| w.stake()); "stake".to_string() }
                    5 | 6 | 7 => { if cx.r(2) == 0 { cx.run("req_unstake", &g, None, 0, |w| w.request_unstake()); } else { let a = UNIT; cx.run("withdraw_stake", &g, None, 0, |w| { let _ = w.withdraw_stake(U128(a)); }); } "unstake".to_string() }
                    _ => { let fail = cx.r(4) == 0; cx.resolve(fail); "cb".to_string() }
                }
            }
            23 | 24 => { let fail = cx.r(4) == 0; cx.resolve(fail); "cb".into() }
            _ => { let dt = cx.r(150) + 1; cx.now += dt * NS; "time".into() }
        };
        let _ = rootid;
        // 性質：欠保證人時，這棵樹的金庫只能因為償債／違約賠付而減少
        let rs = cx.roots.clone();
        for r in rs {
            if owes_before.get(&r).copied().unwrap_or(0) > 0 {
                let after = tree_vault(cx, r);
                let before = tv_before[&r];
                if after < before && !["claim_default", "reimburse", "enforce"].contains(&opname.as_str()) {
                    cx.hit(&format!("VAULT_LEFT_WHILE_FROZEN:{}", opname));
                }
            }
        }
        opname
    }

    fn env_hash(n: u64) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v[..8].copy_from_slice(&n.to_le_bytes());
        v
    }

    /// 收尾：所有單都能走到終點、所有錢都領得走
    fn drain(cx: &mut Cx, seed: u64) {
        while !cx.pending.is_empty() { cx.resolve(false); }
        let roots = cx.roots.clone();
        cx.now += 100_000 * NS;
        for k in cx.credits.clone() {
            let c = cx.peek(|w| w.credits.get(&k).cloned().unwrap());
            match c.status {
                CreditStatus::Open | CreditStatus::Accepted => { cx.run("cancel", &acc("x.near"), None, 0, |w| w.cancel_open(U64(k))).unwrap_or_else(|| panic!("stuck cancel seed {}", seed)); }
                CreditStatus::Delivered => { cx.run("claim_default", &c.seller.clone(), None, 0, |w| w.claim_default(U64(k))).unwrap_or_else(|| panic!("stuck claim seed {}", seed)); }
                CreditStatus::Disputed => { cx.run("resolve_timeout", &acc("x.near"), None, 0, |w| w.resolve_timeout(U64(k))).unwrap_or_else(|| panic!("stuck dispute seed {}", seed)); }
                _ => {}
            }
            cx.check(seed, "drain1");
        }
        for k in cx.credits.clone() {
            let c = cx.peek(|w| w.credits.get(&k).cloned().unwrap());
            if c.debt.0 > 0 {
                let d = c.debt.0;
                cx.run("reimburse", &acc("funder.near"), None, d, |w| w.reimburse(U64(k))).unwrap_or_else(|| panic!("stuck reimburse seed {}", seed));
            }
            cx.check(seed, "drain2");
        }
        for r in roots { cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())); cx.check(seed, "drain3"); }
        while !cx.pending.is_empty() { cx.resolve(false); }
        for id in cx.cells.iter().map(|c| c.id).collect::<Vec<_>>() {
            cx.run("claim_refund", &acc("funder.near"), None, 0, |w| w.claim_refund(U64(id)));
        }
        for a in ["s1.near", "s2.near", "funder.near", "g.near"] { cx.run("withdraw", &acc(a), None, 0, |w| { let _ = w.withdraw(); }); }
        cx.run("req_unstake", &acc("g.near"), None, 0, |w| w.request_unstake());
        cx.now += 100 * NS;
        let amt = cx.peek(|w| w.stakes.get(&acc("g.near")).map(|s| s.amount.0).unwrap_or(0));
        if amt > 0 { cx.run("withdraw_stake", &acc("g.near"), None, 0, |w| { let _ = w.withdraw_stake(U128(amt)); }).unwrap_or_else(|| panic!("stuck stake seed {}", seed)); }
        while !cx.pending.is_empty() { cx.resolve(false); }
        cx.check(seed, "drain4");
        let vt = cx.peek(|w| w.vault_total);
        assert_eq!(vt, 0, "money stuck after drain, seed {}", seed);
    }


    /// 定向 PoC：欠保證人時，子格 agent 用 settle 把子格金庫付給友好賣方
    #[test]
    fn invariants() {
        std::panic::set_hook(Box::new(|i| {
            let s = i.to_string();
            if s.contains("INVARIANT") || s.contains("stuck") || s.contains("must not panic") { eprintln!("{}", s); }
        }));
        let seeds: u64 = std::env::var("SEEDS").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
        let steps: u64 = std::env::var("STEPS").ok().and_then(|s| s.parse().ok()).unwrap_or(200);
        let th: u64 = std::env::var("THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
        let mut hs = vec![];
        for t in 0..th {
            hs.push(std::thread::Builder::new().stack_size(16 << 20).spawn(move || {
                let (mut ok, mut fail, mut hits): (BTreeMap<String, u64>, BTreeMap<String, u64>, BTreeMap<String, u64>) = Default::default();
                let mut failures = 0u64;
                let (mut seen_enf, mut seen_debt) = (0u64, 0u64);
                let mut seed = t + 1;
                while seed <= seeds {
                    let r = catch_unwind(AssertUnwindSafe(|| {
                        let mut cx = new_world(seed);
                        for _ in 0..steps {
                            let op = step(&mut cx, seed);
                            cx.check(seed, &op);
                        }
                        let ids = cx.credits.clone();
                        let (e, d) = cx.peek(|w| (ids.iter().filter(|k| w.credits.get(k).unwrap().status == CreditStatus::Enforced).count() as u64, ids.iter().filter(|k| w.credits.get(k).unwrap().debt.0 > 0).count() as u64));
                        drain(&mut cx, seed);
                        (cx, e, d)
                    }));
                    match r {
                        Ok((cx, e, d)) => {
                            seen_enf += e; seen_debt += d;
                            for (k, v) in cx.ok { *ok.entry(k).or_default() += v; }
                            for (k, v) in cx.fail { *fail.entry(k).or_default() += v; }
                            for (k, v) in cx.hits { *hits.entry(k).or_default() += v; }
                        }
                        Err(_) => { failures += 1; }
                    }
                    seed += th;
                }
                (ok, fail, hits, failures, seen_enf, seen_debt)
            }).unwrap());
        }
        let (mut ok, mut fail, mut hits): (BTreeMap<String, u64>, BTreeMap<String, u64>, BTreeMap<String, u64>) = Default::default();
        let (mut failures, mut e, mut d) = (0, 0, 0);
        for h in hs {
            let (a, b, c, f, x, y) = h.join().unwrap();
            for (k, v) in a { *ok.entry(k).or_default() += v; }
            for (k, v) in b { *fail.entry(k).or_default() += v; }
            for (k, v) in c { *hits.entry(k).or_default() += v; }
            failures += f; e += x; d += y;
        }
        println!("OK   {:?}", ok);
        println!("PANIC{:?}", fail);
        println!("HITS {:?}", hits);
        println!("END-STATE enforced={} debt={} FAILURES {}", e, d, failures);
        assert_eq!(failures, 0);
    }

    include!("exact.rs");
}
