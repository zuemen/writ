// Random-sequence invariant test: random calls plus random callback failures, ledger checked at every step. SEEDS and STEPS are adjustable.
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
        last_err: String,
        token: Option<AccountId>, // None = NEAR world; Some = token world, vault, stake and seller funds are all this token
        tbal: u128,               // the contract's token balance (model)
        tsur: u128,
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
                                    // The 1 yocto attached to ft_transfer is a small amount the contract pays itself; the model does not track it
                                    if m == "ft_transfer" {
                                        let v: Value = serde_json::from_slice(args).unwrap();
                                        self.tbal -= v["amount"].as_str().unwrap().parse::<u128>().unwrap();
                                    }
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
                Err(e) => {
                    self.last_err = e.downcast_ref::<String>().cloned().or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                    *self.fail.entry(name.to_string()).or_default() += 1;
                    None
                }
            }
        }
        fn resolve(&mut self, fail: bool) {
            let Some(cb) = self.pending.pop_front() else { return };
            let amt: u128 = cb.args["amount"].as_str().unwrap().parse().unwrap();
            // Transfer failed, money did not leave the contract: check which asset this one is
            let in_token = match cb.method.as_str() {
                "on_withdraw" => !cb.args["asset"].is_null(),
                _ => { let id: u64 = cb.args["cell"].as_str().unwrap().parse().unwrap(); self.peek(|w| w.cells.get(&id).unwrap().asset.is_some()) }
            };
            if fail { if in_token { self.tbal += amt; } else { self.bal += amt; } }
            let r: Result<(), PromiseError> = if fail { Err(PromiseError::Failed) } else { Ok(()) };
            let a = cb.args.clone();
            match cb.method.as_str() {
                "on_transfer" => {
                    self.run("cb_on_transfer", &writ(), None, 0, |w| {
                        let _ = w.on_transfer(U64(a["cell"].as_str().unwrap().parse().unwrap()), U128(amt), a["invoice_hash"].as_str().unwrap().to_string(), a["to"].as_str().unwrap().parse().unwrap(), a["idx"].as_u64().unwrap() as u32, a["remaining"].as_u64().unwrap() as u32, r);
                    }).expect("on_transfer must not panic");
                }
                "on_refund" => { self.run("cb_on_refund", &writ(), None, 0, |w| w.on_refund(U64(a["cell"].as_str().unwrap().parse().unwrap()), U128(amt), r)).expect("on_refund must not panic"); }
                "on_withdraw" => { self.run("cb_on_withdraw", &writ(), None, 0, |w| w.on_withdraw(a["who"].as_str().unwrap().parse().unwrap(), U128(amt), a["asset"].as_str().map(|s| s.parse().unwrap()), r)).expect("on_withdraw must not panic"); }
                m => panic!("unknown cb {}", m),
            }
        }
        fn hit(&mut self, s: &str) { *self.hits.entry(s.to_string()).or_default() += 1; }

        /// Payment in the token world: the token contract calls ft_on_transfer. panic = ft_resolve_transfer refunds everything, balance unchanged.
        fn ft(&mut self, name: &str, sender: &AccountId, amount: u128, msg: String) -> bool {
            let token = self.token.clone().unwrap();
            let s = sender.clone();
            match self.run(name, &token, None, 0, |w| w.ft_on_transfer(s, U128(amount), msg)) {
                Some(back) => { self.tbal += amount - back.0; true }
                None => false,
            }
        }

        fn check(&mut self, seed: u64, op: &str) {
            let cells: Vec<u64> = self.cells.iter().map(|c| c.id).collect();
            let roots = self.roots.clone();
            let credits = self.credits.clone();
            let bal = self.bal;
            let asset = self.token.clone();
            let tbal = self.tbal;
            let errs: Vec<String> = self.peek(|w| {
                let mut e = vec![];
                let mut sum = 0u128;
                let mut near_sum = 0u128;
                for id in &cells { let c = w.cells.get(id).unwrap(); sum += c.vault.0 + c.unclaimed.0; }
                let g = acc("g.near");
                let st = w.stake_get(&g, &asset);
                sum += st.amount.0;
                for a in ["s1.near", "s2.near", "funder.near", "g.near", "arb.near"] {
                    sum += w.claimable.get(&(acc(a), asset.clone())).copied().unwrap_or(0);
                    if asset.is_some() { near_sum += w.claimable.get(&(acc(a), None)).copied().unwrap_or(0); }
                }
                for id in &cells { near_sum += w.cells.get(id).unwrap().near_reserve.0; }
                if asset.is_none() && near_sum != 0 { e.push(format!("NEAR tree holds a reserve {}", near_sum)); }
                let mut exp = 0u128;
                for r in &roots {
                    let Some(t) = w.terms.get(r) else { continue };
                    let (mut o, mut b, mut d) = (0u128, 0u128, 0u32);
                    for k in &credits {
                        let c = w.credits.get(k).unwrap();
                        if c.root.0 != *r { continue; }
                        if matches!(c.status, CreditStatus::Open | CreditStatus::Accepted | CreditStatus::Delivered | CreditStatus::Disputed) {
                            o += c.amount.0; b += c.bond_locked.0; exp += c.exposure.0;
                            // After acceptance the bond always equals the ratio the terms promise, exposure is the remainder
                            if c.status != CreditStatus::Open {
                                let want = c.amount.0 * t.args.bond_bps as u128 / 10_000;
                                if c.bond_locked.0 != want { e.push(format!("bond {} vs promised {}", c.bond_locked.0, want)); }
                                if c.exposure.0 != c.amount.0 - want { e.push(format!("exposure {} of order", c.exposure.0)); }
                            }
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
                // Books: paid out - recovered = what all orders still owe the guarantor; the seller list has a cap
                for k in &credits { if w.credits.get(k).unwrap().asset != asset { e.push("credit in the wrong asset".into()); } }
                let owed: u128 = credits.iter().map(|k| w.credits.get(k).unwrap().debt.0).sum();
                if st.claims_paid.0 < st.recovered.0 || st.claims_paid.0 - st.recovered.0 != owed { e.push(format!("book claims {} recovered {} owed {}", st.claims_paid.0, st.recovered.0, owed)); }
                if st.sellers.len() > MAX_BOOK_SELLERS { e.push("book sellers over the cap".into()); }
                // Each seller's exposure = the exposure of all its open orders; at zero no record is kept
                for s in ["s1.near", "s2.near"] {
                    let s = acc(s);
                    let want: u128 = credits.iter().map(|k| w.credits.get(k).unwrap()).filter(|c| c.seller == s && matches!(c.status, CreditStatus::Open | CreditStatus::Accepted | CreditStatus::Delivered | CreditStatus::Disputed)).map(|c| c.exposure.0).sum();
                    let have = w.seller_exposure_of(&g, &asset, &s);
                    if have != want { e.push(format!("seller exposure {} {} vs {}", s, have, want)); }
                    if want == 0 && w.seller_exposure.contains_key(&(g.clone(), asset.clone(), s.clone())) { e.push(format!("empty seller entry {}", s)); }
                }
                if st.amount.0 < st.exposure.0 { e.push("stake<exposure".into()); }
                for id in &cells {
                    let c = w.cells.get(id).unwrap();
                    if c.root != *id && matches!(c.status, Status::Revoked { .. }) && c.vault.0 > 0 { e.push(format!("closed child holds vault {}", id)); }
                }
                // Each asset is reconciled separately: NEAR has only reserve and withdrawable; tokens have vault, stake, deposit and withdrawable
                if let Some(t) = &asset {
                    let tt = w.token_total.get(t).copied().unwrap_or(0);
                    if sum != tt { e.push(format!("token_total {} vs buckets {}", tt, sum)); }
                    if tbal < tt { e.push(format!("token balance {} < token_total {}", tbal, tt)); }
                    if near_sum != w.vault_total { e.push(format!("vault_total {} vs NEAR buckets {}", w.vault_total, near_sum)); }
                    if let Some(x) = cells.iter().map(|id| w.cells.get(id).unwrap()).find(|c| c.asset != asset) { e.push(format!("cell {} in the wrong asset", x.amc_said)); }
                } else {
                    if sum != w.vault_total { e.push(format!("vault_total {} vs buckets {}", w.vault_total, sum)); }
                }
                if bal < w.vault_total { e.push(format!("balance {} < vault_total {}", bal, w.vault_total)); }
                std::mem::forget(e.clone());
                e
            });
            let vt = self.peek(|w| w.vault_total);
            let mut errs = errs;
            let sur = bal - vt;
            if sur < self.sur { errs.push(format!("surplus fell {} -> {}", self.sur, sur)); }
            self.sur = sur;
            if let Some(t) = self.token.clone() {
                let tt = self.peek(|w| w.token_total.get(&t).copied().unwrap_or(0));
                let tsur = tbal.saturating_sub(tt);
                if tsur < self.tsur { errs.push(format!("token surplus fell {} -> {}", self.tsur, tsur)); }
                self.tsur = tsur;
            }
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

    fn new_world(seed: u64) -> Cx { world_in(seed, None) }

    /// Token world: half of the seeds run this. NEAR reserve is random too, so the reserve-short paths are reached.
    fn world_in(seed: u64, token: Option<AccountId>) -> Cx {
        let mut cx = Cx { snap: HashMap::new(), now: 1_000_000 * NS, bal: 5_000 * 1_000_000_000_000_000_000_000_000u128, rng: seed.wrapping_mul(0x9E3779B97F4A7C15) | 1, pending: VecDeque::new(), cells: vec![], roots: vec![], credits: vec![], nextpk: 0, nextinv: 1, ok: Default::default(), fail: Default::default(), hits: Default::default(), log: vec![], sur: 0, last_err: String::new(), token: token.clone(), tbal: 0, tsur: 0 };
        cx.up(&writ(), None, 0);
        let w = Contract::new(acc("owner.near"), None, Some(Windows { accept_ttl: U64(100), inspect: U64(50), grace: U64(50), recourse: U64(100), dispute_timeout: U64(200), unstake_delay: U64(30) }));
        env::state_write(&w);
        drop(w);
        cx.snap = near_sdk::mock::with_mocked_blockchain(|b| b.take_storage());
        let vaults = [(cx.r(4) as u128 + 1) * UNIT, (cx.r(3) as u128 + 1) * UNIT, 10 * UNIT];
        let stake = (cx.r(25) as u128 + 6) * UNIT;
        let bps = [0u32, 0, 2000, 5000][cx.r(4) as usize];
        let payer = if cx.r(2) == 0 { FeePayer::Buyer } else { FeePayer::Seller };
        let cap = [0u32, 0, 3000, 8000][cx.r(4) as usize];
        let now = cx.now;
        let mut roots = vec![];
        let reserve_near: u128 = if token.is_some() { (cx.r(40) as u128 + 1) * CREDIT_STORAGE + cx.r(3) as u128 * hire_fee(1) } else { 0 };
        for i in 0..3u8 {
            let p = pk(i);
            let ch = { cx.up(&writ(), None, 0); make_chain(40, seed + i as u64) };
            let w0 = ch[0].clone();
            let v = vaults[i as usize];
            let p2 = p.clone();
            let tk = token.clone();
            let id = cx.run("init", &writ(), None, 0, |w| {
                let id = w.next_id; w.next_id += 1;
                w.cells.insert(id, Cell { amc_said: format!("E{}", id), issuer_aid: "A".into(), issuer_pk: "00".repeat(32), agent_pk: p2.clone(), verifier: acc("g.near"), funder: acc("funder.near"),
                    lei_commit: "00".repeat(32), ecr_commit: "00".repeat(32), scope: vec![acc("s1.near"), acc("s2.near")], valid_until: U64(now + 20000 * NS), unit: U128(UNIT), n: 40, idx: 0, w_cur: w0.clone(),
                    daily_links: 1000, max_links: 5, max_strikes: 8, day: now / NS_PER_DAY, day_used: 0, vault: U128(v), unclaimed: U128(0), spends: 0, rejects: 0, strikes: 0, status: Status::Active, asset: tk.clone(), root: id, parent: None, depth: 0, children: vec![], tree_size: 1, near_reserve: U128(if i < 2 { reserve_near } else { 0 }) });
                w.key_to_cell.insert(p2.clone(), id);
                w.used_keys.insert(p2.clone());
                w.add_total(&tk, v);
                if i < 2 { w.vault_total += reserve_near; }
                if tk.is_some() { w.stakes.insert((acc("g.near"), tk.clone()), Stake::default()); }
                if i < 2 {
                    w.terms.insert(id, CreditTerms { terms_ecr_commit: String::new(), args: CreditArgs { limit: U128(20 * UNIT), bond_bps: bps, premium_bps: 150, min_tenor: U64(10), max_tenor: U64(1000), terms_hash: "00".repeat(32), terms_sig: "00".repeat(64), entity_tag: format!("t{}", i), arbiter: acc("arb.near"), fee_payer: payer, seller_cap_bps: cap, asset: tk.clone() }, guarantor: acc("g.near"), outstanding: U128(0), bond_locked: U128(0), open_debts: 0 });
                }
                id
            }).unwrap();
            if token.is_some() { cx.tbal += v; }
            cx.cells.push(CellH { id, pk: p, links: ch });
            roots.push(id);
            cx.nextpk += 1;
        }
        cx.roots = roots;
        cx.run("init2", &writ(), None, 0, |w| { w.verifiers.insert(acc("g.near"), "00".repeat(32)); });
        if token.is_some() {
            assert!(cx.ft("stake", &acc("g.near"), stake, "stake".into()));
        } else {
            cx.run("stake", &acc("g.near"), None, stake, |w| w.stake());
        }
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
            7 | 8 => {
                let Some(c) = &info else { return "skip".into() }; let s = c.seller.clone(); let k = c.id;
                cx.up(&s, None, 0);
                let said = cx.peek(|w| w.check_order(k, None));
                let got = cx.run("accept", &s, None, 0, |w| w.accept_credit(k)).is_some();
                if said.ok != got || said.would_accept != got { panic!("INVARIANT check_order ok={} would_accept={} but accept={} reasons={:?}", said.ok, said.would_accept, got, said.reasons); }
                if let Some(r) = said.reasons.first() { let r = format!("ACCEPT:{}", r); cx.hit(&r); }
                "accept".into()
            }
            9 | 10 => { let Some(c) = &info else { return "skip".into() }; let s = c.seller.clone(); let k = c.id; let f = match cx.r(5) { 0 => Some(U128((c.amount.0 / 2).max(1))), 1 => Some(U128(c.amount.0 - 1)), 2 => Some(U128(c.amount.0 + 1)), _ => None }; cx.run("deliver", &s, None, 0, |w| w.mark_delivered(k, "ab".repeat(32), f)); "deliver".into() }
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
                if cx.token.is_some() && d > 0 {
                    // A token tree paying with NEAR is always rejected: 1 NEAR cannot count as a large amount of tokens
                    if cx.run("near_on_token", &funder, None, d, |w| w.settle_by_funder(k)).is_some() { panic!("INVARIANT NEAR paid a token order"); }
                    cx.ft("settle_by_funder", &funder, d, format!("settle:{}", k.0));
                } else {
                    cx.run("settle_by_funder", &funder, None, d, |w| w.settle_by_funder(k));
                }
                "settle_by_funder".into()
            }
            13 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let d = if cx.r(2) == 0 { c.amount.0 } else { c.amount.0 + 3 }; if cx.token.is_some() { cx.ft("dispute", &funder, d, format!("dispute:{}:{}", k.0, "cd".repeat(32))); } else { cx.run("dispute", &funder, None, d, |w| w.dispute(k, "cd".repeat(32))); } "dispute".into() }
            14 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let b = cx.r(2) == 0; cx.run("resolve", &arb, None, 0, |w| w.resolve_dispute(k, b)); "resolve".into() }
            15 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; cx.run("resolve_timeout", &g, None, 0, |w| w.resolve_timeout(k)); "resolve_timeout".into() }
            16 | 17 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let who = if cx.r(4) == 0 { g.clone() } else { c.seller.clone() }; cx.run("claim_default", &who, None, 0, |w| w.claim_default(k)); "claim_default".into() }
            18 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let d = match cx.r(3) { 0 => 0, 1 => c.debt.0, _ => c.debt.0 + 5 }; if cx.token.is_some() && d > 0 { cx.ft("reimburse", &funder, d, format!("reimburse:{}", k.0)); } else { cx.run("reimburse", &funder, None, d, |w| w.reimburse(k)); } "reimburse".into() }
            19 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; cx.run("enforce", &g, None, 0, |w| w.enforce_recourse(k)); "enforce".into() }
            20 => { let Some(c) = &info else { return "skip".into() }; let k = c.id; let who = [funder.clone(), g.clone(), c.seller.clone()][cx.r(3) as usize].clone(); cx.run("cancel", &who, None, 0, |w| w.cancel_open(k)); "cancel".into() }
            21 => { let who = [acc("s1.near"), acc("s2.near"), funder.clone(), g.clone()][cx.r(4) as usize].clone(); let a = if cx.r(2) == 0 { cx.token.clone() } else { None }; cx.run("withdraw", &who, None, 0, |w| { let _ = w.withdraw(a); }); "withdraw".into() }
            22 => {
                match cx.r(10) {
                    8 => {
                        // Rules are set only on s2: s1 never has a rule, so the later paths are reached
                        let s = acc("s2.near");
                        let p = if cx.r(4) == 0 { None } else { Some(SellerPolicy { max_amount: U128((cx.r(6) as u128 + 1) * UNIT), max_tenor_secs: U64(cx.r(400) + 10), min_bond_bps: [0u32, 0, 2000][cx.r(3) as usize], max_defaults: cx.r(3) as u32, guarantors: if cx.r(6) == 0 { vec![acc("other.near")] } else { vec![] }, asset: if cx.r(8) == 0 { Some(acc("fake.near")) } else { cx.token.clone() }, max_fee_bps: [100u32, 500, 10_000][cx.r(3) as usize], arbiters: if cx.r(8) == 0 { vec![acc("other.near")] } else { vec![] } }) };
                        let d = SELLER_POLICY_STORAGE + cx.r(2) as u128 * 5;
                        cx.run("set_policy", &s, None, d, |w| w.set_seller_policy(p));
                        "set_policy".to_string()
                    }
                    0 => { cx.run("revoke", &funder, None, 0, |w| w.revoke(U64(cid), "manual".into())); "revoke".to_string() }
                    1 => { cx.run("claim_refund", &funder, None, 0, |w| w.claim_refund(U64(cid))); "claim_refund".to_string() }
                    2 => { let d = UNIT; if cx.token.is_some() && cx.r(2) == 0 { cx.ft("fund", &funder, d, format!("fund:{}", cid)); } else { cx.run("top_up", &funder, None, d, |w| w.top_up(U64(cid))); } "top_up".to_string() }
                    3 => { let d = DEFAULT_ALLOWANCE.as_yoctonear(); cx.run("reinstate", &funder, None, d, |w| w.reinstate(U64(cid))); "reinstate".to_string() }
                    4 => { let a = UNIT; if cx.token.is_some() { cx.ft("stake", &g, a, "stake".into()); } else { cx.run("stake", &g, None, a, |w| w.stake()); } "stake".to_string() }
                    5 | 6 | 7 => { let t = cx.token.clone(); if cx.r(2) == 0 { cx.run("req_unstake", &g, None, 0, |w| w.request_unstake(t)); } else { let a = UNIT; cx.run("withdraw_stake", &g, None, 0, |w| { let _ = w.withdraw_stake(U128(a), t); }); } "unstake".to_string() }
                    _ => { let fail = cx.r(4) == 0; cx.resolve(fail); "cb".to_string() }
                }
            }
            23 | 24 => { let fail = cx.r(4) == 0; cx.resolve(fail); "cb".into() }
            _ => { let dt = if cx.r(4) == 0 { cx.r(150) + 1 } else { cx.r(20) + 1 }; cx.now += dt * NS; "time".into() }
        };
        let _ = rootid;
        // Property: when the guarantor is owed, this tree's vault can shrink only through repayment or default payout
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

    /// Wrap-up: every order can reach its end, all money can be withdrawn
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
                if cx.token.is_some() {
                    assert!(cx.ft("reimburse", &acc("funder.near"), d, format!("reimburse:{}", k)), "stuck reimburse seed {}", seed);
                } else {
                    cx.run("reimburse", &acc("funder.near"), None, d, |w| w.reimburse(U64(k))).unwrap_or_else(|| panic!("stuck reimburse seed {}", seed));
                }
            }
            cx.check(seed, "drain2");
        }
        for r in roots { cx.run("revoke", &acc("funder.near"), None, 0, |w| w.revoke(U64(r), "x".into())); cx.check(seed, "drain3"); }
        while !cx.pending.is_empty() { cx.resolve(false); }
        for id in cx.cells.iter().map(|c| c.id).collect::<Vec<_>>() {
            cx.run("claim_refund", &acc("funder.near"), None, 0, |w| w.claim_refund(U64(id)));
        }
        let t = cx.token.clone();
        for a in ["s1.near", "s2.near", "funder.near", "g.near"] {
            cx.run("withdraw", &acc(a), None, 0, |w| { let _ = w.withdraw(None); });
            if t.is_some() { let t2 = t.clone(); cx.run("withdraw", &acc(a), None, 0, |w| { let _ = w.withdraw(t2); }); }
        }
        let t2 = t.clone();
        cx.run("req_unstake", &acc("g.near"), None, 0, |w| w.request_unstake(t2));
        cx.now += 100 * NS;
        let t2 = t.clone();
        let amt = cx.peek(|w| w.stakes.get(&(acc("g.near"), t2)).map(|s| s.amount.0).unwrap_or(0));
        let t2 = t.clone();
        if amt > 0 { cx.run("withdraw_stake", &acc("g.near"), None, 0, |w| { let _ = w.withdraw_stake(U128(amt), t2); }).unwrap_or_else(|| panic!("stuck stake seed {}", seed)); }
        while !cx.pending.is_empty() { cx.resolve(false); }
        cx.check(seed, "drain4");
        let vt = cx.peek(|w| w.vault_total);
        assert_eq!(vt, 0, "money stuck after drain, seed {}", seed);
        if let Some(t) = &t {
            let tt = cx.peek(|w| w.token_total.get(t).copied().unwrap_or(0));
            assert_eq!(tt, 0, "token stuck after drain, seed {}", seed);
        }
    }


    /// Directed PoC: when the guarantor is owed, a child-cell agent uses settle to pay the child cell's vault to a friendly seller
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
                        let mut cx = if seed % 2 == 0 { world_in(seed, Some(acc("usdc.near"))) } else { new_world(seed) };
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
