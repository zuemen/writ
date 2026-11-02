//! Writ 攻擊台（attack bench）＋ 正常流程。全部在本機 sandbox 上跑，不碰 testnet。
//!
//! 跑法：`make -C contract test`（第一次會下載 near-sandbox，需要網路一次）
//!
//! 每個測試最後印一行 `WRIT_BENCH|<id>|<attack>|<expected>|<observed>|<attacker_gain_yocto>`，
//! README 首頁總表直接由這些行產生（scripts/bench_table.py）。

use ed25519_dalek::{Signer, SigningKey};
use near_workspaces::network::Sandbox;
use near_workspaces::types::{KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const WASM: &str = "res/writ.wasm";
const UNIT: u128 = 10_000_000_000_000_000_000_000; // 0.01 NEAR / 鏈節

// ---------------------------------------------------------------- 工具

/// PayWord 鏈：links[k] = H^(n-k)(seed)，links[0] = w0。付 j 節時交出 links[idx+j]。
struct Payword {
    links: Vec<[u8; 32]>,
}
impl Payword {
    fn new(n: u32) -> Self {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&rand::random::<u64>().to_le_bytes());
        let mut links = vec![[0u8; 32]; n as usize + 1];
        links[n as usize] = seed;
        for k in (0..n as usize).rev() {
            links[k] = Sha256::digest(links[k + 1]).into();
        }
        Self { links }
    }
    fn w0(&self) -> String {
        hex::encode(self.links[0])
    }
    fn link(&self, k: u32) -> String {
        hex::encode(self.links[k as usize])
    }
}

struct World {
    worker: Worker<Sandbox>,
    writ: Contract,
    verifier: Account,
    verifier_sk: SigningKey,
    funder: Account,
    merchant: Account,
    attacker: Account,
}

/// cargo-mutants 用：WRIT_REBUILD=1 時每次測試先從（被突變的）原始碼重建 wasm，否則用 make build 的產物。
fn wasm_bytes() -> anyhow::Result<Vec<u8>> {
    static BUILT: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    if std::env::var("WRIT_REBUILD").is_err() {
        return Ok(std::fs::read(WASM)?);
    }
    Ok(BUILT.get_or_init(|| {
        let st = std::process::Command::new("cargo")
            .args(["build", "--target", "wasm32-unknown-unknown", "--release", "--target-dir", "target/mutants-wasm"])
            .status().expect("cargo build");
        assert!(st.success(), "wasm build failed");
        std::fs::read("target/mutants-wasm/wasm32-unknown-unknown/release/writ.wasm").unwrap()
    }).clone())
}

async fn world() -> anyhow::Result<World> {
    let worker = near_workspaces::sandbox().await?;
    let writ = worker.dev_deploy(&wasm_bytes()?).await?;
    writ.call("new").args_json(json!({"unseal_delay_secs": 5})).transact().await?.into_result()?;
    let verifier = worker.dev_create_account().await?;
    let funder = worker.dev_create_account().await?;
    let merchant = worker.dev_create_account().await?;
    let attacker = worker.dev_create_account().await?;
    let verifier_sk = SigningKey::generate(&mut rand::thread_rng());
    writ.call("set_verifier")
        .args_json(json!({"account": verifier.id(), "pk_hex": hex::encode(verifier_sk.verifying_key().to_bytes())}))
        .transact().await?.into_result()?;
    Ok(World { worker, writ, verifier, verifier_sk, funder, merchant, attacker })
}

struct Opts {
    n: u32,
    daily: u32,
    valid_secs: u64,
    scope: Vec<AccountId>,
    deposit_near: u128,
    amc_said: String,
    issuer_pk: String,
    asset: Option<AccountId>,
    unit: u128,
}

/// 與合約 attestation_message 完全一致的規範字串。
fn attest_msg(a: &Value, funder: &AccountId) -> String {
    let scope: Vec<String> = a["scope"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
    format!(
        "writ:attest:v1\namc={}\nissuer_pk={}\nagent_pk={}\nw0={}\nn={}\nunit={}\nscope={}\nvalid_until={}\ndaily_links={}\nlei_commit={}\nfunder={}\nverifier={}\nasset={}",
        a["amc_said"].as_str().unwrap(), a["issuer_pk"].as_str().unwrap(), a["agent_pk"].as_str().unwrap(),
        a["w0"].as_str().unwrap(), a["n"], a["unit"].as_str().unwrap(), scope.join(","),
        a["valid_until"].as_str().unwrap(), a["daily_links"], a["lei_commit"].as_str().unwrap(), funder,
        a["verifier"].as_str().unwrap(),
        a.get("asset").and_then(|v| v.as_str()).unwrap_or("near")
    )
}

async fn now_ns(w: &World) -> anyhow::Result<u64> {
    Ok(w.worker.view_block().await?.timestamp())
}

/// 開一格：回傳 (cell id, agent 以合約帳號身分的 Account, PayWord 鏈)
async fn open_cell(w: &World, o: Opts) -> anyhow::Result<(u64, Account, Payword)> {
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let lei_commit = hex::encode(Sha256::digest(b"5493001KJTIIGC8Y1R12|salt-demo"));
    let valid_until = now_ns(w).await? + o.valid_secs * 1_000_000_000;
    let mut args = json!({
        "amc_said": o.amc_said, "issuer_pk": o.issuer_pk, "agent_pk": agent_sk.public_key(),
        "w0": pw.w0(), "n": o.n, "unit": o.unit.to_string(), "scope": o.scope,
        "valid_until": valid_until.to_string(), "daily_links": o.daily, "lei_commit": lei_commit,
        "verifier": w.verifier.id(),
    });
    if let Some(t) = &o.asset { args["asset"] = json!(t); }
    let sig = w.verifier_sk.sign(attest_msg(&args, w.funder.id()).as_bytes());
    args["signature"] = json!(hex::encode(sig.to_bytes()));
    let out = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args}))
        .deposit(NearToken::from_near(o.deposit_near)).max_gas().transact().await?;
    let id: String = out.clone().into_result()?.json()?;
    let agent = Account::from_secret_key(w.writ.id().clone(), agent_sk, &w.worker);
    Ok((id.parse()?, agent, pw))
}

fn default_opts(w: &World) -> Opts {
    Opts {
        n: 20, daily: 10, valid_secs: 3600,
        scope: vec![w.merchant.id().clone()],
        deposit_near: 1,
        amc_said: "EAMC_test_said_000000000000000000000000000000".into(),
        issuer_pk: hex::encode([7u8; 32]),
        asset: None,
        unit: UNIT,
    }
}

async fn spend(agent: &Account, writ: &AccountId, preimage: &str, j: u32, to: &AccountId) -> Result<Value, String> {
    match agent.call(writ, "spend").args_json(json!({"preimage": preimage, "j": j, "to": to})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await {
        Ok(out) => match out.clone().into_result() {
            Ok(v) => Ok(v.json::<Value>().unwrap()),
            Err(e) => Err(format!("EXEC:{:?}", e)),
        },
        Err(e) => Err(format!("{:?}", e)),
    }
}

async fn balance(a: &Account) -> u128 {
    a.view_account().await.unwrap().balance.as_yoctonear()
}

fn bench(id: &str, attack: &str, expected: &str, observed: &str, gain: i128) {
    println!("WRIT_BENCH|{}|{}|{}|{}|{}", id, attack, expected, observed, gain);
}

fn proto_tag(e: &str) -> &'static str {
    if e.contains("AccessKeyNotFound") { "AccessKeyNotFound" }
    else if e.contains("MethodNameMismatch") { "MethodNameMismatch" }
    else if e.contains("DepositWithFunctionCall") { "DepositWithFunctionCall" }
    else if e.contains("RequiresFullAccess") { "RequiresFullAccess" }
    else if e.contains("NotEnoughAllowance") { "NotEnoughAllowance" }
    else { "OTHER" }
}

// ---------------------------------------------------------------- 正常流程

#[tokio::test]
async fn b00_happy_path_pays_merchant_and_present_hides_lei() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw) = open_cell(&w, default_opts(&w)).await?;
    let before = balance(&w.merchant).await;
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert_eq!(v["Paid"]["idx"], 3);
    let after = balance(&w.merchant).await;
    assert_eq!(after - before, 3 * UNIT, "merchant receives exactly 3 links");
    // 第二筆接續鏈頭
    let v = spend(&agent, w.writ.id(), &pw.link(5), 2, w.merchant.id()).await.unwrap();
    assert_eq!(v["Paid"]["remaining_links"], 15);
    let p: Value = w.writ.view("present").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    println!("present = {}", p);
    assert_eq!(p["lei"], "sealed");
    assert_eq!(p["within_limit"]["used"], 5);
    assert!(!p.to_string().contains("5493001KJTIIGC8Y1R12"), "LEI never appears on chain");
    let by_key: Value = w.writ.view("cell_of").args_json(json!({"agent_pk": agent.secret_key().public_key()})).await?.json()?;
    assert_eq!(by_key, json!(cell.to_string()), "cell_of maps the agent key to its cell");
    let vs: Value = w.writ.view("verifiers").await?.json()?;
    assert_eq!(vs[0][0], json!(w.verifier.id()));
    bench("B00", "legit payment 3+2 links to in-scope merchant", "Paid", "Paid", 0);
    Ok(())
}

// ---------------------------------------------------------------- 政策層攻擊（合約回 Rejected，有 tx hash）

#[tokio::test]
async fn a01_prompt_injected_payment_to_attacker_is_rejected() -> anyhow::Result<()> {
    let w = world().await?;
    let (_c, agent, pw) = open_cell(&w, default_opts(&w)).await?;
    let before = balance(&w.attacker).await;
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.attacker.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "SCOPE");
    let gain = balance(&w.attacker).await as i128 - before as i128;
    assert_eq!(gain, 0);
    bench("A01", "prompt-injected agent pays attacker (out of scope)", "Rejected:SCOPE", "Rejected:SCOPE", gain);
    Ok(())
}

#[tokio::test]
async fn a02_over_limit_and_forged_and_replayed_links() -> anyhow::Result<()> {
    let w = world().await?;
    let mut o = default_opts(&w);
    o.n = 5;
    o.daily = 5;
    let (_c, agent, pw) = open_cell(&w, o).await?;
    // 超過鏈長
    let v = spend(&agent, w.writ.id(), &pw.link(5), 6, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "LIMIT");
    bench("A02", "spend more links than the mandate holds", "Rejected:LIMIT", "Rejected:LIMIT", 0);
    // 偽造鏈節（agent 自己編一個 preimage）
    let v = spend(&agent, w.writ.id(), &"ab".repeat(32), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A03", "forged hash-chain link (agent invents budget)", "Rejected:CHAIN", "Rejected:CHAIN", 0);
    // 合法一筆後重放同一個鏈節
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some());
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A04", "replay an already-spent link", "Rejected:CHAIN", "Rejected:CHAIN", 0);
    Ok(())
}

#[tokio::test]
async fn a05_daily_rate_limit() -> anyhow::Result<()> {
    let w = world().await?;
    let mut o = default_opts(&w);
    o.daily = 4;
    let (_c, agent, pw) = open_cell(&w, o).await?;
    assert!(spend(&agent, w.writ.id(), &pw.link(4), 4, w.merchant.id()).await.unwrap().get("Paid").is_some());
    // 人已撥出更多鏈節，但今日速率用完
    let v = spend(&agent, w.writ.id(), &pw.link(5), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "RATE");
    bench("A05", "drain faster than the daily rate (valid links)", "Rejected:RATE", "Rejected:RATE", 0);
    Ok(())
}

#[tokio::test]
async fn a06_expired_mandate() -> anyhow::Result<()> {
    let w = world().await?;
    let mut o = default_opts(&w);
    o.valid_secs = 5;
    let (_c, agent, pw) = open_cell(&w, o).await?;
    w.worker.fast_forward(200).await?;
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "EXPIRED");
    bench("A06", "spend after the AMC validity window", "Rejected:EXPIRED", "Rejected:EXPIRED", 0);
    Ok(())
}

#[tokio::test]
async fn a07_tripwire_deletes_key_after_three_strikes() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw) = open_cell(&w, default_opts(&w)).await?;
    for k in 1..=3 {
        let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.attacker.id()).await.unwrap();
        assert_eq!(v["Rejected"]["strikes"], k);
        assert_eq!(v["Rejected"]["tripped"], k == 3);
    }
    let e = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&e), "AccessKeyNotFound");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["status"], "Tripped");
    let st: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(st["tripped"], 1);
    assert_eq!(st["rejected"], 3);
    bench("A07", "injected agent keeps trying (3 strikes)", "key deleted, next call AccessKeyNotFound", proto_tag(&e), 0);
    Ok(())
}

// ---------------------------------------------------------------- 協定層攻擊（RPC 直接拒絕，沒有 tx hash）

#[tokio::test]
async fn a08_agent_key_cannot_escape_its_method() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    let before = balance(&w.attacker).await;

    // 呼叫 revoke／refresh_key／top_up 以外的寫入方法
    let e = agent.call(w.writ.id(), "set_verifier").args_json(json!({"account": agent.id(), "pk_hex": "00"})).transact().await.unwrap_err();
    assert_eq!(proto_tag(&format!("{:?}", e)), "MethodNameMismatch");
    bench("A08", "agent key calls admin method set_verifier", "MethodNameMismatch", "MethodNameMismatch", 0);

    // 附帶存款（標準 ft_transfer 需要 1 yocto）
    let e = agent.call(w.writ.id(), "spend").args_json(json!({"preimage": "00", "j": 1, "to": w.attacker.id()}))
        .deposit(NearToken::from_yoctonear(1)).transact().await.unwrap_err();
    assert_eq!(proto_tag(&format!("{:?}", e)), "DepositWithFunctionCall");
    bench("A09", "agent attaches deposit (e.g. ft_transfer 1 yocto)", "DepositWithFunctionCall", "DepositWithFunctionCall", 0);

    // 直接把合約帳號的 NEAR 轉走
    let e = agent.transfer_near(w.attacker.id(), NearToken::from_millinear(1)).await;
    let s = format!("{:?}", e);
    assert!(s.contains("RequiresFullAccess"), "plain transfer must be impossible: {}", s);
    bench("A10", "agent sends a plain Transfer from the contract account", "RequiresFullAccess", proto_tag(&s), 0);

    // 用 agent 的鑰匙呼叫別的合約
    let e = agent.call(w.attacker.id(), "anything").transact().await.unwrap_err();
    let s = format!("{:?}", e);
    assert!(s.contains("ReceiverMismatch") || s.contains("MethodNameMismatch") || s.contains("CodeDoesNotExist"), "{}", s);
    bench("A11", "agent key used against another contract", "ReceiverMismatch", if s.contains("ReceiverMismatch") { "ReceiverMismatch" } else { "OTHER" }, 0);

    let gain = balance(&w.attacker).await as i128 - before as i128;
    assert_eq!(gain, 0);
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["status"], "Active", "protocol-layer rejections leave no on-chain trace");
    Ok(())
}

// ---------------------------------------------------------------- 憑證層

#[tokio::test]
async fn a12_forged_or_tampered_attestation_is_refused() -> anyhow::Result<()> {
    let w = world().await?;
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(10);
    let vu = now_ns(&w).await? + 3_600_000_000_000;
    let mut args = json!({
        "amc_said": "EX", "issuer_pk": hex::encode([1u8;32]), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": 10,
        "unit": UNIT.to_string(), "scope": [w.merchant.id()], "valid_until": vu.to_string(), "daily_links": 10,
        "lei_commit": hex::encode([2u8;32]), "verifier": w.verifier.id(),
    });
    // (a) 非白名單的人自己簽
    let rogue = SigningKey::generate(&mut rand::thread_rng());
    args["signature"] = json!(hex::encode(rogue.sign(attest_msg(&args, w.funder.id()).as_bytes()).to_bytes()));
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args.clone()})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A12", "self-signed attestation (not a whitelisted verifier)", "BAD_ATTESTATION", "BAD_ATTESTATION", 0);
    // (b) 驗證者簽了，但出資者把 scope 改成攻擊者
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id()).as_bytes()).to_bytes()));
    args["scope"] = json!([w.attacker.id()]);
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args.clone()})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A13", "funder widens the scope after the verifier signed", "BAD_ATTESTATION", "BAD_ATTESTATION", 0);
    // (c) 另一個帳號拿走別人的 attestation 來開格（funder 綁在簽章裡）
    args["scope"] = json!([w.merchant.id()]);
    let r = w.attacker.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A14", "attacker replays someone else's attestation", "BAD_ATTESTATION", "BAD_ATTESTATION", 0);
    Ok(())
}

#[tokio::test]
async fn a15_revoke_by_kel_real_keri_event_is_permissionless() -> anyhow::Result<()> {
    let w = world().await?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string("tests/fixtures/vectors.json")?)?;
    let mut o = default_opts(&w);
    o.amc_said = v["amc"]["said"].as_str().unwrap().into();
    o.issuer_pk = v["issuer"]["pk_hex"].as_str().unwrap().into();
    let (cell, agent, pw) = open_cell(&w, o).await?;
    assert!(spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap().get("Paid").is_some());

    let b64 = |h: &str| near_sdk::base64::Engine::encode(&near_sdk::base64::prelude::BASE64_STANDARD, hex::decode(h).unwrap());
    let ixn = v["ixn"]["raw_hex"].as_str().unwrap();
    let sig = v["ixn"]["sig_hex"].as_str().unwrap();

    // 竄改 ixn 一個 byte → 簽章不過
    let mut bad = hex::decode(ixn)?;
    let last = bad.len() - 3;
    bad[last] ^= 1;
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(&hex::encode(bad)), "signature": b64(sig)})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"));
    bench("A15", "forged KERI revocation event", "BAD_KEL_SIGNATURE", "BAD_KEL_SIGNATURE", 0);

    // 真簽章、真 ixn，但它錨定的是 AMC 的「發行」（seal s="0"），不是撤銷
    let iss = &v["iss_ixn"];
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(iss["raw_hex"].as_str().unwrap()), "signature": b64(iss["sig_hex"].as_str().unwrap())}))
        .max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NO_REVOCATION_SEAL"));
    bench("A24", "genuine signed KERI event that anchors the AMC issuance, not a revocation", "NO_REVOCATION_SEAL", "NO_REVOCATION_SEAL", 0);

    // 真的 ixn：任何人（這裡用 attacker 帳號）都能提交，不需要信任 watcher
    let funder_before = balance(&w.funder).await;
    let out = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(ixn), "signature": b64(sig)})).max_gas().transact().await?;
    println!("revoke_by_kel tx {} logs {:?}", out.outcome().transaction_hash, out.logs());
    out.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["status"]["Revoked"]["evidence"], v["ixn"]["seal"]["d"]);
    assert!(balance(&w.funder).await > funder_before, "remaining vault refunded to the legal entity");
    let e = spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&e), "AccessKeyNotFound");
    bench("B01", "AMC revoked in KERI TEL, ixn submitted by anyone", "key deleted, next call AccessKeyNotFound", proto_tag(&e), 0);
    Ok(())
}

#[tokio::test]
async fn a16_failed_transfer_refunds_vault_and_others_cannot_revoke() -> anyhow::Result<()> {
    let w = world().await?;
    let ghost: AccountId = format!("ghost.{}", w.worker.root_account()?.id()).parse()?;
    let mut o = default_opts(&w);
    o.scope = vec![w.merchant.id().clone(), ghost.clone()];
    let (cell, agent, pw) = open_cell(&w, o).await?;
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, &ghost).await.unwrap();
    assert!(v.get("Paid").is_some());
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    let vault: u128 = c["vault"].as_str().unwrap().parse()?;
    assert_eq!(vault, 1_000_000_000_000_000_000_000_000 - 100_000_000_000_000_000_000_000, "transfer to non-existent account refunded");
    bench("B02", "payment to a non-existent account", "vault refunded by callback", "refunded", 0);

    let r = w.attacker.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "x"})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_AUTHORIZED"));
    bench("A16", "stranger tries to revoke (griefing)", "NOT_AUTHORIZED", "NOT_AUTHORIZED", 0);

    // 法人自己撤銷
    w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "manual"})).transact().await?.into_result()?;
    let e = spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&e), "AccessKeyNotFound");
    let s: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(s["revoked"], 1);
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["vault_total"], "0", "closing a cell releases its vault from the total");
    Ok(())
}

// ---------------------------------------------------------------- 監理調閱（tier-1）

#[tokio::test]
async fn a17_unseal_needs_supervisor_waiting_period_and_matching_commitment() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, _agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    let supervisor = w.worker.dev_create_account().await?;
    let reason = hex::encode(Sha256::digest(b"court order 2026-TPE-001"));

    // 非監理方不能提出調閱
    let r = w.attacker.call(w.writ.id(), "request_unseal").args_json(json!({"cell": cell.to_string(), "reason_hash": reason})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_SUPERVISOR"));
    bench("A17", "non-supervisor requests disclosure of the legal entity", "NOT_SUPERVISOR", "NOT_SUPERVISOR", 0);

    w.writ.call("set_supervisor").args_json(json!({"account": supervisor.id(), "enabled": true})).transact().await?.into_result()?;
    supervisor.call(w.writ.id(), "request_unseal").args_json(json!({"cell": cell.to_string(), "reason_hash": reason})).transact().await?.into_result()?;

    // 等待期內不能揭露
    let release = |lei: &str, salt: &str| {
        let (lei, salt) = (lei.to_string(), salt.to_string());
        let v = w.verifier.clone(); let id = w.writ.id().clone(); let c = cell.to_string();
        async move { v.call(&id, "release_unseal").args_json(json!({"cell": c, "lei": lei, "salt": salt})).transact().await.unwrap().into_result() }
    };
    let e = format!("{:?}", release("5493001KJTIIGC8Y1R12", "salt-demo").await);
    assert!(e.contains("TOO_EARLY"), "{}", e);
    bench("A18", "verifier discloses before the public waiting period ends", "TOO_EARLY", "TOO_EARLY", 0);

    // 法人提出異議（公開留痕，不阻擋）
    w.funder.call(w.writ.id(), "object_unseal").args_json(json!({"cell": cell.to_string()})).transact().await?.into_result()?;
    w.worker.fast_forward(200).await?;

    // 驗證者想揭露一個不同的 LEI（栽贓給別家公司）
    let e = format!("{:?}", release("529900T8BM49AURSDO55", "salt-demo").await);
    assert!(e.contains("COMMIT_MISMATCH"), "{}", e);
    bench("A19", "verifier discloses a different LEI than it committed to", "COMMIT_MISMATCH", "COMMIT_MISMATCH", 0);

    let out = release("5493001KJTIIGC8Y1R12", "salt-demo").await?;
    println!("unsealed logs: {:?}", out.logs());
    let p: Value = w.writ.view("present").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(p["lei"], "5493001KJTIIGC8Y1R12");
    let u: Value = w.writ.view("get_unseal").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(u["objected"], true);
    bench("B03", "supervisor request → wait → verifier discloses committed LEI (public tx)", "LEI disclosed, objection on record", "disclosed", 0);
    Ok(())
}

// ---------------------------------------------------------------- NEP-141 穩定幣路徑

const FT_WASM: &str = "res/ft_mock.wasm";
const T: u128 = 1_000_000; // tUSDC 6 位小數

async fn ft_balance(w: &World, token: &Contract, who: &AccountId) -> u128 {
    let v: String = token.view("ft_balance_of").args_json(json!({"account_id": who})).await.unwrap().json().unwrap();
    v.parse().unwrap()
}

#[tokio::test]
async fn b04_stablecoin_cell_pays_in_nep141_and_refunds_on_revoke() -> anyhow::Result<()> {
    let w = world().await?;
    let token = w.worker.dev_deploy(&std::fs::read(FT_WASM)?).await?;
    token.call("new").args_json(json!({"owner_id": w.funder.id(), "total_supply": (1_000 * T).to_string()})).transact().await?.into_result()?;
    for who in [w.writ.id(), w.merchant.id(), w.attacker.id()] {
        w.funder.call(token.id(), "storage_deposit").args_json(json!({"account_id": who})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    }
    let mut o = default_opts(&w);
    o.asset = Some(token.id().clone());
    o.unit = T / 10; // 每節 0.1 tUSDC
    let (cell, agent, pw) = open_cell(&w, o).await?;
    // 法人以 ft_transfer_call 入金 5 tUSDC，msg = cell id
    w.funder.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": (5 * T).to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], (5 * T).to_string());

    // 付 3 節給商家
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "{}", v);
    assert_eq!(ft_balance(&w, &token, w.merchant.id()).await, 3 * T / 10);
    bench("B04", "stablecoin cell: agent pays 3 links in NEP-141 (contract attaches the 1 yocto)", "merchant +0.3 tUSDC", "merchant +0.3 tUSDC", 0);

    // 注入攻擊同樣擋下
    let v = spend(&agent, w.writ.id(), &pw.link(4), 1, w.attacker.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "SCOPE");
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, 0);
    bench("A20", "prompt-injected payment from a stablecoin cell", "Rejected:SCOPE", "Rejected:SCOPE", 0);

    // 攻擊者持有同一種代幣，硬塞進這格（想污染帳）→ 退回
    w.funder.call(token.id(), "ft_transfer").args_json(json!({"receiver_id": w.attacker.id(), "amount": T.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).transact().await?.into_result()?;
    w.attacker.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": T.to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, T, "same token from a non-funder is refunded");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], (5 * T - 3 * T / 10).to_string());
    bench("A25", "non-funder pushes the cell's own stablecoin into it", "refunded, vault unchanged", "refunded", 0);

    // 法人撤銷 → 剩餘代幣退回法人
    let before = ft_balance(&w, &token, w.funder.id()).await;
    w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "manual"})).max_gas().transact().await?.into_result()?;
    let after = ft_balance(&w, &token, w.funder.id()).await;
    assert_eq!(after - before, 5 * T - 3 * T / 10, "remaining 4.7 tUSDC refunded");
    // 撤銷後法人再入金 → 退回（格已關閉）
    w.funder.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": T.to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.funder.id()).await, after, "deposit into a closed cell is refunded");
    Ok(())
}

#[tokio::test]
async fn a21_token_cell_refuses_foreign_deposits_and_asset_swap() -> anyhow::Result<()> {
    let w = world().await?;
    let token = w.worker.dev_deploy(&std::fs::read(FT_WASM)?).await?;
    token.call("new").args_json(json!({"owner_id": w.attacker.id(), "total_supply": (1_000 * T).to_string()})).transact().await?.into_result()?;
    w.attacker.call(token.id(), "storage_deposit").args_json(json!({"account_id": w.writ.id()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    // 開一個 NEAR 格；攻擊者把垃圾代幣灌進去，想讓格的金庫帳變亂
    let (cell, _agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    w.attacker.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": (7 * T).to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, 1_000 * T, "foreign token refunded in full");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], "900000000000000000000000");
    bench("A21", "foreign token pushed into a cell via ft_transfer_call", "refunded, vault unchanged", "refunded", 0);

    // 驗證者簽的是 NEAR 格，法人想改成代幣格
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(5);
    let vu = now_ns(&w).await? + 3_600_000_000_000;
    let mut args = json!({"amc_said": "EY", "issuer_pk": hex::encode([1u8;32]), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": 5,
        "unit": UNIT.to_string(), "scope": [w.merchant.id()], "valid_until": vu.to_string(), "daily_links": 5,
        "lei_commit": hex::encode([2u8;32]), "verifier": w.verifier.id()});
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id()).as_bytes()).to_bytes()));
    args["asset"] = json!(token.id());
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result());
    assert!(s.contains("BAD_ATTESTATION"));
    bench("A22", "funder swaps the settlement asset after the verifier signed", "BAD_ATTESTATION", "BAD_ATTESTATION", 0);
    Ok(())
}

// ---------------------------------------------------------------- 邊界與帳務（由 cargo-mutants 找出的缺口補上）

#[tokio::test]
async fn b05_boundaries_accounting_and_events() -> anyhow::Result<()> {
    let w = world().await?;
    // 金庫恰好 = 3 節：開格費 0.1 NEAR + 3 × 0.01 NEAR
    let mut o = default_opts(&w);
    o.n = 5; o.daily = 5; o.deposit_near = 0; // 下面自己算存款
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(5);
    let vu = now_ns(&w).await? + 3_600_000_000_000;
    let mut args = json!({"amc_said": "EB05", "issuer_pk": hex::encode([7u8;32]), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": 5,
        "unit": UNIT.to_string(), "scope": [w.merchant.id()], "valid_until": vu.to_string(), "daily_links": 5,
        "lei_commit": hex::encode([2u8;32]), "verifier": w.verifier.id()});
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id()).as_bytes()).to_bytes()));
    let deposit = 100_000_000_000_000_000_000_000u128 + 3 * UNIT;
    let out = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_yoctonear(deposit)).max_gas().transact().await?;
    assert!(out.logs().iter().any(|l| l.contains("\"event\":\"registered\"")), "registered event emitted");
    let cell: String = out.into_result()?.json()?;
    let agent = Account::from_secret_key(w.writ.id().clone(), agent_sk, &w.worker);
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    let today = now_ns(&w).await? / 86_400_000_000_000;
    assert!(c["day"].as_u64().unwrap() == today || c["day"].as_u64().unwrap() + 1 == today, "day bucket = timestamp / 1 day");

    // 金庫剛好夠 3 節 → 付得出去；再 1 節 → FUNDS
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "vault exactly equal to amount must pay: {}", v);
    let v = spend(&agent, w.writ.id(), &pw.link(4), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS");
    bench("A23", "spend more than the vault holds (valid links, within rate)", "Rejected:FUNDS", "Rejected:FUNDS", 0);

    // 追加入金後，用完整條鏈（idx + j == n）必須成功
    w.funder.call(w.writ.id(), "top_up").args_json(json!({"cell": cell})).deposit(NearToken::from_yoctonear(2 * UNIT)).transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    assert_eq!(c["vault"], (2 * UNIT).to_string(), "top_up adds exactly the deposit");
    let v = spend(&agent, w.writ.id(), &pw.link(5), 2, w.merchant.id()).await.unwrap();
    assert_eq!(v["Paid"]["remaining_links"], 0, "the last link of the chain is spendable: {}", v);

    // 計數：這格被拒 1 次；全域 rejected/cells
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    assert_eq!(c["rejects"], 1);
    assert_eq!(c["spends"], 2);
    let (cell2, _a2, _p2) = open_cell(&w, default_opts(&w)).await?;
    assert_ne!(cell2.to_string(), cell, "cell ids are unique");
    let st: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(st["cells"], 2);
    assert_eq!(st["rejected"], 1);
    assert_eq!(st["paid"], 2);
    assert_eq!(st["paid_yocto"], (5 * UNIT).to_string());
    // 償付能力：金庫總和 = 0.9 NEAR（第二格）+ 0（第一格已用完）
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["vault_total"], "900000000000000000000000");
    assert_eq!(sol["solvent"], true);
    bench("B05", "boundaries: vault == amount pays, last link spendable, top_up, counters, solvency", "all exact", "all exact", 0);
    Ok(())
}

#[tokio::test]
async fn b06_refresh_key_restores_gas_allowance() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw) = open_cell(&w, default_opts(&w)).await?;
    let allowance = |w: &World| {
        let (wk, id, pk) = (w.worker.clone(), w.writ.id().clone(), agent.secret_key().public_key());
        async move {
            let keys = wk.view_access_keys(&id).await.unwrap();
            let k = keys.into_iter().find(|k| k.public_key == pk).expect("agent key present");
            match k.access_key.permission {
                near_workspaces::types::AccessKeyPermission::FunctionCall(f) => f.allowance.unwrap().as_yoctonear(),
                _ => panic!("agent key must be a function-call key"),
            }
        }
    };
    let full = allowance(&w).await;
    assert!(spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap().get("Paid").is_some());
    let used = allowance(&w).await;
    assert!(used < full, "gas allowance is consumed by the agent's transactions");
    let r = w.attacker.call(w.writ.id(), "refresh_key").args_json(json!({"cell": cell.to_string()})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_AUTHORIZED"));
    w.funder.call(w.writ.id(), "refresh_key").args_json(json!({"cell": cell.to_string()})).max_gas().transact().await?.into_result()?;
    assert_eq!(allowance(&w).await, full, "refresh_key restores the full allowance with the same key");
    assert!(spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap().get("Paid").is_some());
    bench("B06", "gas allowance consumed → funder refresh_key (stranger refused)", "allowance restored, agent keeps paying", "restored", 0);
    Ok(())
}
