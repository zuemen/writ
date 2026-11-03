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
// 開格費 = 0.35 NEAR（>= agent 鑰匙的 gas allowance）+ 每節 0.001 NEAR（發票紀錄的儲存）
fn fee(n: u32) -> u128 { 350_000_000_000_000_000_000_000 + (n as u128) * 1_000_000_000_000_000_000_000 }
const AMC_ISSUER: &str = "EISSUER_AID";

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
    attacker_start: u128,
}

/// 攻擊者 NEAR 餘額相對開始時的淨增加（攻擊者自己付 gas，所以沒賺錢時是 0）。
async fn gain(w: &World) -> i128 {
    balance(&w.attacker).await.saturating_sub(w.attacker_start) as i128
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
    writ.call("new").args_json(json!({"owner": writ.id(), "unseal_delay_secs": 5})).transact().await?.into_result()?;
    let verifier = worker.dev_create_account().await?;
    let funder = worker.dev_create_account().await?;
    let merchant = worker.dev_create_account().await?;
    let attacker = worker.dev_create_account().await?;
    let verifier_sk = SigningKey::generate(&mut rand::thread_rng());
    writ.call("set_verifier")
        .args_json(json!({"account": verifier.id(), "pk_hex": hex::encode(verifier_sk.verifying_key().to_bytes())}))
        .transact().await?.into_result()?;
    let attacker_start = balance(&attacker).await;
    Ok(World { worker, writ, verifier, verifier_sk, funder, merchant, attacker, attacker_start })
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
    ecr_commit: String,
    max_links: u32,
    max_strikes: u32,
    issuer_aid: String,
}

const ECR_COMMIT_SALT: &str = "salt-ecr";
/// 測試裡的 attestation 一律用「遠在未來」的時間，表示剛簽完；A33 另外測過期。
const ATTESTED_NOW: u64 = u64::MAX / 2;

/// 與合約 attestation_message 完全一致的規範字串。
fn attest_msg(a: &Value, funder: &AccountId, contract: &AccountId) -> String {
    let scope: Vec<String> = a["scope"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
    format!(
        "writ:attest:v5\ncontract={}\namc={}\nissuer_aid={}\nissuer_pk={}\nagent_pk={}\nw0={}\nn={}\nunit={}\nscope={}\nvalid_until={}\ndaily_links={}\nmax_links={}\nmax_strikes={}\nlei_commit={}\necr_commit={}\nfunder={}\nverifier={}\nattested_at={}\nasset={}\ncredit={}",
        contract, a["amc_said"].as_str().unwrap(), a.get("issuer_aid").and_then(|v| v.as_str()).unwrap(), a["issuer_pk"].as_str().unwrap(), a["agent_pk"].as_str().unwrap(),
        a["w0"].as_str().unwrap(), a["n"], a["unit"].as_str().unwrap(), scope.join(","),
        a["valid_until"].as_str().unwrap(), a["daily_links"], a["max_links"], a["max_strikes"], a["lei_commit"].as_str().unwrap(), a["ecr_commit"].as_str().unwrap(), funder,
        a["verifier"].as_str().unwrap(), a["attested_at"].as_str().unwrap(),
        a.get("asset").and_then(|v| v.as_str()).unwrap_or("near"),
        a.get("credit").filter(|c| !c.is_null()).map(|c| format!("{},{},{},{},{},{},{},{},{}",
            c["limit"].as_str().unwrap(), c["bond_bps"], c["premium_bps"], c["min_tenor"].as_str().unwrap(), c["max_tenor"].as_str().unwrap(),
            c["terms_hash"].as_str().unwrap(), c["terms_sig"].as_str().unwrap(), c["entity_tag"].as_str().unwrap(), c["arbiter"].as_str().unwrap())).unwrap_or_else(|| "none".to_string())
    )
}

async fn now_ns(w: &World) -> anyhow::Result<u64> {
    Ok(w.worker.view_block().await?.timestamp())
}

/// 開一格：回傳 (cell id, agent 以合約帳號身分的 Account, PayWord 鏈)
async fn open_cell(w: &World, o: Opts) -> anyhow::Result<(u64, Account, Payword)> {
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let lei_commit = hex::encode(Sha256::digest(b"WRITDEMO000000000017|salt-demo"));
    let valid_until = now_ns(w).await? + o.valid_secs * 1_000_000_000;
    let mut args = json!({
        "amc_said": o.amc_said, "issuer_aid": o.issuer_aid, "issuer_pk": o.issuer_pk, "max_links": o.max_links, "max_strikes": o.max_strikes, "attested_at": ATTESTED_NOW.to_string(), "agent_pk": agent_sk.public_key(),
        "w0": pw.w0(), "n": o.n, "unit": o.unit.to_string(), "scope": o.scope,
        "valid_until": valid_until.to_string(), "daily_links": o.daily, "lei_commit": lei_commit,
        "ecr_commit": o.ecr_commit,
        "verifier": w.verifier.id(),
    });
    if let Some(t) = &o.asset { args["asset"] = json!(t); }
    let sig = w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes());
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
        ecr_commit: hex::encode(Sha256::digest(format!("LE|{}|ECR|{}", hex::encode([9u8; 32]), ECR_COMMIT_SALT))),
        max_links: 1000,
        max_strikes: 3,
        issuer_aid: AMC_ISSUER.into(),
    }
}

async fn spend(agent: &Account, writ: &AccountId, preimage: &str, j: u32, to: &AccountId) -> Result<Value, String> {
    match agent.call(writ, "spend").args_json(json!({"preimage": preimage, "j": j, "to": to, "invoice_hash": hex::encode(rand::random::<[u8; 32]>())})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await {
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
    assert!(!p.to_string().contains("WRITDEMO000000000017"), "LEI never appears on chain");
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
    bench("A02", "spend more links than the mandate holds", "Rejected:LIMIT", "Rejected:LIMIT", gain(&w).await);
    // 偽造鏈節（agent 自己編一個 preimage）
    let v = spend(&agent, w.writ.id(), &"ab".repeat(32), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A03", "forged hash-chain link (agent invents budget)", "Rejected:CHAIN", "Rejected:CHAIN", gain(&w).await);
    // 合法一筆後重放同一個鏈節
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some());
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A04", "replay an already-spent link", "Rejected:CHAIN", "Rejected:CHAIN", gain(&w).await);
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
    bench("A05", "drain faster than the daily rate (valid links)", "Rejected:RATE", "Rejected:RATE", gain(&w).await);
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
    bench("A06", "spend after the AMC validity window", "Rejected:EXPIRED", "Rejected:EXPIRED", gain(&w).await);
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
    bench("A07", "injected agent keeps trying (3 strikes)", "key deleted, next call AccessKeyNotFound", proto_tag(&e), gain(&w).await);
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
    bench("A08", "agent key calls admin method set_verifier", "MethodNameMismatch", "MethodNameMismatch", gain(&w).await);

    // 附帶存款（標準 ft_transfer 需要 1 yocto）
    let e = agent.call(w.writ.id(), "spend").args_json(json!({"preimage": "00", "j": 1, "to": w.attacker.id()}))
        .deposit(NearToken::from_yoctonear(1)).transact().await.unwrap_err();
    assert_eq!(proto_tag(&format!("{:?}", e)), "DepositWithFunctionCall");
    bench("A09", "agent attaches deposit (e.g. ft_transfer 1 yocto)", "DepositWithFunctionCall", "DepositWithFunctionCall", gain(&w).await);

    // 直接把合約帳號的 NEAR 轉走
    let e = agent.transfer_near(w.attacker.id(), NearToken::from_millinear(1)).await;
    let s = format!("{:?}", e);
    assert!(s.contains("RequiresFullAccess"), "plain transfer must be impossible: {}", s);
    bench("A10", "agent sends a plain Transfer from the contract account", "RequiresFullAccess", proto_tag(&s), gain(&w).await);

    // 用 agent 的鑰匙呼叫別的合約
    let e = agent.call(w.attacker.id(), "anything").transact().await.unwrap_err();
    let s = format!("{:?}", e);
    assert!(s.contains("ReceiverMismatch") || s.contains("MethodNameMismatch") || s.contains("CodeDoesNotExist"), "{}", s);
    bench("A11", "agent key used against another contract", "ReceiverMismatch", if s.contains("ReceiverMismatch") { "ReceiverMismatch" } else { "OTHER" }, gain(&w).await);

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
        "lei_commit": hex::encode([2u8;32]), "ecr_commit": hex::encode([3u8;32]), "issuer_aid": AMC_ISSUER, "max_links": 1000, "max_strikes": 3, "attested_at": ATTESTED_NOW.to_string(), "verifier": w.verifier.id(),
    });
    // (a) 非白名單的人自己簽
    let rogue = SigningKey::generate(&mut rand::thread_rng());
    args["signature"] = json!(hex::encode(rogue.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args.clone()})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A12", "self-signed attestation (not a whitelisted verifier)", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    // (b) 驗證者簽了，但出資者把 scope 改成攻擊者
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    args["scope"] = json!([w.attacker.id()]);
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args.clone()})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A13", "funder widens the scope after the verifier signed", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    // (c) 另一個帳號拿走別人的 attestation 來開格（funder 綁在簽章裡）
    args["scope"] = json!([w.merchant.id()]);
    let r = w.attacker.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A14", "attacker replays someone else's attestation", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    Ok(())
}

#[tokio::test]
async fn a15_revoke_by_kel_real_keri_event_is_permissionless() -> anyhow::Result<()> {
    let w = world().await?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string("tests/fixtures/vectors.json")?)?;
    let mut o = default_opts(&w);
    o.amc_said = v["amc"]["said"].as_str().unwrap().into();
    o.issuer_pk = v["issuer"]["pk_hex"].as_str().unwrap().into();
    o.issuer_aid = v["issuer"]["aid"].as_str().unwrap().into();
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
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(&hex::encode(bad)), "signature": b64(sig), "ecr": null})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"));
    bench("A15", "forged KERI revocation event", "BAD_KEL_SIGNATURE", "BAD_KEL_SIGNATURE", gain(&w).await);

    // 真簽章、真 ixn，但它錨定的是 AMC 的「發行」（seal s="0"），不是撤銷
    let iss = &v["iss_ixn"];
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(iss["raw_hex"].as_str().unwrap()), "signature": b64(iss["sig_hex"].as_str().unwrap()), "ecr": null}))
        .max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NO_REVOCATION_SEAL"));
    bench("A24", "genuine signed KERI event that anchors the AMC issuance, not a revocation", "NO_REVOCATION_SEAL", "NO_REVOCATION_SEAL", gain(&w).await);

    // 真的 ixn：任何人（這裡用 attacker 帳號）都能提交，不需要信任 watcher
    let funder_before = balance(&w.funder).await;
    let out = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(ixn), "signature": b64(sig), "ecr": null})).max_gas().transact().await?;
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
    assert_eq!(v["Rejected"]["reason"], "TRANSFER_FAILED", "Paid only appears when the money arrived: {}", v);
    let st: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(st["paid"], 0);
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    let vault: u128 = c["vault"].as_str().unwrap().parse()?;
    assert_eq!(vault, 1_000_000_000_000_000_000_000_000 - fee(20), "transfer to non-existent account refunded");
    bench("B02", "payment to a non-existent account", "Rejected:TRANSFER_FAILED, vault refunded", "Rejected:TRANSFER_FAILED, vault refunded", 0);

    let r = w.attacker.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "x"})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_AUTHORIZED"));
    bench("A16", "stranger tries to revoke (griefing)", "NOT_AUTHORIZED", "NOT_AUTHORIZED", gain(&w).await);

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
    bench("A17", "non-supervisor requests disclosure of the legal entity", "NOT_SUPERVISOR", "NOT_SUPERVISOR", gain(&w).await);

    w.writ.call("set_supervisor").args_json(json!({"account": supervisor.id(), "enabled": true})).transact().await?.into_result()?;
    supervisor.call(w.writ.id(), "request_unseal").args_json(json!({"cell": cell.to_string(), "reason_hash": reason})).transact().await?.into_result()?;

    // 等待期內不能揭露
    let release = |lei: &str, salt: &str| {
        let (lei, salt) = (lei.to_string(), salt.to_string());
        let v = w.verifier.clone(); let id = w.writ.id().clone(); let c = cell.to_string();
        async move { v.call(&id, "release_unseal").args_json(json!({"cell": c, "lei": lei, "salt": salt})).transact().await.unwrap().into_result() }
    };
    let e = format!("{:?}", release("WRITDEMO000000000017", "salt-demo").await);
    assert!(e.contains("TOO_EARLY"), "{}", e);
    bench("A18", "verifier discloses before the public waiting period ends", "TOO_EARLY", "TOO_EARLY", gain(&w).await);

    // 法人提出異議（公開留痕，不阻擋）
    w.funder.call(w.writ.id(), "object_unseal").args_json(json!({"cell": cell.to_string()})).transact().await?.into_result()?;
    w.worker.fast_forward(200).await?;

    // 驗證者想揭露一個不同的 LEI（栽贓給別家公司）
    let e = format!("{:?}", release("529900T8BM49AURSDO55", "salt-demo").await);
    assert!(e.contains("COMMIT_MISMATCH"), "{}", e);
    bench("A19", "verifier discloses a different LEI than it committed to", "COMMIT_MISMATCH", "COMMIT_MISMATCH", gain(&w).await);

    let out = release("WRITDEMO000000000017", "salt-demo").await?;
    println!("unsealed logs: {:?}", out.logs());
    let p: Value = w.writ.view("present").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(p["lei"], "WRITDEMO000000000017");
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
    bench("A20", "prompt-injected payment from a stablecoin cell", "Rejected:SCOPE", "Rejected:SCOPE", gain(&w).await);

    // 攻擊者持有同一種代幣，硬塞進這格（想污染帳）→ 退回
    w.funder.call(token.id(), "ft_transfer").args_json(json!({"receiver_id": w.attacker.id(), "amount": T.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).transact().await?.into_result()?;
    w.attacker.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": T.to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, T, "same token from a non-funder is refunded");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], (5 * T - 3 * T / 10).to_string());
    bench("A25", "non-funder pushes the cell's own stablecoin into it", "refunded, vault unchanged", "refunded", gain(&w).await);

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
    assert_eq!(c["vault"], (1_000_000_000_000_000_000_000_000 - fee(20)).to_string());
    bench("A21", "foreign token pushed into a cell via ft_transfer_call", "refunded, vault unchanged", "refunded", gain(&w).await);

    // 驗證者簽的是 NEAR 格，法人想改成代幣格
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(5);
    let vu = now_ns(&w).await? + 3_600_000_000_000;
    let mut args = json!({"amc_said": "EY", "issuer_pk": hex::encode([1u8;32]), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": 5,
        "unit": UNIT.to_string(), "scope": [w.merchant.id()], "valid_until": vu.to_string(), "daily_links": 5,
        "lei_commit": hex::encode([2u8;32]), "ecr_commit": hex::encode([3u8;32]), "issuer_aid": AMC_ISSUER, "max_links": 1000, "max_strikes": 3, "attested_at": ATTESTED_NOW.to_string(), "verifier": w.verifier.id()});
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    args["asset"] = json!(token.id());
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result());
    assert!(s.contains("BAD_ATTESTATION"));
    bench("A22", "funder swaps the settlement asset after the verifier signed", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    Ok(())
}

// ---------------------------------------------------------------- 邊界與帳務（由 cargo-mutants 找出的缺口補上）

#[tokio::test]
async fn b05_boundaries_accounting_and_events() -> anyhow::Result<()> {
    let w = world().await?;
    // 金庫恰好 = 3 節：開格費 + 3 × 0.01 NEAR
    let mut o = default_opts(&w);
    o.n = 5; o.daily = 5; o.deposit_near = 0; // 下面自己算存款
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(5);
    let vu = now_ns(&w).await? + 3_600_000_000_000;
    let mut args = json!({"amc_said": "EB05", "issuer_pk": hex::encode([7u8;32]), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": 5,
        "unit": UNIT.to_string(), "scope": [w.merchant.id()], "valid_until": vu.to_string(), "daily_links": 5,
        "lei_commit": hex::encode([2u8;32]), "ecr_commit": hex::encode([3u8;32]), "issuer_aid": AMC_ISSUER, "max_links": 1000, "max_strikes": 3, "attested_at": ATTESTED_NOW.to_string(), "verifier": w.verifier.id()});
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let deposit = fee(5) + 3 * UNIT;
    let out = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_yoctonear(deposit)).max_gas().transact().await?;
    assert!(out.logs().iter().any(|l| l.contains("\"event\":\"registered\"")), "registered event emitted");
    let cell: String = out.into_result()?.json()?;
    let agent = Account::from_secret_key(w.writ.id().clone(), agent_sk, &w.worker);
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    let today = now_ns(&w).await? / 86_400_000_000_000;
    assert!(c["day"].as_u64().unwrap() == today || c["day"].as_u64().unwrap() + 1 == today, "day bucket = timestamp / 1 day");

    // 金庫只夠 3 節，要 4 節 → FUNDS（金額 = j × unit，不是 j + unit）
    let v = spend(&agent, w.writ.id(), &pw.link(4), 4, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS", "{}", v);
    // 金庫剛好夠 3 節 → 付得出去；再 1 節 → FUNDS
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "vault exactly equal to amount must pay: {}", v);
    let v = spend(&agent, w.writ.id(), &pw.link(4), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS");
    bench("A23", "spend more than the vault holds (valid links, within rate)", "Rejected:FUNDS", "Rejected:FUNDS", gain(&w).await);

    // 追加入金後，用完整條鏈（idx + j == n）必須成功
    w.funder.call(w.writ.id(), "top_up").args_json(json!({"cell": cell})).deposit(NearToken::from_yoctonear(2 * UNIT)).transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    assert_eq!(c["vault"], (2 * UNIT).to_string(), "top_up adds exactly the deposit");
    let v = spend(&agent, w.writ.id(), &pw.link(5), 2, w.merchant.id()).await.unwrap();
    assert_eq!(v["Paid"]["remaining_links"], 0, "the last link of the chain is spendable: {}", v);

    // 計數：這格被拒 1 次；全域 rejected/cells
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    assert_eq!(c["rejects"], 2);
    assert_eq!(c["spends"], 2);
    let (cell2, _a2, _p2) = open_cell(&w, default_opts(&w)).await?;
    assert_ne!(cell2.to_string(), cell, "cell ids are unique");
    let st: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(st["cells"], 2);
    assert_eq!(st["rejected"], 2);
    assert_eq!(st["paid"], 2);
    assert_eq!(st["paid_yocto"], (5 * UNIT).to_string());
    // 償付能力：金庫總和 = 0.9 NEAR（第二格）+ 0（第一格已用完）
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["vault_total"], (1_000_000_000_000_000_000_000_000 - fee(20)).to_string());
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
    let r = w.attacker.call(w.writ.id(), "refresh_key").args_json(json!({"cell": cell.to_string()})).deposit(NearToken::from_millinear(250)).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_AUTHORIZED"));
    w.funder.call(w.writ.id(), "refresh_key").args_json(json!({"cell": cell.to_string()})).deposit(NearToken::from_millinear(250)).max_gas().transact().await?.into_result()?;
    assert_eq!(allowance(&w).await, full, "refresh_key restores the full allowance with the same key");
    assert!(spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap().get("Paid").is_some());
    bench("B06", "gas allowance consumed → funder refresh_key (stranger refused)", "allowance restored, agent keeps paying", "restored", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第二輪：讀碼審查找到的洞（A26–A30、B07）

async fn send_register(w: &World, args: &Value) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_near(1)).max_gas().transact().await?)
}

fn signed_args(w: &World, o: &Opts, agent_pk: &near_workspaces::types::PublicKey, pw: &Payword, valid_until: u64, contract: &AccountId) -> Value {
    let lei_commit = hex::encode(Sha256::digest(b"WRITDEMO000000000017|salt-demo"));
    let mut args = json!({
        "amc_said": o.amc_said, "issuer_aid": o.issuer_aid, "issuer_pk": o.issuer_pk, "max_links": o.max_links, "max_strikes": o.max_strikes, "attested_at": ATTESTED_NOW.to_string(), "agent_pk": agent_pk,
        "w0": pw.w0(), "n": o.n, "unit": o.unit.to_string(), "scope": o.scope,
        "valid_until": valid_until.to_string(), "daily_links": o.daily, "lei_commit": lei_commit,
        "ecr_commit": o.ecr_commit, "verifier": w.verifier.id(),
    });
    let sig = w.verifier_sk.sign(attest_msg(&args, w.funder.id(), contract).as_bytes());
    args["signature"] = json!(hex::encode(sig.to_bytes()));
    args
}

#[tokio::test]
async fn a26_revoked_mandate_cannot_be_revived_by_replaying_its_attestation() -> anyhow::Result<()> {
    let w = world().await?;
    let o = default_opts(&w);
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let until = now_ns(&w).await? + 3_600_000_000_000;
    let args = signed_args(&w, &o, &agent_sk.public_key(), &pw, until, w.writ.id());
    let id: String = send_register(&w, &args).await?.into_result()?.json()?;
    w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": id, "evidence": "manual"})).transact().await?.into_result()?;

    let r = send_register(&w, &args).await?;
    assert!(format!("{:?}", r.into_result()).contains("AMC_ALREADY_USED"));
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    assert!(keys.iter().all(|k| k.public_key != agent_sk.public_key()), "the revoked agent key stays deleted");
    bench("A26", "revoked mandate revived by replaying its own attestation (resets the budget)", "AMC_ALREADY_USED", "AMC_ALREADY_USED", gain(&w).await);
    Ok(())
}

#[tokio::test]
async fn a27_attestation_is_bound_to_one_contract_deployment() -> anyhow::Result<()> {
    let w = world().await?;
    let o = default_opts(&w);
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let until = now_ns(&w).await? + 3_600_000_000_000;
    let other: AccountId = "another-writ.test.near".parse()?;
    let args = signed_args(&w, &o, &agent_sk.public_key(), &pw, until, &other);
    let r = send_register(&w, &args).await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_ATTESTATION"));
    bench("A27", "attestation signed for another deployment replayed on this contract", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    Ok(())
}

#[tokio::test]
async fn a28_gas_burn_cannot_reach_another_cells_vault() -> anyhow::Result<()> {
    let w = world().await?;
    let surplus = |w: &World| {
        let writ = w.writ.clone();
        async move {
            let sol: Value = writ.view("solvency").await.unwrap().json().unwrap();
            let b: u128 = sol["balance"].as_str().unwrap().parse().unwrap();
            let v: u128 = sol["vault_total"].as_str().unwrap().parse().unwrap();
            b - v
        }
    };
    // 受害格
    let mut victim = default_opts(&w);
    victim.amc_said = "EVICTIM".into();
    open_cell(&w, victim).await?;
    let before = surplus(&w).await;

    // 串通的法人與 agent：開一格，用格式錯誤的參數燒 gas（panic 不算 strike）
    let (cell, agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    for _ in 0..20 {
        let r = agent.call(w.writ.id(), "spend").args_json(json!({"preimage": 1, "j": "x", "to": "!!"}))
            .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?;
        assert!(r.into_result().is_err(), "malformed args must fail");
    }
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["strikes"], 0, "malformed calls burn gas without reaching the policy checks");

    // 免費續命被拒
    let r = w.funder.call(w.writ.id(), "refresh_key").args_json(json!({"cell": cell.to_string()})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("REFRESH_UNPAID"));
    assert!(surplus(&w).await >= before, "this cell's fee covers everything its key burned");
    bench("A28", "colluding funder + agent burn gas and refresh for free to drain other cells' vaults", "REFRESH_UNPAID", "REFRESH_UNPAID", gain(&w).await);
    Ok(())
}

/// HR 路徑：LE 撤銷員工的 ECR。fixtures 由 keri/make_test_vectors.py 以真 keripy 產生。
#[tokio::test]
async fn b07_hr_revokes_the_ecr_without_the_departing_employee() -> anyhow::Result<()> {
    let w = world().await?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string("tests/fixtures/vectors.json")?)?;
    let e = &v["ecr_revocation"];
    let (le_aid, le_pk, ecr_said) = (e["le_aid"].as_str().unwrap(), e["le_pk_hex"].as_str().unwrap(), e["ecr_said"].as_str().unwrap());
    let mut o = default_opts(&w);
    o.amc_said = v["amc"]["said"].as_str().unwrap().into();
    o.issuer_pk = v["issuer"]["pk_hex"].as_str().unwrap().into();
    o.issuer_aid = v["issuer"]["aid"].as_str().unwrap().into();
    o.ecr_commit = hex::encode(Sha256::digest(format!("{}|{}|{}|{}", le_aid, le_pk, ecr_said, ECR_COMMIT_SALT)));
    let (cell, agent, pw) = open_cell(&w, o).await?;
    assert!(spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap().get("Paid").is_some());
    let b64 = |h: &str| near_sdk::base64::Engine::encode(&near_sdk::base64::prelude::BASE64_STANDARD, hex::decode(h).unwrap());
    let (ixn, sig) = (b64(e["raw_hex"].as_str().unwrap()), b64(e["sig_hex"].as_str().unwrap()));

    // 鹽值錯 → 打不開承諾，無法冒充法人
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": ixn, "signature": sig, "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": "wrong"}})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_ECR_OPENING"));
    bench("A29", "attacker presents its own key as the legal entity to revoke the mandate", "BAD_ECR_OPENING", "BAD_ECR_OPENING", gain(&w).await);

    // 承諾打得開，但事件被竄改 → 簽章不過
    let mut tampered = hex::decode(e["raw_hex"].as_str().unwrap())?;
    let last = tampered.len() - 3;
    tampered[last] ^= 1;
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(&hex::encode(tampered)), "signature": sig, "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": ECR_COMMIT_SALT}})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"));
    bench("A30", "forged ECR revocation event with a valid commitment opening", "BAD_KEL_SIGNATURE", "BAD_KEL_SIGNATURE", gain(&w).await);

    // 真事件：任何人交都可以
    w.merchant.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": ixn, "signature": sig, "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": ECR_COMMIT_SALT}})).max_gas().transact().await?.into_result()?;
    let err = spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&err), "AccessKeyNotFound");
    bench("B07", "HR revokes the employee's ECR in KERI; anyone submits it; employee not needed", "key deleted, next call AccessKeyNotFound", proto_tag(&err), 0);
    Ok(())
}

// ---------------------------------------------------------------- 第三輪：發票、單筆上限、恢復、鎖定、輪替

async fn spend_invoice(agent: &Account, writ: &AccountId, preimage: &str, j: u32, to: &AccountId, invoice: &[u8]) -> Value {
    let inv = hex::encode(Sha256::digest(invoice));
    agent.call(writ, "spend").args_json(json!({"preimage": preimage, "j": j, "to": to, "invoice_hash": inv}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await.unwrap().into_result().unwrap().json().unwrap()
}

#[tokio::test]
async fn a31_injection_inside_scope_duplicate_and_inflated_invoices() -> anyhow::Result<()> {
    let w = world().await?;
    let mut o = default_opts(&w);
    o.max_links = 3;
    let (cell, agent, pw) = open_cell(&w, o).await?;
    let merchant_before = balance(&w.merchant).await;
    let v = spend_invoice(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id(), b"INV-1").await;
    assert!(v.get("Paid").is_some(), "{}", v);
    let inv = hex::encode(Sha256::digest(b"INV-1"));
    let paid: bool = w.writ.view("invoice_paid").args_json(json!({"cell": cell.to_string(), "invoice_hash": inv})).await?.json()?;
    assert!(paid, "the invoice is on record for reconciliation");

    let v = spend_invoice(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id(), b"INV-1").await;
    assert_eq!(v["Rejected"]["reason"], "DUPLICATE");
    bench("A31", "injection makes the agent pay an in-scope merchant for the same invoice twice", "Rejected:DUPLICATE", "Rejected:DUPLICATE", gain(&w).await);

    let v = spend_invoice(&agent, w.writ.id(), &pw.link(5), 4, w.merchant.id(), b"INV-2").await;
    assert_eq!(v["Rejected"]["reason"], "PER_TX");
    bench("A32", "injection inflates the amount paid to an in-scope merchant past the per-payment cap", "Rejected:PER_TX", "Rejected:PER_TX", gain(&w).await);

    let r = agent.call(w.writ.id(), "spend").args_json(json!({"preimage": pw.link(2), "j": 1, "to": w.merchant.id(), "invoice_hash": "not-hex"}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json::<Value>()?;
    assert_eq!(r["Rejected"]["reason"], "INVOICE");
    let gained = balance(&w.merchant).await - merchant_before;
    assert_eq!(gained, UNIT, "only the one legitimate payment moved money");
    Ok(())
}

#[tokio::test]
async fn a33_stale_attestation_and_wrong_aid() -> anyhow::Result<()> {
    let w = world().await?;
    let o = default_opts(&w);
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let now = now_ns(&w).await?;
    let mut args = signed_args(&w, &o, &agent_sk.public_key(), &pw, now + 3_600_000_000_000, w.writ.id());
    args["attested_at"] = json!((now - 2 * 3_600_000_000_000).to_string());
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let r = send_register(&w, &args).await?;
    assert!(format!("{:?}", r.into_result()).contains("STALE_ATTESTATION"));
    bench("A33", "attestation signed before a revocation is used long afterwards", "STALE_ATTESTATION", "STALE_ATTESTATION", gain(&w).await);

    // 同一把鑰匙替別的 AID 簽的錨定事件，不能拿來撤銷這一格
    let sk = SigningKey::generate(&mut rand::thread_rng());
    let mut o = default_opts(&w);
    o.issuer_pk = hex::encode(sk.verifying_key().to_bytes());
    let amc = o.amc_said.clone();
    let (cell, _agent, _pw) = open_cell(&w, o).await?;
    let ixn = json!({"t": "ixn", "i": "ESOMEONE_ELSE", "a": [{"i": amc, "s": "1", "d": "EREV"}]}).to_string();
    let b64 = |b: &[u8]| near_sdk::base64::Engine::encode(&near_sdk::base64::prelude::BASE64_STANDARD, b);
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(ixn.as_bytes()), "signature": b64(&sk.sign(ixn.as_bytes()).to_bytes())})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("WRONG_AID"));
    bench("A34", "signed anchoring event from a different KERI identifier", "WRONG_AID", "WRONG_AID", gain(&w).await);
    Ok(())
}

#[tokio::test]
async fn b08_funder_reinstates_after_the_tripwire() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw) = open_cell(&w, default_opts(&w)).await?;
    for _ in 0..3 {
        spend(&agent, w.writ.id(), &pw.link(1), 1, w.attacker.id()).await.unwrap();
    }
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    assert!(keys.iter().all(|k| k.public_key != agent.secret_key().public_key()), "tripped");

    let r = w.attacker.call(w.writ.id(), "reinstate").args_json(json!({"cell": cell.to_string()})).deposit(NearToken::from_millinear(250)).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("ONLY_FUNDER"));
    bench("A35", "stranger re-arms a tripped agent key", "ONLY_FUNDER", "ONLY_FUNDER", gain(&w).await);
    let r = w.funder.call(w.writ.id(), "reinstate").args_json(json!({"cell": cell.to_string()})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("REINSTATE_UNPAID"));

    w.funder.call(w.writ.id(), "reinstate").args_json(json!({"cell": cell.to_string()})).deposit(NearToken::from_millinear(250)).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["status"], "Active");
    assert_eq!(c["strikes"], 0);
    let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "{}", v);
    bench("B08", "three bad invoices trip the key; funder pays to reinstate; agent pays again", "Paid after reinstate", "Paid after reinstate", 0);
    Ok(())
}

#[tokio::test]
async fn b09_verifier_updates_signers_after_key_rotation() -> anyhow::Result<()> {
    let w = world().await?;
    let old = SigningKey::generate(&mut rand::thread_rng());
    let new = SigningKey::generate(&mut rand::thread_rng());
    let mut o = default_opts(&w);
    o.issuer_pk = hex::encode(old.verifying_key().to_bytes());
    let amc = o.amc_said.clone();
    let (cell, agent, _pw) = open_cell(&w, o).await?;
    let ixn = json!({"t": "ixn", "i": AMC_ISSUER, "a": [{"i": amc, "s": "1", "d": "EREV"}]}).to_string();
    let b64 = |b: &[u8]| near_sdk::base64::Engine::encode(&near_sdk::base64::prelude::BASE64_STANDARD, b);
    let submit = |sk: &SigningKey| json!({"cell": cell.to_string(), "ixn": b64(ixn.as_bytes()), "signature": b64(&sk.sign(ixn.as_bytes()).to_bytes())});

    let r = w.merchant.call(w.writ.id(), "revoke_by_kel").args_json(submit(&new)).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"), "before the update the rotated key is unknown");

    let update = json!({"cell": cell.to_string(), "issuer_aid": AMC_ISSUER, "issuer_pk": hex::encode(new.verifying_key().to_bytes()), "ecr_commit": hex::encode([4u8; 32])});
    let r = w.attacker.call(w.writ.id(), "update_signers").args_json(update.clone()).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("ONLY_CELL_VERIFIER"));
    bench("A36", "stranger swaps the keys that may revoke a mandate", "ONLY_CELL_VERIFIER", "ONLY_CELL_VERIFIER", gain(&w).await);
    w.verifier.call(w.writ.id(), "update_signers").args_json(update).transact().await?.into_result()?;

    let r = w.merchant.call(w.writ.id(), "revoke_by_kel").args_json(submit(&old)).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"), "the rotated-out key can no longer revoke");
    w.merchant.call(w.writ.id(), "revoke_by_kel").args_json(submit(&new)).max_gas().transact().await?.into_result()?;
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    assert!(keys.iter().all(|k| k.public_key != agent.secret_key().public_key()));
    bench("B09", "employee rotates keys; verifier updates the signer; new key revokes, old key cannot", "key deleted by the new key", "key deleted by the new key", 0);
    Ok(())
}

#[tokio::test]
async fn b10_locked_deployment_has_no_full_access_key() -> anyhow::Result<()> {
    let worker = near_workspaces::sandbox().await?;
    let owner = worker.dev_create_account().await?;
    let root = worker.root_account()?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let acc = root.create_subaccount("locked").initial_balance(NearToken::from_near(20)).keys(sk.clone()).transact().await?.into_result()?;
    acc.batch(acc.id())
        .deploy(&wasm_bytes()?)
        .call(near_workspaces::operations::Function::new("new").args_json(json!({"owner": owner.id(), "unseal_delay_secs": 5})))
        .delete_key(sk.public_key())
        .transact().await?.into_result()?;
    let keys = worker.view_access_keys(acc.id()).await?;
    assert!(keys.is_empty(), "no key can move the vaults: {:?}", keys.len());
    // owner 從外部帳號管理白名單
    owner.call(acc.id(), "set_verifier").args_json(json!({"account": owner.id(), "pk_hex": hex::encode([1u8; 32])})).transact().await?.into_result()?;
    let got: String = worker.view(acc.id(), "owner").await?.json::<Value>()?.as_str().unwrap().to_string();
    assert_eq!(got, owner.id().as_str());
    bench("B10", "deploy + init + delete full-access key in one batch; owner still manages the whitelist", "0 keys on the contract account", "0 keys on the contract account", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第四輪：獨立審計找到的問題

#[tokio::test]
async fn b11_refund_failure_is_claimable_and_excess_near_returned() -> anyhow::Result<()> {
    let w = world().await?;
    const T: u128 = 1_000_000;
    let token = w.worker.dev_deploy(&std::fs::read("res/ft_mock.wasm")?).await?;
    token.call("new").args_json(json!({"owner_id": w.funder.id(), "total_supply": (10_000 * T).to_string()})).transact().await?.into_result()?;
    token.call("storage_deposit").args_json(json!({"account_id": w.writ.id()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    let mut o = default_opts(&w);
    o.asset = Some(token.id().clone());
    o.deposit_near = 5;
    o.unit = T / 10;
    let before = balance(&w.funder).await;
    let (cell, _agent, _pw) = open_cell(&w, o).await?;
    let spent = before - balance(&w.funder).await;
    assert!(spent < 500_000_000_000_000_000_000_000, "only the fee stays; the rest of the 5 NEAR came back: {}", spent);
    bench("B11", "token cell: NEAR above the fee is returned", "excess returned", "excess returned", 0);

    w.funder.call(token.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": (5 * T).to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    // 法人把代幣餘額清掉並退出代幣，之後撤銷：退款一定失敗
    w.funder.call(token.id(), "ft_transfer").args_json(json!({"receiver_id": w.writ.id(), "amount": (9_995 * T).to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    w.funder.call(token.id(), "storage_unregister").args_json(json!({})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "manual"})).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["unclaimed"], (5 * T).to_string(), "the failed refund is kept, not lost");

    let r = w.attacker.call(w.writ.id(), "claim_refund").args_json(json!({"cell": cell.to_string()})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("ONLY_FUNDER"));
    bench("A37", "stranger claims a failed refund", "ONLY_FUNDER", "ONLY_FUNDER", gain(&w).await);

    token.call("storage_deposit").args_json(json!({"account_id": w.funder.id()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    w.funder.call(w.writ.id(), "claim_refund").args_json(json!({"cell": cell.to_string()})).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.funder.id()).await, 5 * T);
    bench("B12", "refund fails because the funder left the token; funder re-registers and claims", "tokens recovered", "tokens recovered", 0);
    Ok(())
}

#[tokio::test]
async fn a38_removed_verifier_and_supervisor_lose_their_powers() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, _a, _p) = open_cell(&w, default_opts(&w)).await?;
    let reg = w.worker.dev_create_account().await?;
    w.writ.call("set_supervisor").args_json(json!({"account": reg.id(), "enabled": true})).transact().await?.into_result()?;
    reg.call(w.writ.id(), "request_unseal").args_json(json!({"cell": cell.to_string(), "reason_hash": hex::encode([5u8; 32])})).transact().await?.into_result()?;
    w.writ.call("set_supervisor").args_json(json!({"account": reg.id(), "enabled": false})).transact().await?.into_result()?;
    let r = w.verifier.call(w.writ.id(), "release_unseal").args_json(json!({"cell": cell.to_string(), "lei": "WRITDEMO000000000017", "salt": "salt-demo"})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("REQUESTER_REMOVED"));

    w.writ.call("set_verifier").args_json(json!({"account": w.verifier.id()})).transact().await?.into_result()?;
    let r = w.verifier.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "x"})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_AUTHORIZED"));
    let p: Value = w.writ.view("present").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(p["chain_valid"], false);
    bench("A38", "verifier or supervisor removed from the whitelist keeps acting", "REQUESTER_REMOVED, NOT_AUTHORIZED", "REQUESTER_REMOVED, NOT_AUTHORIZED", gain(&w).await);

    let r = w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "x".repeat(200)})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("EVIDENCE_TOO_LONG"));
    bench("A39", "oversized evidence string used to consume shared storage", "EVIDENCE_TOO_LONG", "EVIDENCE_TOO_LONG", gain(&w).await);
    Ok(())
}

/// 每筆付款的實際 gas（README 引用這個數字）。
#[tokio::test]
async fn b13_gas_cost_of_a_payment() -> anyhow::Result<()> {
    let w = world().await?;
    let mut o = default_opts(&w);
    o.n = 200; o.daily = 200; o.deposit_near = 5; o.unit = UNIT / 10;
    let (_c, agent, pw) = open_cell(&w, o).await?;
    let run = |j: u32, k: u32, inv: &'static [u8]| {
        let (agent, writ, to, pre) = (agent.clone(), w.writ.id().clone(), w.merchant.id().clone(), pw.link(k));
        async move {
            let out = agent.call(&writ, "spend").args_json(json!({"preimage": pre, "j": j, "to": to, "invoice_hash": hex::encode(Sha256::digest(inv))}))
                .gas(near_workspaces::types::Gas::from_tgas(80)).transact().await.unwrap();
            assert!(out.clone().into_result().unwrap().json::<Value>().unwrap().get("Paid").is_some());
            out.total_gas_burnt.as_tgas()
        }
    };
    let one = run(1, 1, b"G1").await;
    let hundred = run(100, 101, b"G2").await;
    println!("WRIT_GAS|one_link={}|hundred_links={}", one, hundred);
    assert!(hundred < 30, "a 100-link payment stays cheap: {} Tgas", hundred);
    bench("B13", "gas burnt by a payment, whole transaction", "under 30 Tgas", &format!("1 link {} Tgas, 100 links {} Tgas", one, hundred), 0);
    Ok(())
}

// ---------------------------------------------------------------- 第五輪：cargo-mutants 存活者

#[tokio::test]
async fn b14_boundaries_from_mutation_survivors() -> anyhow::Result<()> {
    let w = world().await?;
    // 單筆上限：剛好等於上限可以付
    let mut o = default_opts(&w);
    o.max_links = 3;
    o.amc_said = "EB14A".into();
    let (cell, agent, pw) = open_cell(&w, o).await?;
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "j == max_links pays: {}", v);
    let unpaid = hex::encode(Sha256::digest(b"never paid"));
    let paid: bool = w.writ.view("invoice_paid").args_json(json!({"cell": cell.to_string(), "invoice_hash": unpaid})).await?.json()?;
    assert!(!paid, "an invoice never paid is not on record");

    // maxStrikes = 0：一直被拒也不刪鑰匙
    let mut o = default_opts(&w);
    o.max_strikes = 0;
    o.amc_said = "EB14B".into();
    let (cell, agent, pw) = open_cell(&w, o).await?;
    for k in 1..=4 {
        let v = spend(&agent, w.writ.id(), &pw.link(1), 1, w.attacker.id()).await.unwrap();
        assert_eq!(v["Rejected"]["strikes"], k);
        assert_eq!(v["Rejected"]["tripped"], false);
    }
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["status"], "Active");

    // solvency 的 storage = 用量 × 每 byte 成本
    let sol: Value = w.writ.view("solvency").await?.json()?;
    let usage = w.writ.view_account().await?.storage_usage as u128;
    assert_eq!(sol["storage"], (usage * 10_000_000_000_000_000_000u128).to_string());
    assert_eq!(sol["solvent"], true);
    bench("B14", "boundaries: j == cap pays, unpaid invoice not on record, maxStrikes 0 never trips, solvency counts storage", "all exact", "all exact", 0);
    Ok(())
}

#[tokio::test]
async fn b15_near_refund_failure_is_kept_and_claimable() -> anyhow::Result<()> {
    let w = world().await?;
    let vault_total = |w: &World| {
        let writ = w.writ.clone();
        async move {
            let sol: Value = writ.view("solvency").await.unwrap().json().unwrap();
            sol["vault_total"].as_str().unwrap().parse::<u128>().unwrap()
        }
    };
    // 法人是可以刪掉再重建的子帳號
    let root = w.worker.root_account()?;
    let funder_sk = SecretKey::from_random(KeyType::ED25519);
    let funder = root.create_subaccount("corp").initial_balance(NearToken::from_near(10)).keys(funder_sk.clone()).transact().await?.into_result()?;
    let o = default_opts(&w);
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let mut args = json!({
        "amc_said": "EB15", "issuer_aid": AMC_ISSUER, "issuer_pk": o.issuer_pk, "max_links": 10, "max_strikes": 3, "attested_at": ATTESTED_NOW.to_string(),
        "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": o.n, "unit": o.unit.to_string(), "scope": o.scope,
        "valid_until": (now_ns(&w).await? + 3_600_000_000_000).to_string(), "daily_links": o.daily, "lei_commit": hex::encode([2u8; 32]),
        "ecr_commit": hex::encode([3u8; 32]), "verifier": w.verifier.id(),
    });
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let id: String = funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_near(1)).max_gas().transact().await?.into_result()?.json()?;
    let vault = 1_000_000_000_000_000_000_000_000 - fee(20);

    // 法人帳號消失，撤銷的退款一定失敗
    funder.clone().delete_account(w.merchant.id()).await?.into_result()?;
    w.verifier.call(w.writ.id(), "revoke").args_json(json!({"cell": id, "evidence": "manual"})).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": id})).await?.json()?;
    assert_eq!(c["unclaimed"], vault.to_string());
    assert_eq!(vault_total(&w).await, vault, "a kept refund still counts against the balance");

    // 法人重建帳號後領回
    let funder = root.create_subaccount("corp").initial_balance(NearToken::from_near(3)).keys(funder_sk).transact().await?.into_result()?;
    let before = balance(&funder).await;
    funder.call(w.writ.id(), "claim_refund").args_json(json!({"cell": id})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?.into_result()?;
    assert_eq!(vault_total(&w).await, 0);
    assert!(balance(&funder).await > before + vault / 2, "the refund arrived");
    bench("B15", "NEAR refund fails because the funder account is gone; it is kept, and claimable after the account returns", "refund recovered", "refund recovered", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第六輪：agent 雇 agent，開除一人整棵樹斷電

fn hire_args(agent_pk: &near_workspaces::types::PublicKey, pw: &Payword, scope: &[&AccountId], valid_until: &str, daily: u32, max_links: u32) -> Value {
    json!({"agent_pk": agent_pk, "w0": pw.w0(), "scope": scope, "valid_until": valid_until, "daily_links": daily, "max_links": max_links})
}

async fn hire(agent: &Account, writ: &AccountId, preimage: &str, j: u32, child: Value) -> Value {
    agent.call(writ, "hire").args_json(json!({"preimage": preimage, "j": j, "child": child}))
        .gas(near_workspaces::types::Gas::from_tgas(60)).transact().await.unwrap().into_result().unwrap().json().unwrap()
}

/// 開根格，再雇一個子 agent。回傳 (根 cell, 根 agent, 根鏈, 子 cell, 子 agent, 子鏈, valid_until)
async fn tree(w: &World, links: u32) -> anyhow::Result<(u64, Account, Payword, u64, Account, Payword, String)> {
    let mut o = default_opts(w);
    o.scope = vec![w.merchant.id().clone(), w.verifier.id().clone()];
    o.deposit_near = 5;
    o.n = 40; o.daily = 40;
    o.max_strikes = 0;
    let (cell, agent, pw) = open_cell(w, o).await?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(links);
    let v = hire(&agent, w.writ.id(), &pw.link(links), links, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], &until, 10, 5)).await;
    let child: u64 = v["Hired"]["child"].as_str().unwrap_or_else(|| panic!("{}", v)).parse()?;
    let cagent = Account::from_secret_key(w.writ.id().clone(), sk, &w.worker);
    Ok((cell, agent, pw, child, cagent, cpw, until))
}

#[tokio::test]
async fn b16_agent_hires_a_narrower_agent_that_pays() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw, child, cagent, cpw, _until) = tree(&w, 5).await?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": child.to_string()})).await?.json()?;
    assert_eq!(c["n"], 5);
    assert_eq!(c["vault"], (5 * UNIT).to_string(), "the child holds exactly the links it was given");
    assert_eq!(c["parent"], cell);
    assert_eq!(c["depth"], 1);
    let root: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(root["idx"], 5, "hiring spends the parent's links");
    assert_eq!(root["tree_size"], 2);
    let p: Value = w.writ.view("present").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(p["children"][0], child.to_string());

    let before = balance(&w.merchant).await;
    let v = spend(&cagent, w.writ.id(), &cpw.link(2), 2, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "{}", v);
    assert_eq!(balance(&w.merchant).await - before, 2 * UNIT);

    // 子 agent 付不到上層才有的對手；上層的鏈節對它也沒用
    let v = spend(&cagent, w.writ.id(), &cpw.link(3), 1, w.verifier.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "SCOPE");
    let v = spend(&cagent, w.writ.id(), &pw.link(6), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["solvent"], true);
    let _ = agent;
    bench("B16", "agent hires a sub-agent with a narrower mandate; it pays inside it", "Paid, parent's links spent", "Paid, parent's links spent", 0);
    Ok(())
}

#[tokio::test]
async fn a40_a_hire_can_only_narrow() -> anyhow::Result<()> {
    let w = world().await?;
    let (_cell, agent, pw, child, cagent, cpw, until) = tree(&w, 5).await?;
    let fresh = || SecretKey::from_random(KeyType::ED25519).public_key();
    let np = Payword::new(3);

    // 子 agent 想給孫 agent 自己都沒有的對手
    let v = hire(&cagent, w.writ.id(), &cpw.link(1), 1, hire_args(&fresh(), &Payword::new(1), &[w.verifier.id()], &until, 5, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_SCOPE");
    bench("A40", "sub-agent grants a counterparty it does not have itself", "Rejected:HIRE_SCOPE", "Rejected:HIRE_SCOPE", gain(&w).await);

    // 期限、速率、單筆上限放寬
    let later = (until.parse::<u64>()? + 1).to_string();
    let v = hire(&agent, w.writ.id(), &pw.link(6), 1, hire_args(&fresh(), &np, &[w.merchant.id()], &later, 5, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_TERMS");
    let v = hire(&agent, w.writ.id(), &pw.link(6), 1, hire_args(&fresh(), &np, &[w.merchant.id()], &until, 41, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_TERMS");
    bench("A41", "hire with a later expiry or a higher rate than the parent", "Rejected:HIRE_TERMS", "Rejected:HIRE_TERMS", gain(&w).await);

    // 沒有員工撥的鏈節，雇不到預算
    let forged = hex::encode([9u8; 32]);
    let v = hire(&agent, w.writ.id(), &forged, 3, hire_args(&fresh(), &np, &[w.merchant.id()], &until, 5, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A42", "agent hires with budget the employee never released", "Rejected:CHAIN", "Rejected:CHAIN", gain(&w).await);

    // 陌生格解僱別人的子 agent
    let other = SecretKey::from_random(KeyType::ED25519);
    let mut o = default_opts(&w);
    o.amc_said = "EOTHER".into();
    let _ = (&other, &child);
    let (_c2, stranger, _p2) = open_cell(&w, o).await?;
    let r = stranger.call(w.writ.id(), "dismiss").args_json(json!({"child": child.to_string()})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_PARENT"));
    bench("A43", "an agent dismisses someone else's sub-agent", "NOT_PARENT", "NOT_PARENT", gain(&w).await);

    // 上層可以解僱自己雇的
    agent.call(w.writ.id(), "dismiss").args_json(json!({"child": child.to_string()})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?.into_result()?;
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    assert!(keys.iter().all(|k| k.public_key != cagent.secret_key().public_key()));
    Ok(())
}

#[tokio::test]
async fn a44_the_tree_has_a_depth_and_size_limit() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw, _child, c1, cpw1, until) = tree(&w, 8).await?;
    // 第 2、3 層
    let sk2 = SecretKey::from_random(KeyType::ED25519);
    let pw2 = Payword::new(3);
    let v = hire(&c1, w.writ.id(), &cpw1.link(3), 3, hire_args(&sk2.public_key(), &pw2, &[w.merchant.id()], &until, 5, 2)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let a2 = Account::from_secret_key(w.writ.id().clone(), sk2, &w.worker);
    let sk3 = SecretKey::from_random(KeyType::ED25519);
    let pw3 = Payword::new(2);
    let v = hire(&a2, w.writ.id(), &pw2.link(2), 2, hire_args(&sk3.public_key(), &pw3, &[w.merchant.id()], &until, 5, 1)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let a3 = Account::from_secret_key(w.writ.id().clone(), sk3, &w.worker);
    let v = hire(&a3, w.writ.id(), &pw3.link(1), 1, hire_args(&SecretKey::from_random(KeyType::ED25519).public_key(), &Payword::new(1), &[w.merchant.id()], &until, 1, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_DEPTH");
    bench("A44", "chain of hires past the depth limit", "Rejected:HIRE_DEPTH", "Rejected:HIRE_DEPTH", gain(&w).await);

    // 根格一直雇到上限（目前 4 格）
    let mut k = 9;
    let mut last = Value::Null;
    for _ in 0..13 {
        let cp = Payword::new(1);
        last = hire(&agent, w.writ.id(), &pw.link(k), 1, hire_args(&SecretKey::from_random(KeyType::ED25519).public_key(), &cp, &[w.merchant.id()], &until, 1, 1)).await;
        if last.get("Hired").is_some() { k += 1; }
    }
    assert_eq!(last["Rejected"]["reason"], "HIRE_TREE", "{}", last);
    let root: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(root["tree_size"], 16);
    bench("A45", "hires past the tree size limit", "Rejected:HIRE_TREE", "Rejected:HIRE_TREE", gain(&w).await);

    // 滿編的樹一筆交易全部關掉
    let keys_before = w.worker.view_access_keys(w.writ.id()).await?.len();
    let funder_before = balance(&w.funder).await;
    let out = w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "employee left"}))
        .gas(near_workspaces::types::Gas::from_tgas(300)).transact().await?;
    let burnt = out.total_gas_burnt.as_tgas();
    out.into_result()?;
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    assert_eq!(keys_before - keys.len(), 16, "all 16 keys gone in one transaction");
    assert!(balance(&w.funder).await > funder_before, "the money went back to the legal entity");
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["vault_total"], "0");
    let st: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(st["revoked"], 16);
    println!("WRIT_GAS|revoke_tree_16={}", burnt);
    bench("B17", "one revocation closes a full tree of 16 agents in one transaction", "16 keys deleted", &format!("16 keys deleted, {} Tgas", burnt), 0);
    Ok(())
}

/// 主秀：HR 撤銷員工的 ECR，整棵樹斷電。fixtures 是真 keripy 事件。
#[tokio::test]
async fn b18_hr_fires_one_employee_and_the_whole_tree_goes_dark() -> anyhow::Result<()> {
    let w = world().await?;
    let v: Value = serde_json::from_str(&std::fs::read_to_string("tests/fixtures/vectors.json")?)?;
    let e = &v["ecr_revocation"];
    let (le_aid, le_pk, ecr_said) = (e["le_aid"].as_str().unwrap(), e["le_pk_hex"].as_str().unwrap(), e["ecr_said"].as_str().unwrap());
    let mut o = default_opts(&w);
    o.amc_said = v["amc"]["said"].as_str().unwrap().into();
    o.issuer_pk = v["issuer"]["pk_hex"].as_str().unwrap().into();
    o.issuer_aid = v["issuer"]["aid"].as_str().unwrap().into();
    o.ecr_commit = hex::encode(Sha256::digest(format!("{}|{}|{}|{}", le_aid, le_pk, ecr_said, ECR_COMMIT_SALT)));
    o.deposit_near = 5;
    let (cell, agent, pw) = open_cell(&w, o).await?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let sk1 = SecretKey::from_random(KeyType::ED25519);
    let pw1 = Payword::new(4);
    let v1 = hire(&agent, w.writ.id(), &pw.link(4), 4, hire_args(&sk1.public_key(), &pw1, &[w.merchant.id()], &until, 5, 4)).await;
    let c1: String = v1["Hired"]["child"].as_str().unwrap().to_string();
    let a1 = Account::from_secret_key(w.writ.id().clone(), sk1, &w.worker);
    let sk2 = SecretKey::from_random(KeyType::ED25519);
    let pw2 = Payword::new(2);
    let v2 = hire(&a1, w.writ.id(), &pw1.link(2), 2, hire_args(&sk2.public_key(), &pw2, &[w.merchant.id()], &until, 5, 2)).await;
    let c2: String = v2["Hired"]["child"].as_str().unwrap().to_string();
    let a2 = Account::from_secret_key(w.writ.id().clone(), sk2, &w.worker);
    assert!(spend(&a2, w.writ.id(), &pw2.link(1), 1, w.merchant.id()).await.unwrap().get("Paid").is_some());

    let b64 = |h: &str| near_sdk::base64::Engine::encode(&near_sdk::base64::prelude::BASE64_STANDARD, hex::decode(h).unwrap());
    w.merchant.call(w.writ.id(), "revoke_by_kel").args_json(json!({"cell": cell.to_string(), "ixn": b64(e["raw_hex"].as_str().unwrap()), "signature": b64(e["sig_hex"].as_str().unwrap()), "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": ECR_COMMIT_SALT}}))
        .gas(near_workspaces::types::Gas::from_tgas(200)).transact().await?.into_result()?;
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    for a in [&agent, &a1, &a2] {
        assert!(keys.iter().all(|k| k.public_key != a.secret_key().public_key()), "every key in the tree is gone");
    }
    for k in [c1.as_str(), c2.as_str()] {
        let c: Value = w.writ.view("get_cell").args_json(json!({"cell": k})).await?.json()?;
        assert!(c["status"]["Revoked"]["evidence"].as_str().unwrap().contains("closed"), "{}", c["status"]);
        assert_eq!(c["vault"], "0");
    }
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["vault_total"], "0", "all vaults returned");
    let err = spend(&a2, w.writ.id(), &pw2.link(2), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&err), "AccessKeyNotFound");
    bench("B18", "HR revokes one employee's ECR; the agent, its sub-agent and sub-sub-agent all lose their keys", "3 keys deleted by one signed event", "3 keys deleted by one signed event", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第七輪：Who pays is named before the agent buys

const LEI: &str = "WRITDEMO000000000017";
const LEI_SALT: &str = "salt-lei";
const SEC: u64 = 1_000_000_000;

struct CreditWorld {
    w: World,
    cell: u64,
    agent: Account,
    pw: Payword,
    arbiter: Account,
    le: SigningKey,
    le_aid: String,
    ecr_said: String,
}

/// 短時間窗的合約，一棵可賒帳的格。保證人質押 stake NEAR。金庫 30 節。
async fn credit_world(bond_bps: u32, stake: u128, grace: u64, recourse: u64) -> anyhow::Result<CreditWorld> {
    credit_world_with(bond_bps, stake, grace, recourse, 30 * UNIT, LEI).await
}

/// vault：開格後的金庫（yocto）。committed_lei：驗證者承諾的 LEI（測栽贓時和 LE 簽的不同）。
async fn credit_world_with(bond_bps: u32, stake: u128, grace: u64, recourse: u64, vault: u128, committed_lei: &str) -> anyhow::Result<CreditWorld> {
    credit_world_full(bond_bps, stake, grace, recourse, vault, committed_lei, 0).await
}

async fn credit_world_full(bond_bps: u32, stake: u128, grace: u64, recourse: u64, vault: u128, committed_lei: &str, inspect: u64) -> anyhow::Result<CreditWorld> {
    credit_world_fee(bond_bps, 0, stake, grace, recourse, vault, committed_lei, inspect).await
}

#[allow(clippy::too_many_arguments)]
async fn credit_world_fee(bond_bps: u32, premium_bps: u32, stake: u128, grace: u64, recourse: u64, vault: u128, committed_lei: &str, inspect: u64) -> anyhow::Result<CreditWorld> {
    credit_world_x(CwOpts { bond: bond_bps, premium: premium_bps, stake, grace, recourse, vault, lei: committed_lei.to_string(), inspect, ..Default::default() }).await
}

/// 信用世界的所有選項。預設：沒保證金、沒費用、質押 5 NEAR、金庫 30 節。
struct CwOpts { bond: u32, premium: u32, stake: u128, grace: u64, recourse: u64, vault: u128, lei: String, inspect: u64, max_tenor: u64 }
impl Default for CwOpts {
    fn default() -> Self {
        Self { bond: 0, premium: 0, stake: 5, grace: 0, recourse: 1, vault: 30 * UNIT, lei: LEI.to_string(), inspect: 0, max_tenor: 3600 }
    }
}

async fn credit_world_x(x: CwOpts) -> anyhow::Result<CreditWorld> {
    let CwOpts { bond: bond_bps, premium: premium_bps, stake, grace, recourse, vault, lei: committed_lei, inspect, max_tenor } = x;
    let worker = near_workspaces::sandbox().await?;
    let writ = worker.dev_deploy(&wasm_bytes()?).await?;
    writ.call("new").args_json(json!({"owner": writ.id(), "unseal_delay_secs": 5,
        "windows": {"accept_ttl": "2", "inspect": inspect.to_string(), "grace": grace.to_string(), "recourse": recourse.to_string(), "dispute_timeout": "2", "unstake_delay": "1"}}))
        .transact().await?.into_result()?;
    let verifier = worker.dev_create_account().await?;
    let funder = worker.dev_create_account().await?;
    let merchant = worker.dev_create_account().await?;
    let attacker = worker.dev_create_account().await?;
    let arbiter = worker.dev_create_account().await?;
    let verifier_sk = SigningKey::generate(&mut rand::thread_rng());
    writ.call("set_verifier").args_json(json!({"account": verifier.id(), "pk_hex": hex::encode(verifier_sk.verifying_key().to_bytes())})).transact().await?.into_result()?;
    if stake > 0 {
        verifier.call(writ.id(), "stake").deposit(NearToken::from_near(stake)).transact().await?.into_result()?;
    }
    let attacker_start = balance(&attacker).await;
    let w = World { worker, writ, verifier, verifier_sk, funder, merchant, attacker, attacker_start };

    let le = SigningKey::generate(&mut rand::thread_rng());
    let le_pk = hex::encode(le.verifying_key().to_bytes());
    let (le_aid, ecr_said) = ("ELE_AID".to_string(), "EECR_SAID".to_string());
    let mut o = default_opts(&w);
    o.amc_said = "EAMC_CREDIT".into();
    o.scope = vec![w.merchant.id().clone(), w.verifier.id().clone(), w.funder.id().clone()];
    o.ecr_commit = hex::encode(Sha256::digest(format!("{}|{}|{}|{}", le_aid, le_pk, ecr_said, ECR_COMMIT_SALT)));
    o.max_links = 10;
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(o.n);
    let until = now_ns(&w).await? + 3_600 * SEC;
    let terms_hash = hex::encode([0xabu8; 32]);
    let msg = format!("writ:terms:v1\ncontract={}\namc={}\nterms={}\nlei={}", w.writ.id(), o.amc_said, terms_hash, LEI);
    let terms_sig = hex::encode(le.sign(msg.as_bytes()).to_bytes());
    let mut args = json!({
        "amc_said": o.amc_said, "issuer_aid": o.issuer_aid, "issuer_pk": o.issuer_pk, "max_links": o.max_links, "max_strikes": o.max_strikes,
        "attested_at": ATTESTED_NOW.to_string(), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": o.n, "unit": o.unit.to_string(),
        "scope": o.scope, "valid_until": until.to_string(), "daily_links": o.daily,
        "lei_commit": hex::encode(Sha256::digest(format!("{}|{}", committed_lei, LEI_SALT))), "ecr_commit": o.ecr_commit, "verifier": w.verifier.id(),
        "credit": {"limit": (10 * UNIT).to_string(), "bond_bps": bond_bps, "premium_bps": premium_bps, "min_tenor": "0", "max_tenor": max_tenor.to_string(), "terms_hash": terms_hash,
                   "terms_sig": terms_sig, "entity_tag": "ENTITY-7", "arbiter": arbiter.id()},
    });
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let id: String = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_yoctonear(fee(20) + vault)).max_gas().transact().await?.into_result()?.json()?;
    let agent = Account::from_secret_key(w.writ.id().clone(), agent_sk, &w.worker);
    Ok(CreditWorld { w, cell: id.parse()?, agent, pw, arbiter, le, le_aid, ecr_said })
}

impl CreditWorld {
    async fn open(&self, link: u32, j: u32, due_in: u64, inv: &str) -> Value {
        let due = now_ns(&self.w).await.unwrap() + due_in * SEC;
        self.agent.call(self.w.writ.id(), "open_credit").args_json(json!({"preimage": self.pw.link(link), "j": j, "to": self.w.merchant.id(), "invoice_hash": hex::encode(Sha256::digest(inv)), "due_at": due.to_string()}))
            .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await.unwrap().into_result().unwrap().json().unwrap()
    }
    async fn seller(&self, method: &str, args: Value) -> Result<(), String> {
        let r = self.w.merchant.call(self.w.writ.id(), method).args_json(args).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await.map_err(|e| e.to_string())?;
        r.into_result().map(|_| ()).map_err(|e| format!("{:?}", e))
    }
    async fn opened(&self, link: u32, j: u32, due_in: u64, inv: &str) -> String {
        let v = self.open(link, j, due_in, inv).await;
        v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string()
    }
    async fn delivered(&self, link: u32, j: u32, due_in: u64, inv: &str) -> String {
        let id = self.opened(link, j, due_in, inv).await;
        self.seller("accept_credit", json!({"credit": id})).await.unwrap();
        self.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
        id
    }
    async fn credit(&self, id: &str) -> Value {
        self.w.writ.view("credit_of").args_json(json!({"credit": id})).await.unwrap().json().unwrap()
    }
    async fn solvent(&self) -> Value {
        self.w.writ.view("solvency").await.unwrap().json().unwrap()
    }
}
async fn wait_secs(s: u64) { tokio::time::sleep(std::time::Duration::from_secs(s)).await; }

#[tokio::test]
async fn b19_buy_on_credit_pay_on_time_identity_stays_sealed() -> anyhow::Result<()> {
    let cw = credit_world(5000, 5, 0, 1).await?;
    let w = &cw.w;
    let card: Value = w.writ.view("risk_card").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert_eq!(card["legal_entity"], "sealed");
    assert_eq!(card["guarantor"], w.verifier.id().as_str());
    assert_eq!(card["bond_bps"], 5000);
    assert_ne!(card["first_seen"], "0", "the record starts when the company registers");
    let id = cw.delivered(3, 3, 3600, "INV-A").await;
    let c = cw.credit(&id).await;
    assert_eq!(c["bond_locked"], (UNIT * 3 / 2).to_string());
    assert_eq!(c["exposure"], (UNIT * 3 - UNIT * 3 / 2).to_string());
    let merchant0 = balance(&w.merchant).await;
    let v: Value = cw.agent.call(w.writ.id(), "settle").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert!(v.get("CreditSettled").is_some(), "{}", v);
    cw.seller("withdraw", json!({})).await.unwrap();
    assert!(balance(&w.merchant).await - merchant0 > 2 * UNIT, "the seller got paid");
    let card: Value = w.writ.view("risk_card").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert_eq!(card["legal_entity"], "sealed", "paying on time reveals nothing");
    assert_eq!(card["settled"], 1);
    assert_eq!(card["outstanding"], "0");
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], "0");
    let rcpt: Value = w.writ.view("liability_receipt").args_json(json!({"credit": id})).await?.json()?;
    assert_eq!(rcpt["agent_path"][0], cw.cell.to_string());
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B19", "agent buys on credit, seller delivers, company pays on time", "paid, identity sealed", "paid, identity sealed", 0);
    Ok(())
}

impl CreditWorld {
    fn opening(&self) -> Value {
        json!({"le_aid": self.le_aid, "le_pk": hex::encode(self.le.verifying_key().to_bytes()), "ecr_said": self.ecr_said, "salt": ECR_COMMIT_SALT})
    }
    async fn card(&self) -> Value {
        self.w.writ.view("risk_card").args_json(json!({"cell": self.cell.to_string()})).await.unwrap().json().unwrap()
    }
    async fn guarantor(&self, method: &str, args: Value) -> Result<(), String> {
        let r = self.w.verifier.call(self.w.writ.id(), method).args_json(args).gas(near_workspaces::types::Gas::from_tgas(150)).transact().await.map_err(|e| e.to_string())?;
        r.into_result().map(|_| ()).map_err(|e| format!("{:?}", e))
    }
    async fn funder(&self, method: &str, args: Value, deposit: u128) -> Result<(), String> {
        let r = self.w.funder.call(self.w.writ.id(), method).args_json(args).deposit(NearToken::from_yoctonear(deposit)).gas(near_workspaces::types::Gas::from_tgas(150)).transact().await.map_err(|e| e.to_string())?;
        r.into_result().map(|_| ()).map_err(|e| format!("{:?}", e))
    }
}

#[tokio::test]
async fn b20_default_covered_by_the_vault_stays_sealed() -> anyhow::Result<()> {
    let cw = credit_world(0, 5, 0, 2).await?;
    let later = cw.delivered(1, 1, 3600, "INV-LATER").await;
    let e = cw.seller("claim_default", json!({"credit": later})).await.unwrap_err();
    assert!(e.contains("NOT_DUE"), "{}", e);
    let id = cw.delivered(4, 3, 1, "INV-D").await;
    bench("A46", "seller claims default before the due date", "NOT_DUE", "NOT_DUE", gain(&cw.w).await);
    wait_secs(2).await;
    let r = cw.w.attacker.call(cw.w.writ.id(), "claim_default").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("ONLY_SELLER"));
    bench("A47", "stranger claims someone else's default", "ONLY_SELLER", "ONLY_SELLER", gain(&cw.w).await);
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let c = cw.credit(&id).await;
    assert_eq!(c["status"], "Defaulted");
    assert_eq!(c["debt"], "0", "the vault paid first");
    let card = cw.card().await;
    assert_eq!(card["defaults"], 1, "the default stays on the entity's record");
    assert_eq!(card["legal_entity"], "sealed");
    assert_eq!(card["frozen"], false);
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B20", "default covered by the company's own vault: seller paid, on the record, identity sealed", "paid, sealed", "paid, sealed", 0);
    Ok(())
}

#[tokio::test]
async fn b21_guarantor_pays_then_recourse_tree_dies_identity_revealed() -> anyhow::Result<()> {
    // 金庫只有 2 節，賣 5 節：賠付一定走到保證人
    let cw = credit_world_with(0, 5, 0, 2, 2 * UNIT, LEI).await?;
    let w = &cw.w;
    let id = cw.delivered(5, 5, 1, "INV-G").await;
    wait_secs(2).await;
    let stake0: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let c = cw.credit(&id).await;
    let debt: u128 = c["debt"].as_str().unwrap().parse()?;
    assert!(debt > 0, "the guarantor paid part of it: {}", c);
    let stake1: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(stake0["amount"].as_str().unwrap().parse::<u128>()? - stake1["amount"].as_str().unwrap().parse::<u128>()?, debt);
    let m0 = balance(&w.merchant).await;
    cw.seller("withdraw", json!({})).await.unwrap();
    assert!(balance(&w.merchant).await - m0 > 4 * UNIT, "the seller got the whole amount");
    bench("B21", "company does not pay; the named guarantor's stake covers the seller, no approval needed", "seller paid in full", "seller paid in full", 0);

    // 只凍結，不斷電；身分還封著
    let card = cw.card().await;
    assert_eq!(card["frozen"], true);
    assert_eq!(card["legal_entity"], "sealed");
    let v = cw.open(6, 1, 3600, "INV-AFTER").await;
    assert_eq!(v["Rejected"]["reason"], "FROZEN");
    bench("A48", "frozen company keeps buying on credit", "Rejected:FROZEN", "Rejected:FROZEN", gain(w).await);
    let e = cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("RECOURSE_OPEN"), "{}", e);
    bench("A49", "guarantor cuts the power before the recourse period ends", "RECOURSE_OPEN", "RECOURSE_OPEN", gain(w).await);
    let e = cw.guarantor("credit_unseal", json!({"credit": id, "lei": LEI, "salt": LEI_SALT, "ecr": cw.opening()})).await.unwrap_err();
    assert!(e.contains("NOT_ENFORCED"), "{}", e);
    bench("A50", "guarantor reveals the company before enforcement", "NOT_ENFORCED", "NOT_ENFORCED", gain(w).await);

    wait_secs(3).await;
    let keys0 = w.worker.view_access_keys(w.writ.id()).await?.len();
    cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    assert_eq!(keys0 - w.worker.view_access_keys(w.writ.id()).await?.len(), 1, "the tree's key is gone");

    // owner 把保證人移出白名單，也擋不了揭露
    w.writ.call("set_verifier").args_json(json!({"account": w.verifier.id()})).transact().await?.into_result()?;
    let e = cw.guarantor("credit_unseal", json!({"credit": id, "lei": "WRITDEMO999999999999", "salt": LEI_SALT, "ecr": cw.opening()})).await.unwrap_err();
    assert!(e.contains("COMMIT_MISMATCH"), "{}", e);
    cw.guarantor("credit_unseal", json!({"credit": id, "lei": LEI, "salt": LEI_SALT, "ecr": cw.opening()})).await.unwrap();
    assert_eq!(cw.card().await["legal_entity"], LEI);
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B22", "recourse period ends unpaid: the whole tree loses its keys and the company is named", "key deleted, LEI public", "key deleted, LEI public", 0);
    Ok(())
}

#[tokio::test]
async fn b23_company_reimburses_guarantor_and_stays_sealed() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 1, 2 * UNIT, LEI).await?;
    let id = cw.delivered(5, 5, 1, "INV-R").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let debt: u128 = cw.credit(&id).await["debt"].as_str().unwrap().parse()?;
    let e = cw.funder("reimburse", json!({"credit": id}), debt - 1).await.unwrap_err();
    assert!(e.contains("PAY_FULL_DEBT"), "{}", e);
    cw.funder("reimburse", json!({"credit": id}), debt).await.unwrap();
    let card = cw.card().await;
    assert_eq!(card["frozen"], false);
    assert_eq!(card["legal_entity"], "sealed");
    let e = cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("NO_DEBT"), "{}", e);
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B23", "company repays the guarantor in time: unfrozen, identity stays sealed", "sealed", "sealed", 0);
    Ok(())
}

#[tokio::test]
async fn a51_revoking_does_not_escape_a_debt() -> anyhow::Result<()> {
    let cw = credit_world(0, 5, 0, 1).await?;
    let w = &cw.w;
    let id = cw.delivered(3, 3, 1, "INV-X").await;
    let f0 = balance(&w.funder).await;
    cw.funder("revoke", json!({"cell": cw.cell.to_string(), "evidence": "skip town"}), 0).await.unwrap();
    assert!(balance(&w.funder).await < f0, "nothing was refunded while a debt is open");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert!(c["vault"].as_str().unwrap().parse::<u128>()? >= 3 * UNIT, "the vault stays to cover the debt");
    bench("A51", "company revokes its own agent to walk away from a debt and take the vault", "vault kept", "vault kept", gain(w).await);
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["debt"], "0", "the kept vault paid the seller");
    // 結清後，餘額可領回
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert!(c["unclaimed"].as_str().unwrap().parse::<u128>()? > 0, "{}", c);
    let f1 = balance(&w.funder).await;
    cw.funder("claim_refund", json!({"cell": cw.cell.to_string()}), 0).await.unwrap();
    assert!(balance(&w.funder).await > f1, "the rest returned once nothing is owed");
    assert_eq!(cw.solvent().await["vault_total"].as_str().unwrap().parse::<u128>()?, 5_000_000_000_000_000_000_000_000u128 + 3 * UNIT, "only the stake and the seller's unwithdrawn payment are left");
    bench("B24", "employee fired with a debt open: the debt stands, the rest is returned afterwards", "seller paid, refund after", "seller paid, refund after", 0);
    Ok(())
}

#[tokio::test]
async fn a52_seller_side_attacks() -> anyhow::Result<()> {
    let cw = credit_world(0, 5, 0, 1).await?;
    let w = &cw.w;
    // 沒交貨就告違約
    let id = cw.opened(1, 1, 1, "INV-N").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    let e = cw.seller("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("NOT_DELIVERED"), "{}", e);
    bench("A52", "seller claims default without delivering", "NOT_DELIVERED", "NOT_DELIVERED", gain(w).await);

    // 公司付了款，賣方刪帳號或不提領：也不能再告違約
    cw.funder("settle_by_funder", json!({"credit": id}), 0).await.unwrap();
    let e = cw.seller("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("NOT_DELIVERED"), "{}", e);
    assert_eq!(cw.credit(&id).await["status"], "Settled");
    bench("A53", "seller refuses the money, then claims default anyway", "settled on the ledger", "settled on the ledger", gain(w).await);

    // 爭議要附全額押金；有押金就不能告違約；只有仲裁人能裁
    let id = cw.delivered(3, 2, 1, "INV-P").await;
    let e = cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), UNIT).await.unwrap_err();
    assert!(e.contains("ESCROW_FULL_AMOUNT"), "{}", e);
    bench("A54", "company disputes for free to stall a debt", "ESCROW_FULL_AMOUNT", "ESCROW_FULL_AMOUNT", gain(w).await);
    cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), 2 * UNIT).await.unwrap();
    wait_secs(2).await;
    let e = cw.seller("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("NOT_DELIVERED"), "{}", e);
    let e = cw.guarantor("resolve_dispute", json!({"credit": id, "to_seller": false})).await.unwrap_err();
    assert!(e.contains("ONLY_ARBITER"), "{}", e);
    bench("A55", "guarantor decides a dispute it has money in", "ONLY_ARBITER", "ONLY_ARBITER", gain(w).await);
    cw.arbiter.call(w.writ.id(), "resolve_dispute").args_json(json!({"credit": id, "to_seller": true})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    assert_eq!(cw.credit(&id).await["status"], "Settled");

    // 仲裁人逾時：有交貨憑據給賣方
    let id = cw.delivered(4, 1, 1, "INV-Q").await;
    cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), UNIT).await.unwrap();
    let e = cw.seller("resolve_timeout", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("ARBITER_STILL_HAS_TIME"), "{}", e);
    wait_secs(3).await;
    cw.seller("resolve_timeout", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Settled");

    // 沒人接受的單會過期，額度放回
    let id = cw.opened(5, 1, 3600, "INV-T").await;
    wait_secs(3).await;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("OFFER_EXPIRED"), "{}", e);
    cw.seller("cancel_open", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Cancelled");
    assert_eq!(cw.card().await["outstanding"], "0");
    bench("B25", "dispute with full escrow, arbiter and timeout paths; unaccepted offers expire", "resolved", "resolved", 0);
    Ok(())
}

#[tokio::test]
async fn a56_bond_is_locked_per_credit_and_cannot_be_raced() -> anyhow::Result<()> {
    // 金庫 4.x 節，保證金 100%：兩筆各鎖 2 節。串通的賣方先告違約，只能動到自己那筆的保證金
    let cw = credit_world_with(10_000, 5, 0, 1, 5 * UNIT, LEI).await?;
    let first = cw.delivered(2, 2, 3600, "INV-1").await;
    let second = cw.delivered(4, 2, 1, "INV-2").await;
    let c1 = cw.credit(&first).await;
    assert_eq!(c1["bond_locked"], (2 * UNIT).to_string());
    let c2 = cw.credit(&second).await;
    assert_eq!(c2["bond_locked"], (2 * UNIT).to_string());
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": second})).await.unwrap();
    assert_eq!(cw.credit(&second).await["debt"], "0", "its own bond covered it");
    let c: Value = cw.w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert!(c["vault"].as_str().unwrap().parse::<u128>()? >= 2 * UNIT, "the first seller's locked bond was not touched: {}", c["vault"]);
    bench("A56", "a colluding seller defaults first to drain the bond another seller relies on", "first seller's bond intact", "first seller's bond intact", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a79_a_bond_the_company_cannot_fund_is_refused() -> anyhow::Result<()> {
    // 金庫 3 節，保證金 100%：第一筆鎖 2 節，第二筆鎖不到 2 節。以前差額會靜默轉給保證人
    let cw = credit_world_with(10_000, 5, 0, 1, 3 * UNIT, LEI).await?;
    let first = cw.delivered(2, 2, 3600, "INV-1").await;
    assert_eq!(cw.credit(&first).await["bond_locked"], (2 * UNIT).to_string());
    let second = cw.opened(4, 2, 3600, "INV-2").await;
    let e = cw.seller("accept_credit", json!({"credit": second})).await.unwrap_err();
    assert!(e.contains("BOND_SHORT"), "{}", e);
    assert_eq!(cw.credit(&second).await["status"], "Open");
    let st: Value = cw.w.writ.view("stake_of").args_json(json!({"account": cw.w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], "0", "nothing moved to the guarantor");
    bench("A79", "company with a thin vault gets an order accepted with less bond than the risk card says", "BOND_SHORT", "BOND_SHORT", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a57_order_limits_and_guarantor_rules() -> anyhow::Result<()> {
    let cw = credit_world(0, 0, 0, 1).await?;
    let w = &cw.w;
    // 到期日短到沒時間反應
    let due = now_ns(w).await? - 5 * SEC;
    let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(1), "j": 1, "to": w.merchant.id(), "invoice_hash": hex::encode([3u8; 32]), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["Rejected"]["reason"], "TENOR");
    bench("A57", "injected order with a due date outside the agreed terms", "Rejected:TENOR", "Rejected:TENOR", gain(w).await);
    // 注入付給攻擊者
    let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(1), "j": 1, "to": w.attacker.id(), "invoice_hash": hex::encode([4u8; 32]), "due_at": (now_ns(w).await? + 3000 * SEC).to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["Rejected"]["reason"], "SCOPE");
    bench("A58", "injected order to a seller outside the mandate", "Rejected:SCOPE", "Rejected:SCOPE", gain(w).await);
    // 保證人沒押錢就接不了
    let id = cw.opened(1, 1, 3600, "INV-S").await;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("GUARANTOR_CAPACITY"), "{}", e);
    bench("A59", "seller accepts an order the guarantor has no stake to back", "GUARANTOR_CAPACITY", "GUARANTOR_CAPACITY", gain(w).await);
    // 有曝險不能抽走質押
    cw.w.verifier.call(w.writ.id(), "stake").deposit(NearToken::from_near(1)).transact().await?.into_result()?;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    cw.guarantor("request_unstake", json!({})).await.unwrap();
    wait_secs(2).await;
    let e = cw.guarantor("withdraw_stake", json!({"amount": "1000000000000000000000000"})).await.unwrap_err();
    assert!(e.contains("STAKE_EXPOSED"), "{}", e);
    bench("A60", "guarantor pulls its stake while it has exposure", "STAKE_EXPOSED", "STAKE_EXPOSED", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a61_guarantor_cannot_frame_another_company() -> anyhow::Result<()> {
    // 驗證者承諾的是受害公司的 LEI，LE 簽的是真公司的
    let victim = "VICTIMCO000000000099";
    let cw = credit_world_with(0, 5, 0, 1, 2 * UNIT, victim).await?;
    let id = cw.delivered(5, 5, 1, "INV-F").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    let e = cw.guarantor("credit_unseal", json!({"credit": id, "lei": victim, "salt": LEI_SALT, "ecr": cw.opening()})).await.unwrap_err();
    assert!(e.contains("LE_DID_NOT_SIGN"), "{}", e);
    assert_eq!(cw.card().await["legal_entity"], "sealed");
    bench("A61", "guarantor commits to another company's LEI, without that company's key, and reveals it", "LE_DID_NOT_SIGN", "LE_DID_NOT_SIGN", gain(&cw.w).await);
    Ok(())
}

// ---------------------------------------------------------------- 第八輪：獨立審計找到的問題

#[tokio::test]
async fn a62_the_audit_findings_stay_fixed() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw, child, cagent, cpw, until) = tree(&w, 5).await?;

    // F1／F2：重複帳號灌爆 scope，讓撤銷永遠失敗
    let many: Vec<&AccountId> = std::iter::repeat(w.merchant.id()).take(17).collect();
    let v = hire(&agent, w.writ.id(), &pw.link(6), 1, hire_args(&SecretKey::from_random(KeyType::ED25519).public_key(), &Payword::new(1), &many, &until, 1, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_SCOPE");
    bench("A62", "hire with a huge duplicated scope, to make the tree too expensive to revoke", "Rejected:HIRE_SCOPE", "Rejected:HIRE_SCOPE", gain(&w).await);

    // F7：父子各付同一張發票
    let inv = b"INV-SHARED";
    let v = spend_invoice(&agent, w.writ.id(), &pw.link(6), 1, w.merchant.id(), inv).await;
    assert!(v.get("Paid").is_some(), "{}", v);
    let v = spend_invoice(&cagent, w.writ.id(), &cpw.link(1), 1, w.merchant.id(), inv).await;
    assert_eq!(v["Rejected"]["reason"], "DUPLICATE");
    bench("A63", "parent and sub-agent each pay the same invoice", "Rejected:DUPLICATE", "Rejected:DUPLICATE", gain(&w).await);

    // F5：被解僱的鑰匙再被雇用
    agent.call(w.writ.id(), "dismiss").args_json(json!({"child": child.to_string()})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?.into_result()?;
    let v = hire(&agent, w.writ.id(), &pw.link(7), 1, hire_args(&cagent.secret_key().public_key(), &Payword::new(1), &[w.merchant.id()], &until, 1, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_KEY");
    bench("A64", "a dismissed key is hired again", "Rejected:HIRE_KEY", "Rejected:HIRE_KEY", gain(&w).await);
    let _ = cell;
    Ok(())
}

#[tokio::test]
async fn a65_a_tripped_parent_suspends_its_sub_agents() -> anyhow::Result<()> {
    let w = world().await?;
    let mut o = default_opts(&w);
    o.deposit_near = 3;
    let (cell, agent, pw) = open_cell(&w, o).await?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(4);
    let v = hire(&agent, w.writ.id(), &pw.link(4), 4, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], &until, 4, 2)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let cagent = Account::from_secret_key(w.writ.id().clone(), sk, &w.worker);
    for _ in 0..3 {
        spend(&agent, w.writ.id(), &pw.link(5), 1, w.attacker.id()).await.unwrap();
    }
    let v = spend(&cagent, w.writ.id(), &cpw.link(1), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "SUSPENDED");
    bench("A65", "parent is tripped; its sub-agent keeps spending", "Rejected:SUSPENDED", "Rejected:SUSPENDED", gain(&w).await);
    w.funder.call(w.writ.id(), "reinstate").args_json(json!({"cell": cell.to_string()})).deposit(NearToken::from_millinear(250)).max_gas().transact().await?.into_result()?;
    let v = spend(&cagent, w.writ.id(), &cpw.link(1), 1, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "reinstating the parent restores the tree: {}", v);
    bench("B26", "funder reinstates a tripped parent: its sub-agents work again", "Paid", "Paid", 0);
    Ok(())
}

#[tokio::test]
async fn a66_the_agent_cannot_spend_a_locked_bond() -> anyhow::Result<()> {
    let cw = credit_world_with(10_000, 5, 0, 1, 5 * UNIT, LEI).await?;
    let w = &cw.w;
    let id = cw.delivered(3, 3, 3600, "INV-B").await;
    assert_eq!(cw.credit(&id).await["bond_locked"], (3 * UNIT).to_string());
    // 金庫 4.5 節，3 節鎖給賣方：只能動 1.5 節
    let v = spend(&cw.agent, w.writ.id(), &cw.pw.link(5), 2, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS");
    bench("A66", "agent spends the bond locked for a seller", "Rejected:FUNDS", "Rejected:FUNDS", gain(w).await);
    Ok(())
}

// ---------------------------------------------------------------- 第九輪：信用合約審計

#[tokio::test]
async fn a67_offers_die_with_the_mandate() -> anyhow::Result<()> {
    let cw = credit_world(0, 5, 0, 1).await?;
    let id = cw.opened(1, 1, 3600, "INV-OFFER").await;
    cw.funder("revoke", json!({"cell": cw.cell.to_string(), "evidence": "fired"}), 0).await.unwrap();
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("AGENT_NOT_ACTIVE"), "{}", e);
    bench("A67", "seller accepts an order after the company revoked the agent, on the guarantor's money", "AGENT_NOT_ACTIVE", "AGENT_NOT_ACTIVE", gain(&cw.w).await);
    cw.funder("cancel_open", json!({"credit": id}), 0).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Cancelled");
    assert_eq!(cw.card().await["outstanding"], "0");
    Ok(())
}

#[tokio::test]
async fn a68_a_seller_cannot_deliver_and_default_at_once() -> anyhow::Result<()> {
    let cw = credit_world_full(0, 5, 0, 1, 30 * UNIT, LEI, 60).await?;
    let id = cw.opened(1, 1, 1, "INV-RUSH").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
    let e = cw.seller("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("INSPECTION_OPEN"), "{}", e);
    bench("A68", "seller marks delivery and claims default together, leaving no time to dispute", "INSPECTION_OPEN", "INSPECTION_OPEN", gain(&cw.w).await);
    // 公司搶先爭議，賣方仍能留下交貨憑據；逾時歸賣方
    let cw = credit_world(0, 5, 0, 1).await?;
    let id2 = cw.opened(1, 1, 3600, "INV-RACE").await;
    cw.seller("accept_credit", json!({"credit": id2})).await.unwrap();
    cw.funder("dispute", json!({"credit": id2, "reason_hash": hex::encode([2u8; 32])}), UNIT).await.unwrap();
    cw.seller("mark_delivered", json!({"credit": id2, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
    wait_secs(3).await;
    cw.seller("resolve_timeout", json!({"credit": id2})).await.unwrap();
    assert_eq!(cw.credit(&id2).await["status"], "Settled");
    bench("A69", "company disputes first so the seller cannot record delivery", "delivery recorded, seller paid", "delivery recorded, seller paid", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a70_money_hidden_in_a_sub_agent_goes_to_the_debt_first() -> anyhow::Result<()> {
    // 根格金庫大多搬給子 agent，賴帳後公司想靠斷電把子格的錢領回
    let cw = credit_world_with(0, 5, 0, 1, 17 * UNIT, LEI).await?;
    let w = &cw.w;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(9);
    // 3 節給子 agent，加上雇用費，根格只剩一點點
    let v = hire(&cw.agent, w.writ.id(), &cw.pw.link(3), 3, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], &until, 3, 3)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let id = cw.delivered(5, 2, 1, "INV-HIDE").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let debt: u128 = cw.credit(&id).await["debt"].as_str().unwrap().parse()?;
    assert!(debt > 0, "the guarantor had to pay");
    wait_secs(2).await;
    let st0: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    let f0 = balance(&w.funder).await;
    cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    assert!(balance(&w.funder).await <= f0, "the company got nothing back while it owes");
    let c = cw.credit(&id).await;
    assert_eq!(c["debt"], "0", "the sub-agent's money repaid the guarantor: {}", c);
    assert_eq!(c["status"], "Reimbursed", "repaid in full, so no reason to reveal the company");
    let st1: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st1["amount"].as_str().unwrap().parse::<u128>()? - st0["amount"].as_str().unwrap().parse::<u128>()?, debt);
    assert_eq!(cw.card().await["legal_entity"], "sealed");
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("A70", "company parks money in a sub-agent, defaults, and tries to get it back when the tree closes", "money repays the guarantor first", "money repays the guarantor first", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn b27_undelivered_orders_release_the_guarantor_and_late_repayment_works() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 1, 4 * UNIT, LEI).await?;
    let far = cw.opened(1, 1, 3600, "INV-FAR").await;
    cw.seller("accept_credit", json!({"credit": far})).await.unwrap();
    let e = cw.w.attacker.call(cw.w.writ.id(), "cancel_open").args_json(json!({"credit": far})).transact().await?.into_result();
    assert!(format!("{:?}", e).contains("NOT_DUE"));
    cw.seller("mark_delivered", json!({"credit": far, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
    let v: Value = cw.agent.call(cw.w.writ.id(), "settle").args_json(json!({"credit": far})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert!(v.get("CreditSettled").is_some(), "{}", v);
    let id = cw.opened(2, 1, 1, "INV-UNDELIVERED").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    cw.w.attacker.call(cw.w.writ.id(), "cancel_open").args_json(json!({"credit": id})).transact().await?.into_result()?;
    let st: Value = cw.w.writ.view("stake_of").args_json(json!({"account": cw.w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], "0", "the guarantor is released");
    // 斷電之後才還也可以
    let id = cw.delivered(7, 5, 1, "INV-LATE").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    let c = cw.credit(&id).await;
    assert_eq!(c["status"], "Enforced");
    let debt: u128 = c["debt"].as_str().unwrap().parse()?;
    cw.funder("reimburse", json!({"credit": id}), debt).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Reimbursed");
    let e = cw.guarantor("credit_unseal", json!({"credit": id, "lei": LEI, "salt": LEI_SALT, "ecr": cw.opening()})).await.unwrap_err();
    assert!(e.contains("NOT_ENFORCED"), "{}", e);
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B27", "undelivered orders release the guarantor; repaying after enforcement stops the reveal", "released, stays sealed", "released, stays sealed", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第十輪：審計修正的複審

#[tokio::test]
async fn a71_repaying_releases_what_was_retained() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 60, 17 * UNIT, LEI).await?;
    let w = &cw.w;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(9);
    let v = hire(&cw.agent, w.writ.id(), &cw.pw.link(3), 3, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], &until, 3, 3)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let id = cw.delivered(5, 2, 1, "INV-STUCK").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    assert!(cw.credit(&id).await["debt"].as_str().unwrap().parse::<u128>()? > 0);
    cw.funder("revoke", json!({"cell": cw.cell.to_string(), "evidence": "closing"}), 0).await.unwrap();
    let st0: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    // 金庫留下的錢就夠還：不必另外帶錢，剩下的放給公司領回
    cw.funder("reimburse", json!({"credit": id}), 0).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Reimbursed");
    let st1: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert!(st1["amount"].as_str().unwrap().parse::<u128>()? > st0["amount"].as_str().unwrap().parse::<u128>()?);
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], "0", "nothing left stuck in a closed root: {}", c);
    assert!(c["unclaimed"].as_str().unwrap().parse::<u128>()? > 0, "{}", c);
    let f0 = balance(&w.funder).await;
    cw.funder("claim_refund", json!({"cell": cw.cell.to_string()}), 0).await.unwrap();
    assert!(balance(&w.funder).await > f0);
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("A71", "money retained in a closed tree gets stuck after the company repays", "released to the company", "released to the company", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a72_while_owing_the_guarantor_nothing_else_gets_paid_first() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 60, 5 * UNIT, LEI).await?;
    let w = &cw.w;
    let friend = cw.delivered(1, 1, 3600, "INV-FRIEND").await;
    let id = cw.delivered(9, 8, 1, "INV-DEBT").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    assert!(cw.credit(&id).await["debt"].as_str().unwrap().parse::<u128>()? > 0);
    let e = cw.funder("settle_by_funder", json!({"credit": friend}), 0).await.unwrap_err();
    assert!(e.contains("REPAY_GUARANTOR_FIRST"), "{}", e);
    let v = spend_invoice(&cw.agent, w.writ.id(), &cw.pw.link(10), 1, w.merchant.id(), b"INV-CASHOUT").await;
    assert_eq!(v["Rejected"]["reason"], "FROZEN", "{}", v);
    let sk = SecretKey::from_random(KeyType::ED25519);
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let v = hire(&cw.agent, w.writ.id(), &cw.pw.link(10), 1, hire_args(&sk.public_key(), &Payword::new(3), &[w.merchant.id()], c["valid_until"].as_str().unwrap(), 1, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "FROZEN", "{}", v);
    // 自己帶錢來付別筆可以
    cw.funder("settle_by_funder", json!({"credit": friend}), UNIT).await.unwrap();
    assert_eq!(cw.credit(&friend).await["status"], "Settled");
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("A72", "company owes the guarantor and pays a friendly seller from the vault first", "REPAY_GUARANTOR_FIRST", "REPAY_GUARANTOR_FIRST", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a73_late_delivery_cannot_win_a_dispute() -> anyhow::Result<()> {
    let cw = credit_world(0, 5, 0, 1).await?;
    let id = cw.opened(1, 1, 3600, "INV-LATE-PROOF").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), UNIT).await.unwrap();
    wait_secs(3).await;
    let e = cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap_err();
    assert!(e.contains("DISPUTE_CLOSED"), "{}", e);
    bench("A73", "seller files a delivery proof after the arbiter's time ran out", "DISPUTE_CLOSED", "DISPUTE_CLOSED", gain(&cw.w).await);
    cw.seller("resolve_timeout", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Cancelled");
    // 爭議中補交：仲裁人多一段驗收期，不能立刻逾時領走
    let cw = credit_world_full(0, 5, 0, 1, 30 * UNIT, LEI, 60).await?;
    let id = cw.opened(1, 1, 3600, "INV-LAST-MINUTE").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), UNIT).await.unwrap();
    cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
    wait_secs(3).await;
    let e = cw.seller("resolve_timeout", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("ARBITER_STILL_HAS_TIME"), "{}", e);
    bench("A74", "seller files a proof at the last second and collects before the arbiter can look", "ARBITER_STILL_HAS_TIME", "ARBITER_STILL_HAS_TIME", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a75_a_suspended_agent_cannot_settle() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 1, 30 * UNIT, LEI).await?;
    let w = &cw.w;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(5);
    let v = hire(&cw.agent, w.writ.id(), &cw.pw.link(3), 3, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], c["valid_until"].as_str().unwrap(), 3, 3)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let child = Account::from_secret_key(w.writ.id().clone(), sk, &w.worker);
    let due = now_ns(w).await? + 3_600 * SEC;
    let v: Value = child.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cpw.link(1), "j": 1, "to": w.merchant.id(), "invoice_hash": hex::encode(Sha256::digest("INV-CHILD")), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    let id = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    for i in 0..3 {
        spend_invoice(&cw.agent, w.writ.id(), &cw.pw.link(4), 1, w.attacker.id(), format!("X{}", i).as_bytes()).await;
    }
    let e = child.call(w.writ.id(), "settle").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result();
    assert!(format!("{:?}", e).contains("SUSPENDED"), "{:?}", e);
    bench("A75", "sub-agent keeps settling after its parent tripped", "SUSPENDED", "SUSPENDED", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn b28_guarantor_can_collect_again_and_unblock_a_silent_seller() -> anyhow::Result<()> {
    // 保證金釋放後再收一次
    let cw = credit_world(5000, 5, 0, 1).await?;
    let w = &cw.w;
    let cw2 = credit_world_with(5000, 5, 0, 1, 5 * UNIT, LEI).await?;
    let other = cw2.opened(2, 2, 1, "INV-OTHER").await;
    cw2.seller("accept_credit", json!({"credit": other})).await.unwrap();
    let id = cw2.delivered(7, 5, 1, "INV-MAIN").await;
    wait_secs(2).await;
    cw2.seller("claim_default", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    cw2.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    assert_eq!(cw2.credit(&id).await["status"], "Enforced");
    let d0: u128 = cw2.credit(&id).await["debt"].as_str().unwrap().parse()?;
    cw2.seller("cancel_open", json!({"credit": other})).await.unwrap();
    cw2.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    let d1: u128 = cw2.credit(&id).await["debt"].as_str().unwrap().parse()?;
    assert!(d1 < d0, "the released bond repaid the guarantor: {} -> {}", d0, d1);
    cw2.funder("reimburse", json!({"credit": id}), d1).await.unwrap();
    assert_eq!(cw2.credit(&id).await["status"], "Reimbursed");
    assert_eq!(cw2.solvent().await["solvent"], true);
    // 賣方不請求：保證人要等多一段追償期才可代為觸發，錢仍給賣方
    let id = cw.delivered(1, 1, 1, "INV-SILENT").await;
    let e = cw.guarantor("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("ONLY_SELLER"), "{}", e);
    wait_secs(3).await;
    cw.guarantor("claim_default", json!({"credit": id})).await.unwrap();
    let got: Value = w.writ.view("claimable_of").args_json(json!({"account": w.merchant.id()})).await?.json()?;
    assert_eq!(got.as_str().unwrap().parse::<u128>()?, UNIT, "the seller is still the one paid");
    bench("B28", "released bond repays the guarantor; a silent seller cannot hold exposure open", "collected, unblocked", "collected, unblocked", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第十一輪

#[tokio::test]
async fn a76_a_sub_agent_cannot_pay_a_friend_while_the_company_owes() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 60, 17 * UNIT, LEI).await?;
    let w = &cw.w;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(5);
    let v = hire(&cw.agent, w.writ.id(), &cw.pw.link(3), 3, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], c["valid_until"].as_str().unwrap(), 3, 3)).await;
    assert!(v.get("Hired").is_some(), "{}", v);
    let child = Account::from_secret_key(w.writ.id().clone(), sk, &w.worker);
    let due = now_ns(w).await? + 3_600 * SEC;
    let v: Value = child.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cpw.link(2), "j": 2, "to": w.merchant.id(), "invoice_hash": hex::encode(Sha256::digest("INV-FRIEND")), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    let friend = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
    cw.seller("accept_credit", json!({"credit": friend})).await.unwrap();
    let id = cw.delivered(5, 2, 1, "INV-OWED").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    assert!(cw.credit(&id).await["debt"].as_str().unwrap().parse::<u128>()? > 0);
    let e = child.call(w.writ.id(), "settle").args_json(json!({"credit": friend})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result();
    assert!(format!("{:?}", e).contains("REPAY_GUARANTOR_FIRST"), "{:?}", e);
    bench("A76", "while the company owes, a sub-agent settles a friendly order from its own vault", "REPAY_GUARANTOR_FIRST", "REPAY_GUARANTOR_FIRST", gain(w).await);
    // 欠債時一直試不會把 agent 自己弄死，還清後還能工作
    for i in 0..4 {
        let v = spend_invoice(&cw.agent, w.writ.id(), &cw.pw.link(6), 1, w.merchant.id(), format!("F{}", i).as_bytes()).await;
        assert_eq!(v["Rejected"]["reason"], "FROZEN", "{}", v);
        assert_eq!(v["Rejected"]["tripped"], false, "{}", v);
    }
    Ok(())
}

#[tokio::test]
async fn a77_guarantor_or_company_cannot_be_the_seller() -> anyhow::Result<()> {
    let cw = credit_world(0, 5, 0, 1).await?;
    let w = &cw.w;
    for (link, who, inv) in [(1u32, &w.verifier, "INV-G"), (2u32, &w.funder, "INV-F")] {
        let due = now_ns(w).await? + 3_600 * SEC;
        let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(link), "j": 1, "to": who.id(), "invoice_hash": hex::encode(Sha256::digest(inv)), "due_at": due.to_string()}))
            .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
        let id = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
        let e = who.call(w.writ.id(), "accept_credit").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result();
        assert!(format!("{:?}", e).contains("SELLER_NOT_INDEPENDENT"), "{:?}", e);
    }
    bench("A77", "guarantor or company sells to the agent to manufacture a default", "SELLER_NOT_INDEPENDENT", "SELLER_NOT_INDEPENDENT", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn b29_rotating_the_legal_entity_key_does_not_block_the_reveal() -> anyhow::Result<()> {
    let cw = credit_world_with(0, 5, 0, 1, 2 * UNIT, LEI).await?;
    let w = &cw.w;
    let id = cw.delivered(5, 5, 1, "INV-ROTATE").await;
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    cw.guarantor("update_signers", json!({"cell": cw.cell.to_string(), "issuer_aid": c["issuer_aid"], "issuer_pk": c["issuer_pk"], "ecr_commit": hex::encode([3u8; 32])})).await.unwrap();
    cw.guarantor("enforce_recourse", json!({"credit": id})).await.unwrap();
    cw.guarantor("credit_unseal", json!({"credit": id, "lei": LEI, "salt": LEI_SALT, "ecr": cw.opening()})).await.unwrap();
    assert_eq!(cw.card().await["legal_entity"], LEI);
    bench("B29", "the legal entity rotates its key after signing the terms", "reveal still works", "reveal still works", 0);
    Ok(())
}

// ---------------------------------------------------------------- 第十二輪：保證費

#[tokio::test]
async fn b30_the_guarantor_earns_a_fee_for_standing_behind_the_order() -> anyhow::Result<()> {
    let cw = credit_world_fee(0, 1000, 5, 0, 1, 30 * UNIT, LEI, 0).await?;
    let w = &cw.w;
    assert_eq!(cw.card().await["premium_bps"], 1000);
    let st0: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    let c0: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    // 只開單不收費，賣方接受才收
    let id = cw.opened(5, 5, 3600, "INV-FEE").await;
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["amount"], st0["amount"]);
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    let fee = 5 * UNIT / 10;
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["amount"].as_str().unwrap().parse::<u128>()? - st0["amount"].as_str().unwrap().parse::<u128>()?, fee);
    assert_eq!(st["earned"], fee.to_string());
    assert_eq!(cw.card().await["guarantor_earned"], fee.to_string());
    let c1: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let v0: u128 = c0["vault"].as_str().unwrap().parse()?;
    let v1: u128 = c1["vault"].as_str().unwrap().parse()?;
    assert!(v0 - v1 > fee, "storage and fee both left the vault");
    assert_eq!(cw.solvent().await["solvent"], true);
    // 結清也不退：費用買的是已經承擔的曝險
    cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
    let v: Value = cw.agent.call(w.writ.id(), "settle").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert!(v.get("CreditSettled").is_some(), "{}", v);
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["earned"], fee.to_string(), "settling does not refund the fee");
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B30", "the guarantor earns its fee when the seller accepts; nothing is refunded", "fee on the risk card and in the stake", "fee on the risk card and in the stake", 0);
    Ok(())
}

#[tokio::test]
async fn a80_a_long_order_cannot_pay_the_one_period_fee() -> anyhow::Result<()> {
    // 每期 2%；天期 90 天要收 3 期。一期的費用付得起、三期付不起：不能把長單當短單賺保證
    let cw = credit_world_x(CwOpts { premium: 200, vault: UNIT, max_tenor: 100 * 86_400, ..Default::default() }).await?;
    let due = now_ns(&cw.w).await? + 90 * 86_400 * SEC;
    // 10 節的 2% = 0.2 節，一期付得起；三期 0.6 節超過扣完單據儲存後的金庫
    let v: Value = cw.agent.call(cw.w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(10), "j": 10, "to": cw.w.merchant.id(), "invoice_hash": hex::encode(Sha256::digest("INV-LONG")), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    let id = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("PREMIUM_SHORT"), "{}", e);
    bench("A80", "a long order pays the fee of a short one", "PREMIUM_SHORT", "PREMIUM_SHORT", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a78_a_company_with_no_money_for_the_fee_gets_no_guarantee() -> anyhow::Result<()> {
    let cw = credit_world_fee(0, 2000, 5, 0, 1, UNIT, LEI, 0).await?;
    // 金庫 1 節扣掉單據儲存剩 0.5 節；5 節的 20% 是 1 節，付不起
    let id = cw.opened(5, 5, 3600, "INV-NOFEE").await;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("PREMIUM_SHORT"), "{}", e);
    let st: Value = cw.w.writ.view("stake_of").args_json(json!({"account": cw.w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], "0");
    bench("A78", "a company with an empty vault takes a guarantee without paying for it", "PREMIUM_SHORT", "PREMIUM_SHORT", gain(&cw.w).await);
    Ok(())
}
