//! Writ attack bench + normal flow. Everything runs on the local sandbox, never touches testnet.
//!
//! How to run: `make -C contract test` (the first run downloads near-sandbox, needs network once)
//!
//! Each test prints one last line `WRIT_BENCH|<id>|<attack>|<expected>|<observed>|<attacker_gain_yocto>`,
//! the README summary table is generated directly from these lines (scripts/bench_table.py).

use ed25519_dalek::{Signer, SigningKey};
use near_workspaces::network::Sandbox;
use near_workspaces::types::{KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const WASM: &str = "res/writ.wasm";
const UNIT: u128 = 10_000_000_000_000_000_000_000; // 0.01 NEAR per chain link
// Opening fee = 0.35 NEAR (>= the agent key's gas allowance) + 0.001 NEAR per link (storage for the invoice record)
fn fee(n: u32) -> u128 { 350_000_000_000_000_000_000_000 + (n as u128) * 1_000_000_000_000_000_000_000 }
const AMC_ISSUER: &str = "EISSUER_AID";

// ---------------------------------------------------------------- helpers

/// PayWord chain: links[k] = H^(n-k)(seed), links[0] = w0. Paying j links hands over links[idx+j].
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

/// Attacker's net NEAR gain relative to the start (the attacker pays its own gas, so it is 0 when no profit was made).
async fn gain(w: &World) -> i128 {
    balance(&w.attacker).await.saturating_sub(w.attacker_start) as i128
}

/// For cargo-mutants: with WRIT_REBUILD=1 every test first rebuilds the wasm from the (mutated) source, otherwise it uses the output of make build.
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
/// Attestations in tests always use a time "far in the future", meaning just signed; A33 tests expiry separately.
const ATTESTED_NOW: u64 = u64::MAX / 2;

/// Canonical string identical to the contract's attestation_message.
fn attest_msg(a: &Value, funder: &AccountId, contract: &AccountId) -> String {
    let scope: Vec<String> = a["scope"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
    format!(
        "writ:attest:v7\ncontract={}\namc={}\nissuer_aid={}\nissuer_pk={}\nagent_pk={}\nw0={}\nn={}\nunit={}\nscope={}\nvalid_until={}\ndaily_links={}\nmax_links={}\nmax_strikes={}\nlei_commit={}\necr_commit={}\nfunder={}\nverifier={}\nattested_at={}\nasset={}\ncredit={}\ncover={}",
        contract, a["amc_said"].as_str().unwrap(), a.get("issuer_aid").and_then(|v| v.as_str()).unwrap(), a["issuer_pk"].as_str().unwrap(), a["agent_pk"].as_str().unwrap(),
        a["w0"].as_str().unwrap(), a["n"], a["unit"].as_str().unwrap(), scope.join(","),
        a["valid_until"].as_str().unwrap(), a["daily_links"], a["max_links"], a["max_strikes"], a["lei_commit"].as_str().unwrap(), a["ecr_commit"].as_str().unwrap(), funder,
        a["verifier"].as_str().unwrap(), a["attested_at"].as_str().unwrap(),
        a.get("asset").and_then(|v| v.as_str()).unwrap_or("near"),
        a.get("credit").filter(|c| !c.is_null()).map(|c| format!("{},{},{},{},{},{},{},{},{},{},{},{}",
            c["limit"].as_str().unwrap(), c["bond_bps"], c["premium_bps"], c["min_tenor"].as_str().unwrap(), c["max_tenor"].as_str().unwrap(),
            c["terms_hash"].as_str().unwrap(), c["terms_sig"].as_str().unwrap(), c["entity_tag"].as_str().unwrap(), c["arbiter"].as_str().unwrap(), c["fee_payer"].as_str().unwrap(), c["seller_cap_bps"], c.get("asset").and_then(|v| v.as_str()).unwrap_or("near"))).unwrap_or_else(|| "none".to_string()),
        a.get("cover").filter(|c| !c.is_null()).map(|c| format!("{},{},{},{},{},{}",
            c["limit"].as_str().unwrap(), c["deductible_bps"], c["premium_bps"], c["claim_window"].as_str().unwrap(), c["arbiter"].as_str().unwrap(), c["terms_hash"].as_str().unwrap())).unwrap_or_else(|| "none".to_string())
    )
}

async fn now_ns(w: &World) -> anyhow::Result<u64> {
    Ok(w.worker.view_block().await?.timestamp())
}

/// Open a cell: returns (cell id, the agent's Account acting as the contract account, PayWord chain)
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
    match agent.call(writ, "spend").args_json(json!({"preimage": preimage, "j": j, "to": to, "invoice_hash": hex::encode(rand::random::<[u8; 32]>())})).gas(near_workspaces::types::Gas::from_tgas(80)).transact().await {
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

// ---------------------------------------------------------------- normal flow

#[tokio::test]
async fn b00_happy_path_pays_merchant_and_present_hides_lei() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw) = open_cell(&w, default_opts(&w)).await?;
    let before = balance(&w.merchant).await;
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert_eq!(v["Paid"]["idx"], 3);
    let after = balance(&w.merchant).await;
    assert_eq!(after - before, 3 * UNIT, "merchant receives exactly 3 links");
    // second payment continues from the chain head
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

// ---------------------------------------------------------------- policy-layer attacks (contract returns Rejected, with a tx hash)

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
    // beyond the chain length
    let v = spend(&agent, w.writ.id(), &pw.link(5), 6, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "LIMIT");
    bench("A02", "spend more links than the mandate holds", "Rejected:LIMIT", "Rejected:LIMIT", gain(&w).await);
    // forged chain link (the agent makes up a preimage)
    let v = spend(&agent, w.writ.id(), &"ab".repeat(32), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A03", "forged hash-chain link (agent invents budget)", "Rejected:CHAIN", "Rejected:CHAIN", gain(&w).await);
    // replay the same chain link after one legitimate payment
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
    // the human released more links, but today's rate is used up
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

// ---------------------------------------------------------------- protocol-layer attacks (RPC rejects directly, no tx hash)

#[tokio::test]
async fn a08_agent_key_cannot_escape_its_method() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    let before = balance(&w.attacker).await;

    // call a write method other than revoke / refresh_key / top_up
    let e = agent.call(w.writ.id(), "set_verifier").args_json(json!({"account": agent.id(), "pk_hex": "00"})).transact().await.unwrap_err();
    assert_eq!(proto_tag(&format!("{:?}", e)), "MethodNameMismatch");
    bench("A08", "agent key calls admin method set_verifier", "MethodNameMismatch", "MethodNameMismatch", gain(&w).await);

    // attach a deposit (standard ft_transfer needs 1 yocto)
    let e = agent.call(w.writ.id(), "spend").args_json(json!({"preimage": "00", "j": 1, "to": w.attacker.id()}))
        .deposit(NearToken::from_yoctonear(1)).transact().await.unwrap_err();
    assert_eq!(proto_tag(&format!("{:?}", e)), "DepositWithFunctionCall");
    bench("A09", "agent attaches deposit (e.g. ft_transfer 1 yocto)", "DepositWithFunctionCall", "DepositWithFunctionCall", gain(&w).await);

    // transfer the contract account's NEAR away directly
    let e = agent.transfer_near(w.attacker.id(), NearToken::from_millinear(1)).await;
    let s = format!("{:?}", e);
    assert!(s.contains("RequiresFullAccess"), "plain transfer must be impossible: {}", s);
    bench("A10", "agent sends a plain Transfer from the contract account", "RequiresFullAccess", proto_tag(&s), gain(&w).await);

    // call another contract with the agent's key
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

// ---------------------------------------------------------------- credential layer

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
    // (a) a non-allowlisted party signs by itself
    let rogue = SigningKey::generate(&mut rand::thread_rng());
    args["signature"] = json!(hex::encode(rogue.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args.clone()})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A12", "self-signed attestation (not a whitelisted verifier)", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    // (b) the verifier signed, but the funder changed scope to the attacker
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    args["scope"] = json!([w.attacker.id()]);
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args.clone()})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
    let s = format!("{:?}", r.into_result()); assert!(s.contains("BAD_ATTESTATION"), "{}", { std::fs::write("/tmp/a12.txt", &s).ok(); "see /tmp/a12.txt" });
    bench("A13", "funder widens the scope after the verifier signed", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(&w).await);
    // (c) another account takes someone else's attestation to open a cell (funder is bound into the signature)
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

    // tamper with one byte of the ixn: signature fails
    let mut bad = hex::decode(ixn)?;
    let last = bad.len() - 3;
    bad[last] ^= 1;
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(&hex::encode(bad)), "signature": b64(sig), "ecr": null})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"));
    bench("A15", "forged KERI revocation event", "BAD_KEL_SIGNATURE", "BAD_KEL_SIGNATURE", gain(&w).await);

    // real signature, real ixn, but it anchors the AMC's "issuance" (seal s="0"), not the revocation
    let iss = &v["iss_ixn"];
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(iss["raw_hex"].as_str().unwrap()), "signature": b64(iss["sig_hex"].as_str().unwrap()), "ecr": null}))
        .max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NO_REVOCATION_SEAL"));
    bench("A24", "genuine signed KERI event that anchors the AMC issuance, not a revocation", "NO_REVOCATION_SEAL", "NO_REVOCATION_SEAL", gain(&w).await);

    // real ixn: anyone (here the attacker account) can submit it, no need to trust a watcher
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

    // the legal entity revokes by itself
    w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "manual"})).transact().await?.into_result()?;
    let e = spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&e), "AccessKeyNotFound");
    let s: Value = w.writ.view("stats").await?.json()?;
    assert_eq!(s["revoked"], 1);
    let sol: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(sol["vault_total"], "0", "closing a cell releases its vault from the total");
    Ok(())
}

// ---------------------------------------------------------------- regulator disclosure (tier-1)

#[tokio::test]
async fn a17_unseal_needs_supervisor_waiting_period_and_matching_commitment() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, _agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    let supervisor = w.worker.dev_create_account().await?;
    let reason = hex::encode(Sha256::digest(b"court order 2026-TPE-001"));

    // a non-regulator cannot request disclosure
    let r = w.attacker.call(w.writ.id(), "request_unseal").args_json(json!({"cell": cell.to_string(), "reason_hash": reason})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_SUPERVISOR"));
    bench("A17", "non-supervisor requests disclosure of the legal entity", "NOT_SUPERVISOR", "NOT_SUPERVISOR", gain(&w).await);

    w.writ.call("set_supervisor").args_json(json!({"account": supervisor.id(), "enabled": true})).transact().await?.into_result()?;
    supervisor.call(w.writ.id(), "request_unseal").args_json(json!({"cell": cell.to_string(), "reason_hash": reason})).transact().await?.into_result()?;

    // cannot disclose during the waiting period
    let release = |lei: &str, salt: &str| {
        let (lei, salt) = (lei.to_string(), salt.to_string());
        let v = w.verifier.clone(); let id = w.writ.id().clone(); let c = cell.to_string();
        async move { v.call(&id, "release_unseal").args_json(json!({"cell": c, "lei": lei, "salt": salt})).transact().await.unwrap().into_result() }
    };
    let e = format!("{:?}", release("WRITDEMO000000000017", "salt-demo").await);
    assert!(e.contains("TOO_EARLY"), "{}", e);
    bench("A18", "verifier discloses before the public waiting period ends", "TOO_EARLY", "TOO_EARLY", gain(&w).await);

    // the legal entity objects (public trace, does not block)
    w.funder.call(w.writ.id(), "object_unseal").args_json(json!({"cell": cell.to_string()})).transact().await?.into_result()?;
    w.worker.fast_forward(200).await?;

    // the verifier tries to disclose a different LEI (framing another company)
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

// ---------------------------------------------------------------- NEP-141 stablecoin path

const FT_WASM: &str = "res/ft_mock.wasm";
const T: u128 = 1_000_000; // tUSDC, 6 decimals

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
    o.unit = T / 10; // 0.1 tUSDC per link
    let (cell, agent, pw) = open_cell(&w, o).await?;
    // the legal entity deposits 5 tUSDC with ft_transfer_call, msg = cell id
    w.funder.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": (5 * T).to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], (5 * T).to_string());

    // pay 3 links to the merchant
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "{}", v);
    assert_eq!(ft_balance(&w, &token, w.merchant.id()).await, 3 * T / 10);
    bench("B04", "stablecoin cell: agent pays 3 links in NEP-141 (contract attaches the 1 yocto)", "merchant +0.3 tUSDC", "merchant +0.3 tUSDC", 0);

    // the injection attack is blocked the same way
    let v = spend(&agent, w.writ.id(), &pw.link(4), 1, w.attacker.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "SCOPE");
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, 0);
    bench("A20", "prompt-injected payment from a stablecoin cell", "Rejected:SCOPE", "Rejected:SCOPE", gain(&w).await);

    // the attacker holds the same token and forces it into this cell (trying to pollute the books): refunded
    w.funder.call(token.id(), "ft_transfer").args_json(json!({"receiver_id": w.attacker.id(), "amount": T.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).transact().await?.into_result()?;
    w.attacker.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": T.to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, T, "same token from a non-funder is refunded");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], (5 * T - 3 * T / 10).to_string());
    bench("A25", "non-funder pushes the cell's own stablecoin into it", "refunded, vault unchanged", "refunded", gain(&w).await);

    // the legal entity revokes: remaining tokens are refunded to the legal entity
    let before = ft_balance(&w, &token, w.funder.id()).await;
    w.funder.call(w.writ.id(), "revoke").args_json(json!({"cell": cell.to_string(), "evidence": "manual"})).max_gas().transact().await?.into_result()?;
    let after = ft_balance(&w, &token, w.funder.id()).await;
    assert_eq!(after - before, 5 * T - 3 * T / 10, "remaining 4.7 tUSDC refunded");
    // the legal entity deposits again after revocation: refunded (the cell is closed)
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
    // open a NEAR cell; the attacker pours junk tokens in, trying to confuse the cell's vault books
    let (cell, _agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    w.attacker.call(token.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": w.writ.id(), "amount": (7 * T).to_string(), "msg": cell.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    assert_eq!(ft_balance(&w, &token, w.attacker.id()).await, 1_000 * T, "foreign token refunded in full");
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["vault"], (1_000_000_000_000_000_000_000_000 - fee(20)).to_string());
    bench("A21", "foreign token pushed into a cell via ft_transfer_call", "refunded, vault unchanged", "refunded", gain(&w).await);

    // the verifier signed a NEAR cell, the legal entity tries to turn it into a token cell
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

// ---------------------------------------------------------------- edges and accounting (gaps found by cargo-mutants, now filled)

#[tokio::test]
async fn b05_boundaries_accounting_and_events() -> anyhow::Result<()> {
    let w = world().await?;
    // vault is exactly 3 links: opening fee + 3 × 0.01 NEAR
    let mut o = default_opts(&w);
    o.n = 5; o.daily = 5; o.deposit_near = 0; // compute the deposit below by hand
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

    // the vault covers only 3 links, 4 are wanted -> FUNDS (amount = j × unit, not j + unit)
    let v = spend(&agent, w.writ.id(), &pw.link(4), 4, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS", "{}", v);
    // the vault covers exactly 3 links -> payable; one more link -> FUNDS
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "vault exactly equal to amount must pay: {}", v);
    let v = spend(&agent, w.writ.id(), &pw.link(4), 1, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS");
    bench("A23", "spend more than the vault holds (valid links, within rate)", "Rejected:FUNDS", "Rejected:FUNDS", gain(&w).await);

    // after topping up, using the whole chain (idx + j == n) must succeed
    w.funder.call(w.writ.id(), "top_up").args_json(json!({"cell": cell})).deposit(NearToken::from_yoctonear(2 * UNIT)).transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell})).await?.json()?;
    assert_eq!(c["vault"], (2 * UNIT).to_string(), "top_up adds exactly the deposit");
    let v = spend(&agent, w.writ.id(), &pw.link(5), 2, w.merchant.id()).await.unwrap();
    assert_eq!(v["Paid"]["remaining_links"], 0, "the last link of the chain is spendable: {}", v);

    // counters: this cell rejected once; global rejected/cells
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
    // solvency: vault total = 0.9 NEAR (second cell) + 0 (first cell used up)
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

// ---------------------------------------------------------------- round 2: holes found in code review (A26-A30, B07)

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
    // victim cell
    let mut victim = default_opts(&w);
    victim.amc_said = "EVICTIM".into();
    open_cell(&w, victim).await?;
    let before = surplus(&w).await;

    // colluding legal entity and agent: open a cell and burn gas with malformed arguments (a panic does not count as a strike)
    let (cell, agent, _pw) = open_cell(&w, default_opts(&w)).await?;
    for _ in 0..20 {
        let r = agent.call(w.writ.id(), "spend").args_json(json!({"preimage": 1, "j": "x", "to": "!!"}))
            .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?;
        assert!(r.into_result().is_err(), "malformed args must fail");
    }
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["strikes"], 0, "malformed calls burn gas without reaching the policy checks");

    // free refresh rejected
    let r = w.funder.call(w.writ.id(), "refresh_key").args_json(json!({"cell": cell.to_string()})).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("REFRESH_UNPAID"));
    assert!(surplus(&w).await >= before, "this cell's fee covers everything its key burned");
    bench("A28", "colluding funder + agent burn gas and refresh for free to drain other cells' vaults", "REFRESH_UNPAID", "REFRESH_UNPAID", gain(&w).await);
    Ok(())
}

/// HR path: the LE revokes the employee's ECR. Fixtures are generated with real keripy by keri/make_test_vectors.py.
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

    // wrong salt: the commitment cannot be opened, so the legal entity cannot be impersonated
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": ixn, "signature": sig, "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": "wrong"}})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_ECR_OPENING"));
    bench("A29", "attacker presents its own key as the legal entity to revoke the mandate", "BAD_ECR_OPENING", "BAD_ECR_OPENING", gain(&w).await);

    // commitment opens, but the event was tampered with: signature fails
    let mut tampered = hex::decode(e["raw_hex"].as_str().unwrap())?;
    let last = tampered.len() - 3;
    tampered[last] ^= 1;
    let r = w.attacker.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": b64(&hex::encode(tampered)), "signature": sig, "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": ECR_COMMIT_SALT}})).max_gas().transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("BAD_KEL_SIGNATURE"));
    bench("A30", "forged ECR revocation event with a valid commitment opening", "BAD_KEL_SIGNATURE", "BAD_KEL_SIGNATURE", gain(&w).await);

    // real event: anyone may submit
    w.merchant.call(w.writ.id(), "revoke_by_kel")
        .args_json(json!({"cell": cell.to_string(), "ixn": ixn, "signature": sig, "ecr": {"le_aid": le_aid, "le_pk": le_pk, "ecr_said": ecr_said, "salt": ECR_COMMIT_SALT}})).max_gas().transact().await?.into_result()?;
    let err = spend(&agent, w.writ.id(), &pw.link(2), 1, w.merchant.id()).await.unwrap_err();
    assert_eq!(proto_tag(&err), "AccessKeyNotFound");
    bench("B07", "HR revokes the employee's ECR in KERI; anyone submits it; employee not needed", "key deleted, next call AccessKeyNotFound", proto_tag(&err), 0);
    Ok(())
}

// ---------------------------------------------------------------- round 3: invoice, per-payment cap, recovery, lock, rotation

async fn spend_invoice(agent: &Account, writ: &AccountId, preimage: &str, j: u32, to: &AccountId, invoice: &[u8]) -> Value {
    let inv = hex::encode(Sha256::digest(invoice));
    agent.call(writ, "spend").args_json(json!({"preimage": preimage, "j": j, "to": to, "invoice_hash": inv}))
        .gas(near_workspaces::types::Gas::from_tgas(80)).transact().await.unwrap().into_result().unwrap().json().unwrap()
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

    // an anchoring event signed by the same key for a different AID cannot be used to revoke this cell
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
    // the owner manages the allowlist from an external account
    owner.call(acc.id(), "set_verifier").args_json(json!({"account": owner.id(), "pk_hex": hex::encode([1u8; 32])})).transact().await?.into_result()?;
    let got: String = worker.view(acc.id(), "owner").await?.json::<Value>()?.as_str().unwrap().to_string();
    assert_eq!(got, owner.id().as_str());
    bench("B10", "deploy + init + delete full-access key in one batch; owner still manages the whitelist", "0 keys on the contract account", "0 keys on the contract account", 0);
    Ok(())
}

// ---------------------------------------------------------------- round 4: problems found by an independent audit

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
    // the legal entity empties its token balance and leaves the token, then revokes: the refund must fail
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

/// actual gas per payment (the README quotes this number).
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

// ---------------------------------------------------------------- round 5: cargo-mutants survivors

#[tokio::test]
async fn b14_boundaries_from_mutation_survivors() -> anyhow::Result<()> {
    let w = world().await?;
    // per-payment cap: exactly the cap can be paid
    let mut o = default_opts(&w);
    o.max_links = 3;
    o.amc_said = "EB14A".into();
    let (cell, agent, pw) = open_cell(&w, o).await?;
    let v = spend(&agent, w.writ.id(), &pw.link(3), 3, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "j == max_links pays: {}", v);
    let unpaid = hex::encode(Sha256::digest(b"never paid"));
    let paid: bool = w.writ.view("invoice_paid").args_json(json!({"cell": cell.to_string(), "invoice_hash": unpaid})).await?.json()?;
    assert!(!paid, "an invoice never paid is not on record");

    // maxStrikes = 0: repeated rejections do not delete the key
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

    // solvency storage = usage × cost per byte
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
    // the legal entity is a sub-account that can be deleted and recreated
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

    // the legal entity account is gone, the revocation refund must fail
    funder.clone().delete_account(w.merchant.id()).await?.into_result()?;
    w.verifier.call(w.writ.id(), "revoke").args_json(json!({"cell": id, "evidence": "manual"})).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": id})).await?.json()?;
    assert_eq!(c["unclaimed"], vault.to_string());
    assert_eq!(vault_total(&w).await, vault, "a kept refund still counts against the balance");

    // the legal entity claims it back after recreating the account
    let funder = root.create_subaccount("corp").initial_balance(NearToken::from_near(3)).keys(funder_sk).transact().await?.into_result()?;
    let before = balance(&funder).await;
    funder.call(w.writ.id(), "claim_refund").args_json(json!({"cell": id})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?.into_result()?;
    assert_eq!(vault_total(&w).await, 0);
    assert!(balance(&funder).await > before + vault / 2, "the refund arrived");
    bench("B15", "NEAR refund fails because the funder account is gone; it is kept, and claimable after the account returns", "refund recovered", "refund recovered", 0);
    Ok(())
}

// ---------------------------------------------------------------- round 6: agents hiring agents, firing one person powers off the whole tree

fn hire_args(agent_pk: &near_workspaces::types::PublicKey, pw: &Payword, scope: &[&AccountId], valid_until: &str, daily: u32, max_links: u32) -> Value {
    json!({"agent_pk": agent_pk, "w0": pw.w0(), "scope": scope, "valid_until": valid_until, "daily_links": daily, "max_links": max_links})
}

async fn hire(agent: &Account, writ: &AccountId, preimage: &str, j: u32, child: Value) -> Value {
    agent.call(writ, "hire").args_json(json!({"preimage": preimage, "j": j, "child": child}))
        .gas(near_workspaces::types::Gas::from_tgas(60)).transact().await.unwrap().into_result().unwrap().json().unwrap()
}

/// Open a root cell, then hire a child agent. Returns (root cell, root agent, root chain, child cell, child agent, child chain, valid_until)
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

    // the child agent cannot pay counterparties that exist only at the upper level; the upper level's chain links are useless to it
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

    // the child agent wants to give the grandchild agent a counterparty it does not have itself
    let v = hire(&cagent, w.writ.id(), &cpw.link(1), 1, hire_args(&fresh(), &Payword::new(1), &[w.verifier.id()], &until, 5, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_SCOPE");
    bench("A40", "sub-agent grants a counterparty it does not have itself", "Rejected:HIRE_SCOPE", "Rejected:HIRE_SCOPE", gain(&w).await);

    // deadline, rate and per-payment cap are loosened
    let later = (until.parse::<u64>()? + 1).to_string();
    let v = hire(&agent, w.writ.id(), &pw.link(6), 1, hire_args(&fresh(), &np, &[w.merchant.id()], &later, 5, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_TERMS");
    let v = hire(&agent, w.writ.id(), &pw.link(6), 1, hire_args(&fresh(), &np, &[w.merchant.id()], &until, 41, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_TERMS");
    bench("A41", "hire with a later expiry or a higher rate than the parent", "Rejected:HIRE_TERMS", "Rejected:HIRE_TERMS", gain(&w).await);

    // without links released by the employee, no budget can be hired
    let forged = hex::encode([9u8; 32]);
    let v = hire(&agent, w.writ.id(), &forged, 3, hire_args(&fresh(), &np, &[w.merchant.id()], &until, 5, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "CHAIN");
    bench("A42", "agent hires with budget the employee never released", "Rejected:CHAIN", "Rejected:CHAIN", gain(&w).await);

    // a stranger cell dismisses someone else's child agent
    let other = SecretKey::from_random(KeyType::ED25519);
    let mut o = default_opts(&w);
    o.amc_said = "EOTHER".into();
    let _ = (&other, &child);
    let (_c2, stranger, _p2) = open_cell(&w, o).await?;
    let r = stranger.call(w.writ.id(), "dismiss").args_json(json!({"child": child.to_string()})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?;
    assert!(format!("{:?}", r.into_result()).contains("NOT_PARENT"));
    bench("A43", "an agent dismisses someone else's sub-agent", "NOT_PARENT", "NOT_PARENT", gain(&w).await);

    // the upper level can dismiss the ones it hired
    agent.call(w.writ.id(), "dismiss").args_json(json!({"child": child.to_string()})).gas(near_workspaces::types::Gas::from_tgas(60)).transact().await?.into_result()?;
    let keys = w.worker.view_access_keys(w.writ.id()).await?;
    assert!(keys.iter().all(|k| k.public_key != cagent.secret_key().public_key()));
    Ok(())
}

#[tokio::test]
async fn a44_the_tree_has_a_depth_and_size_limit() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw, _child, c1, cpw1, until) = tree(&w, 8).await?;
    // levels 2 and 3
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

    // the root cell keeps hiring up to the limit (currently 4 cells)
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

    // a full tree is shut down in one transaction
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

/// Main show: HR revokes the employee's ECR and the whole tree is powered off. Fixtures are real keripy events.
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

// ---------------------------------------------------------------- round 7: Who pays is named before the agent buys

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
    extra: Vec<Account>,
    token: Option<Contract>,
    unit: u128,
}

/// A contract with a short time window, a cell that can buy on credit. The guarantor stakes stake NEAR. The vault holds 30 links.
async fn credit_world(bond_bps: u32, stake: u128, grace: u64, recourse: u64) -> anyhow::Result<CreditWorld> {
    credit_world_with(bond_bps, stake, grace, recourse, 30 * UNIT, LEI).await
}

/// vault: the vault after opening the cell (yocto). committed_lei: the LEI the verifier commits to (differs from the one the LE signed when testing framing).
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

/// All options of the credit world. Defaults: no bond, no fee, stake 5 NEAR, vault 30 links.
struct CwOpts { bond: u32, premium: u32, stake: u128, grace: u64, recourse: u64, vault: u128, lei: String, inspect: u64, max_tenor: u64, fee_payer: &'static str, accept_ttl: u64, cap: u32, extra_sellers: u32, token: bool }
impl Default for CwOpts {
    fn default() -> Self {
        Self { bond: 0, premium: 0, stake: 5, grace: 0, recourse: 1, vault: 30 * UNIT, lei: LEI.to_string(), inspect: 0, max_tenor: 3600, fee_payer: "Buyer", accept_ttl: 2, cap: 0, extra_sellers: 0, token: false }
    }
}

async fn credit_world_x(x: CwOpts) -> anyhow::Result<CreditWorld> {
    let CwOpts { bond: bond_bps, premium: premium_bps, stake, grace, recourse, vault, lei: committed_lei, inspect, max_tenor, fee_payer, accept_ttl, cap, extra_sellers, token } = x;
    let worker = near_workspaces::sandbox().await?;
    let writ = worker.dev_deploy(&wasm_bytes()?).await?;
    writ.call("new").args_json(json!({"owner": writ.id(), "unseal_delay_secs": 5,
        "windows": {"accept_ttl": accept_ttl.to_string(), "inspect": inspect.to_string(), "grace": grace.to_string(), "recourse": recourse.to_string(), "dispute_timeout": "2", "unstake_delay": "1"}}))
        .transact().await?.into_result()?;
    let verifier = worker.dev_create_account().await?;
    let funder = worker.dev_create_account().await?;
    let merchant = worker.dev_create_account().await?;
    let attacker = worker.dev_create_account().await?;
    let arbiter = worker.dev_create_account().await?;
    let verifier_sk = SigningKey::generate(&mut rand::thread_rng());
    writ.call("set_verifier").args_json(json!({"account": verifier.id(), "pk_hex": hex::encode(verifier_sk.verifying_key().to_bytes())})).transact().await?.into_result()?;
    if stake > 0 && !token {
        verifier.call(writ.id(), "stake").deposit(NearToken::from_near(stake)).transact().await?.into_result()?;
    }
    let attacker_start = balance(&attacker).await;
    let w = World { worker, writ, verifier, verifier_sk, funder, merchant, attacker, attacker_start };
    // token world: 6-decimal stablecoin, 1 token per link
    let ft = if token {
        let t = w.worker.dev_deploy(&std::fs::read(FT_WASM)?).await?;
        t.call("new").args_json(json!({"owner_id": w.funder.id(), "total_supply": (1_000_000 * T).to_string()})).transact().await?.into_result()?;
        for who in [w.writ.id(), w.merchant.id(), w.verifier.id(), w.attacker.id(), arbiter.id()] {
            w.funder.call(t.id(), "storage_deposit").args_json(json!({"account_id": who})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
        }
        Some(t)
    } else { None };
    let unit = if token { T } else { UNIT };

    let le = SigningKey::generate(&mut rand::thread_rng());
    let le_pk = hex::encode(le.verifying_key().to_bytes());
    let (le_aid, ecr_said) = ("ELE_AID".to_string(), "EECR_SAID".to_string());
    let mut o = default_opts(&w);
    o.amc_said = "EAMC_CREDIT".into();
    o.scope = vec![w.merchant.id().clone(), w.verifier.id().clone(), w.funder.id().clone()];
    let mut extra = vec![];
    for _ in 0..extra_sellers {
        let s = w.worker.dev_create_account().await?;
        o.scope.push(s.id().clone());
        extra.push(s);
    }
    o.ecr_commit = hex::encode(Sha256::digest(format!("{}|{}|{}|{}", le_aid, le_pk, ecr_said, ECR_COMMIT_SALT)));
    o.max_links = 10;
    o.unit = unit;
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
        "credit": {"limit": (10 * unit).to_string(), "bond_bps": bond_bps, "premium_bps": premium_bps, "min_tenor": "0", "max_tenor": max_tenor.to_string(), "terms_hash": terms_hash,
                   "terms_sig": terms_sig, "entity_tag": "ENTITY-7", "arbiter": arbiter.id(), "fee_payer": fee_payer, "seller_cap_bps": cap},
    });
    if let Some(t) = &ft {
        // the credit asset signed by the verifier differs from the cell's asset: cannot open
        args["asset"] = json!(t.id());
        let sig = w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes());
        let mut bad = args.clone();
        bad["signature"] = json!(hex::encode(sig.to_bytes()));
        let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": bad})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
        assert!(format!("{:?}", r.into_result()).contains("CREDIT_ASSET_MISMATCH"));
        args["credit"]["asset"] = json!(t.id());
    }
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    if ft.is_some() {
        // the credit asset is signed in: changing it afterwards cannot open either
        let mut bad = args.clone();
        bad["credit"]["asset"] = Value::Null;
        let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": bad})).deposit(NearToken::from_near(1)).max_gas().transact().await?;
        assert!(format!("{:?}", r.into_result()).contains("BAD_ATTESTATION"));
    }
    // the guarantor signed Seller, the company tries to change it to Buyer (and the reverse): signature fails
    if fee_payer == "Seller" || cap > 0 {
        let mut tampered = args.clone();
        tampered["credit"]["fee_payer"] = json!("Buyer");
        tampered["credit"]["seller_cap_bps"] = json!(0);
        let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": tampered})).deposit(NearToken::from_yoctonear(fee(20) + vault)).max_gas().transact().await?;
        assert!(format!("{:?}", r.into_result()).contains("BAD_ATTESTATION"));
    }
    // token tree: NEAR is kept as reserve (1 NEAR), vault and stake both go through ft_transfer_call
    let near = if ft.is_some() { fee(20) + NEAR_RESERVE } else { fee(20) + vault };
    let id: String = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_yoctonear(near)).max_gas().transact().await?.into_result()?.json()?;
    let agent = Account::from_secret_key(w.writ.id().clone(), agent_sk, &w.worker);
    if let Some(t) = &ft {
        w.funder.call(t.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": vault.to_string(), "msg": id.clone()})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
        if stake > 0 {
            w.funder.call(t.id(), "ft_transfer").args_json(json!({"receiver_id": w.verifier.id(), "amount": (stake * T).to_string()})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
            w.verifier.call(t.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": (stake * T).to_string(), "msg": "stake"})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
        }
    }
    Ok(CreditWorld { w, cell: id.parse()?, agent, pw, arbiter, le, le_aid, ecr_said, extra, token: ft, unit })
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
    // the vault has only 2 links, selling 5: the payout must reach the guarantor
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

    // freeze only, no power off; identity is still sealed
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

    // the owner removes the guarantor from the allowlist, which still cannot block disclosure
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
    // after settlement, the balance can be withdrawn
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
    // file a default without delivery
    let id = cw.opened(1, 1, 1, "INV-N").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    wait_secs(2).await;
    let e = cw.seller("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("NOT_DELIVERED"), "{}", e);
    bench("A52", "seller claims default without delivering", "NOT_DELIVERED", "NOT_DELIVERED", gain(w).await);

    // the company paid, the seller deleted the account or does not withdraw: a default still cannot be filed
    cw.funder("settle_by_funder", json!({"credit": id}), 0).await.unwrap();
    let e = cw.seller("claim_default", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("NOT_DELIVERED"), "{}", e);
    assert_eq!(cw.credit(&id).await["status"], "Settled");
    bench("A53", "seller refuses the money, then claims default anyway", "settled on the ledger", "settled on the ledger", gain(w).await);

    // a dispute needs the full deposit; with the deposit no default can be filed; only the arbiter can rule
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

    // arbiter timeout: with delivery evidence, the seller wins
    let id = cw.delivered(4, 1, 1, "INV-Q").await;
    cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), UNIT).await.unwrap();
    let e = cw.seller("resolve_timeout", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("ARBITER_STILL_HAS_TIME"), "{}", e);
    wait_secs(3).await;
    cw.seller("resolve_timeout", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Settled");

    // an order nobody accepts expires, the limit is restored
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
    // vault 4.x links, bond 100%: two orders lock 2 links each. A colluding seller files a default first and can only touch its own order's bond
    let cw = credit_world_with(10_000, 5, 0, 1, 6 * UNIT, LEI).await?;
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
    // vault 3.5 links, bond 100%: the first order locks 2 links, the second cannot lock a full 2. Previously the difference was silently shifted to the guarantor
    let cw = credit_world_with(10_000, 5, 0, 1, 7 * UNIT / 2, LEI).await?;
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
    // due date too short to react
    let due = now_ns(w).await? - 5 * SEC;
    let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(1), "j": 1, "to": w.merchant.id(), "invoice_hash": hex::encode([3u8; 32]), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["Rejected"]["reason"], "TENOR");
    bench("A57", "injected order with a due date outside the agreed terms", "Rejected:TENOR", "Rejected:TENOR", gain(w).await);
    // injection pays the attacker
    let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(1), "j": 1, "to": w.attacker.id(), "invoice_hash": hex::encode([4u8; 32]), "due_at": (now_ns(w).await? + 3000 * SEC).to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["Rejected"]["reason"], "SCOPE");
    bench("A58", "injected order to a seller outside the mandate", "Rejected:SCOPE", "Rejected:SCOPE", gain(w).await);
    // a guarantor with no stake cannot accept
    let id = cw.opened(1, 1, 3600, "INV-S").await;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("GUARANTOR_CAPACITY"), "{}", e);
    bench("A59", "seller accepts an order the guarantor has no stake to back", "GUARANTOR_CAPACITY", "GUARANTOR_CAPACITY", gain(w).await);
    // with exposure the stake cannot be withdrawn
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
    // the verifier commits to the victim company's LEI, the LE signed the real company's
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

// ---------------------------------------------------------------- round 8: problems found by an independent audit

#[tokio::test]
async fn a62_the_audit_findings_stay_fixed() -> anyhow::Result<()> {
    let w = world().await?;
    let (cell, agent, pw, child, cagent, cpw, until) = tree(&w, 5).await?;

    // F1/F2: duplicate accounts blow up scope, making revocation fail forever
    let many: Vec<&AccountId> = std::iter::repeat(w.merchant.id()).take(17).collect();
    let v = hire(&agent, w.writ.id(), &pw.link(6), 1, hire_args(&SecretKey::from_random(KeyType::ED25519).public_key(), &Payword::new(1), &many, &until, 1, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_SCOPE");
    bench("A62", "hire with a huge duplicated scope, to make the tree too expensive to revoke", "Rejected:HIRE_SCOPE", "Rejected:HIRE_SCOPE", gain(&w).await);

    // F7: parent and child each pay the same invoice
    let inv = b"INV-SHARED";
    let v = spend_invoice(&agent, w.writ.id(), &pw.link(6), 1, w.merchant.id(), inv).await;
    assert!(v.get("Paid").is_some(), "{}", v);
    let v = spend_invoice(&cagent, w.writ.id(), &cpw.link(1), 1, w.merchant.id(), inv).await;
    assert_eq!(v["Rejected"]["reason"], "DUPLICATE");
    bench("A63", "parent and sub-agent each pay the same invoice", "Rejected:DUPLICATE", "Rejected:DUPLICATE", gain(&w).await);

    // F5: a dismissed key is hired again
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
    // vault 4.5 links, 3 links locked for the seller: only 1.5 links can be touched
    let v = spend(&cw.agent, w.writ.id(), &cw.pw.link(5), 2, w.merchant.id()).await.unwrap();
    assert_eq!(v["Rejected"]["reason"], "FUNDS");
    bench("A66", "agent spends the bond locked for a seller", "Rejected:FUNDS", "Rejected:FUNDS", gain(w).await);
    Ok(())
}

// ---------------------------------------------------------------- round 9: credit contract audit

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
    // the company disputes first, the seller can still leave delivery evidence; on timeout it goes to the seller
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
    // the root cell vault is mostly moved to the child agent; after defaulting, the company tries to take the child cell's money back by powering off
    let cw = credit_world_with(0, 5, 0, 1, 17 * UNIT, LEI).await?;
    let w = &cw.w;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(9);
    // 3 links to the child agent, plus the hiring fee, leave the root cell only a little
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
    // repaying after power off is also fine
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

// ---------------------------------------------------------------- round 10: re-review of audit fixes

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
    // the money left in the vault is enough to repay: no need to bring more, the rest is released for the company to withdraw
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
    // bringing its own money to pay another order is fine
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
    // top-up during a dispute: the arbiter gets one more review period, it cannot time out and be collected at once
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
    // collect again after the bond is released
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
    // the seller does not request: the guarantor must wait one more recovery period before triggering on its behalf, the money still goes to the seller
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

// ---------------------------------------------------------------- round 11

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
    // while in debt, retrying does not kill the agent itself, and it can work again after repayment
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

// ---------------------------------------------------------------- round 12: guarantee fee

#[tokio::test]
async fn b30_the_guarantor_earns_a_fee_for_standing_behind_the_order() -> anyhow::Result<()> {
    let cw = credit_world_fee(0, 1000, 5, 0, 1, 30 * UNIT, LEI, 0).await?;
    let w = &cw.w;
    assert_eq!(cw.card().await["premium_bps"], 1000);
    let st0: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    let c0: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    // opening an order collects no fee, only the seller's acceptance does
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
    // not refunded on settlement either: the fee buys exposure that is already borne
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
    // 2% per period; a 90-day term takes 3 periods. One period's fee is affordable, three are not: a long order cannot be treated as a short one to earn the guarantee
    let cw = credit_world_x(CwOpts { premium: 200, vault: UNIT, max_tenor: 100 * 86_400, ..Default::default() }).await?;
    let due = now_ns(&cw.w).await? + 90 * 86_400 * SEC;
    // 2% of 10 links = 0.2 links, one period is affordable; three periods = 0.6 links exceeds the vault after receipt storage
    let v: Value = cw.agent.call(cw.w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(10), "j": 10, "to": cw.w.merchant.id(), "invoice_hash": hex::encode(Sha256::digest("INV-LONG")), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    let id = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("PREMIUM_SHORT"), "{}", e);
    bench("A80", "a long order pays the fee of a short one", "PREMIUM_SHORT", "PREMIUM_SHORT", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn b31_the_seller_pays_the_fee_when_it_is_paid() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { premium: 1000, fee_payer: "Seller", ..Default::default() }).await?;
    let w = &cw.w;
    bench("A81", "company swaps who pays the fee after the guarantor signed", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(w).await);
    assert_eq!(cw.card().await["fee_payer"], "Seller");
    let c0: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let v0: u128 = c0["vault"].as_str().unwrap().parse()?;
    let id = cw.delivered(5, 5, 3600, "INV-SFEE").await;
    let fee = 5 * UNIT / 10;
    assert_eq!(cw.credit(&id).await["fee"], fee.to_string());
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["earned"], "0", "nothing is charged at accept");
    let c1: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let storage = v0 - c1["vault"].as_str().unwrap().parse::<u128>()?;
    assert!(storage < UNIT, "only the order's storage left the vault: {}", storage);
    let v: Value = cw.agent.call(w.writ.id(), "settle").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert!(v.get("CreditSettled").is_some(), "{}", v);
    let got: Value = w.writ.view("claimable_of").args_json(json!({"account": w.merchant.id()})).await?.json()?;
    assert_eq!(got.as_str().unwrap().parse::<u128>()?, 5 * UNIT - fee);
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["earned"], fee.to_string());
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B31", "the seller pays the fee: nothing at accept, deducted from the invoice when paid", "seller -fee, guarantor +fee", "seller -fee, guarantor +fee", 0);
    Ok(())
}

#[tokio::test]
async fn b32_a_usage_order_settles_only_what_was_used() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { bond: 5000, ..Default::default() }).await?;
    let w = &cw.w;
    let id = cw.opened(10, 10, 3600, "INV-USAGE").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["bond_locked"], (5 * UNIT).to_string());
    let hash = hex::encode([1u8; 32]);
    let e = cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hash, "final_amount": (10 * UNIT + 1).to_string()})).await.unwrap_err();
    assert!(e.contains("BAD_FINAL_AMOUNT"), "{}", e);
    bench("A82", "seller bills more than the order when it marks delivery", "BAD_FINAL_AMOUNT", "BAD_FINAL_AMOUNT", gain(w).await);
    let used = 73 * UNIT / 10;
    cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hash, "final_amount": used.to_string()})).await.unwrap();
    let c = cw.credit(&id).await;
    assert_eq!(c["amount"], used.to_string());
    assert_eq!(c["original_amount"], (10 * UNIT).to_string());
    assert_eq!(c["bond_locked"], (used / 2).to_string());
    assert_eq!(c["exposure"], (used - used / 2).to_string());
    assert_eq!(cw.card().await["outstanding"], used.to_string());
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], (used - used / 2).to_string());
    let v: Value = cw.agent.call(w.writ.id(), "settle").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["CreditSettled"]["amount"], used.to_string());
    let got: Value = w.writ.view("claimable_of").args_json(json!({"account": w.merchant.id()})).await?.json()?;
    assert_eq!(got, json!(used.to_string()));
    let p: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert_eq!(p["idx"], 10, "the budget links stay spent");
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B32", "usage order: limit 10, seller bills 7.3, bond and exposure follow, only 7.3 settles", "7.3 paid", "7.3 paid", 0);
    Ok(())
}

#[tokio::test]
async fn b33_a_seller_rule_refuses_is_adjusted_and_ships() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { bond: 2500, accept_ttl: 3600, ..Default::default() }).await?;
    let w = &cw.w;
    let rule = |bond: u32, max: u128, gs: Value| json!({"max_amount": max.to_string(), "max_tenor_secs": "7200", "min_bond_bps": bond, "max_defaults": 0, "guarantors": gs, "asset": null, "max_fee_bps": 10_000, "arbiters": []});
    let dep = NearToken::from_millinear(15);
    // storage deposit not paid
    let r = w.merchant.call(w.writ.id(), "set_seller_policy").args_json(json!({"policy": rule(5000, 3 * UNIT, json!([]))})).transact().await?.into_result();
    assert!(format!("{:?}", r).contains("POLICY_STORAGE"), "{:?}", r);
    bench("A83", "seller makes the contract store a rule without paying for the storage", "POLICY_STORAGE", "POLICY_STORAGE", gain(w).await);
    w.merchant.call(w.writ.id(), "set_seller_policy").args_json(json!({"policy": rule(5000, 3 * UNIT, json!([w.attacker.id()]))})).deposit(dep).transact().await?.into_result()?;

    let id = cw.opened(5, 5, 3600, "INV-RULE").await;
    let c: Value = w.writ.view("check_order").args_json(json!({"credit": id})).await?.json()?;
    assert_eq!(c["ok"], false);
    assert_eq!(c["reasons"], json!(["ORDER_TOO_LARGE", "BOND_TOO_LOW", "GUARANTOR_NOT_APPROVED"]), "{}", c);
    assert_eq!(c["order"]["amount"], (5 * UNIT).to_string());
    assert_eq!(c["order"]["guarantor"], w.verifier.id().as_str());
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("POLICY:ORDER_TOO_LARGE"), "{}", e);
    assert_eq!(cw.credit(&id).await["status"], "Open");
    bench("A84", "an order outside the seller's own rule gets accepted anyway", "POLICY:ORDER_TOO_LARGE", "POLICY:ORDER_TOO_LARGE", gain(w).await);

    // a rule set by someone else counts only for that person, it cannot touch the seller's
    w.attacker.call(w.writ.id(), "set_seller_policy").args_json(json!({"policy": rule(0, 5 * UNIT, json!([]))})).deposit(dep).transact().await?.into_result()?;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("POLICY:ORDER_TOO_LARGE"), "{}", e);

    // first trial with the rule passed in, it is not stored
    let c: Value = w.writ.view("check_order").args_json(json!({"credit": id, "policy": rule(2500, 5 * UNIT, json!([]))})).await?.json()?;
    assert_eq!(c["ok"], true, "{}", c);
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("POLICY:ORDER_TOO_LARGE"), "{}", e);
    // adjust the rule (no deposit needed again) and ship
    cw.seller("set_seller_policy", json!({"policy": rule(2500, 5 * UNIT, json!([w.verifier.id()]))})).await.unwrap();
    let c: Value = w.writ.view("check_order").args_json(json!({"credit": id})).await?.json()?;
    assert_eq!(c["ok"], true, "{}", c);
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["status"], "Accepted");
    bench("B33", "seller rule: refused with reasons, rule adjusted, order ships", "refused, adjusted, accepted", "refused, adjusted, accepted", 0);
    Ok(())
}

#[tokio::test]
async fn a85_a_colluding_seller_can_only_reach_its_share_of_the_stake() -> anyhow::Result<()> {
    // stake 5 NEAR, per-seller cap 0.3% = 1.5 links. Collusion where a straw seller opens an order, delivers and does not pay can draw at most this much at once
    let cw = credit_world_x(CwOpts { cap: 30, accept_ttl: 3600, ..Default::default() }).await?;
    let w = &cw.w;
    assert_eq!(cw.card().await["seller_cap_bps"], 30);
    let first = cw.opened(1, 1, 3600, "INV-STRAW-1").await;
    cw.seller("accept_credit", json!({"credit": first})).await.unwrap();
    let second = cw.opened(2, 1, 3600, "INV-STRAW-2").await;
    let c: Value = w.writ.view("check_order").args_json(json!({"credit": second})).await?.json()?;
    assert_eq!(c["reasons"], json!(["SELLER_CONCENTRATION"]), "{}", c);
    let e = cw.seller("accept_credit", json!({"credit": second})).await.unwrap_err();
    assert!(e.contains("SELLER_CONCENTRATION"), "{}", e);
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], UNIT.to_string());
    bench("A85", "one straw seller account takes more of the stake than its cap at once", "SELLER_CONCENTRATION", "SELLER_CONCENTRATION", gain(w).await);
    // the first order settles, exposure is released, the second order stands
    cw.funder("settle_by_funder", json!({"credit": first}), 0).await.unwrap();
    cw.seller("accept_credit", json!({"credit": second})).await.unwrap();
    assert_eq!(cw.credit(&second).await["status"], "Accepted");
    Ok(())
}

#[tokio::test]
async fn b34_the_guarantor_sees_its_book() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { premium: 1000, vault: 2 * UNIT, ..Default::default() }).await?;
    let w = &cw.w;
    let book = || async { w.writ.view("guarantor_book").args_json(json!({"account": w.verifier.id()})).await.unwrap().json::<Value>().unwrap() };
    assert_eq!(book().await["loss_ratio_bps"], Value::Null);
    let id = cw.delivered(5, 5, 1, "INV-BOOK").await;
    let b = book().await;
    let fee = 5 * UNIT / 10;
    assert_eq!(b["earned"], fee.to_string());
    assert_eq!(b["exposure"], (5 * UNIT).to_string());
    assert_eq!(b["top_sellers"][0]["seller"], w.merchant.id().as_str());
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let debt: u128 = cw.credit(&id).await["debt"].as_str().unwrap().parse()?;
    let b = book().await;
    assert_eq!(b["claims_paid"], debt.to_string());
    assert_eq!(b["net_loss"], debt.to_string());
    assert_eq!(b["loss_ratio_bps"].as_u64().unwrap() as u128, debt * 10_000 / fee);
    cw.funder("reimburse", json!({"credit": id}), debt).await.unwrap();
    let b = book().await;
    assert_eq!(b["recovered"], debt.to_string());
    assert_eq!(b["net_loss"], "0");
    bench("B34", "guarantor book: stake, exposure, earned, claims, recovered, loss ratio, top sellers", "adds up", "adds up", 0);
    Ok(())
}

#[tokio::test]
async fn a86_throwaway_sellers_cannot_grow_the_book_without_limit() -> anyhow::Result<()> {
    let extra: u32 = 10;
    let cw = credit_world_x(CwOpts { extra_sellers: extra, accept_ttl: 3600, ..Default::default() }).await?;
    let w = &cw.w;
    let mut link = 0;
    for (i, s) in cw.extra.iter().enumerate() {
        link += 1;
        let due = now_ns(w).await? + 3_000 * SEC;
        let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(link), "j": 1, "to": s.id(), "invoice_hash": hex::encode(Sha256::digest(format!("INV-{}", i))), "due_at": due.to_string()}))
            .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
        let id = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
        s.call(w.writ.id(), "accept_credit").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    }
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(st["sellers"].as_array().unwrap().len(), 8, "the list has a cap");
    assert_eq!(st["exposure"], (extra as u128 * UNIT).to_string(), "the exposure is still all there");
    let b: Value = w.writ.view("guarantor_book").args_json(json!({"account": w.verifier.id()})).await?.json()?;
    assert_eq!(b["top_sellers"].as_array().unwrap().len(), 5);
    bench("A86", "throwaway sellers grow the guarantor's record until every accept runs out of gas", "list stays at 8", "list stays at 8", gain(w).await);
    Ok(())
}

// ---------------------------------------------------------------- round 13: credit in a stablecoin (6 decimals, contract/ft-mock)

const NEAR_RESERVE: u128 = 1_000_000_000_000_000_000_000_000;

impl CreditWorld {
    /// Token world defaults: vault 30 tokens, stake 50 tokens.
    fn tk(&self) -> &Contract { self.token.as_ref().unwrap() }
    /// who comes in via ft_transfer_call from the token contract, returns how much was actually used (refunded or panic means 0).
    async fn ftcall(&self, who: &Account, amount: u128, msg: String) -> u128 {
        let v: String = who.call(self.tk().id(), "ft_transfer_call").args_json(json!({"receiver_id": self.w.writ.id(), "amount": amount.to_string(), "msg": msg}))
            .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await.unwrap().into_result().unwrap().json().unwrap();
        v.parse().unwrap()
    }
    async fn fbal(&self, who: &AccountId) -> u128 { ft_balance(&self.w, self.tk(), who).await }
    async fn ttotal(&self) -> u128 {
        let v: String = self.w.writ.view("token_total").args_json(json!({"asset": self.tk().id()})).await.unwrap().json().unwrap();
        v.parse().unwrap()
    }
    async fn tstake(&self) -> Value {
        self.w.writ.view("stake_of").args_json(json!({"account": self.w.verifier.id(), "asset": self.tk().id()})).await.unwrap().json().unwrap()
    }
    async fn tclaim(&self, who: &AccountId) -> u128 {
        let v: String = self.w.writ.view("claimable_of").args_json(json!({"account": who, "asset": self.tk().id()})).await.unwrap().json().unwrap();
        v.parse().unwrap()
    }
    /// The total on the books equals the contract's balance in the token: not one token appears or disappears from nowhere.
    async fn token_books_match(&self) {
        assert_eq!(self.ttotal().await, self.fbal(self.w.writ.id()).await, "token books vs token balance");
    }
}

fn tworld() -> CwOpts { CwOpts { token: true, stake: 50, vault: 30 * T, accept_ttl: 3600, ..Default::default() } }

#[tokio::test]
async fn b35_credit_in_a_stablecoin_with_the_seller_paying_the_fee() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { premium: 200, fee_payer: "Seller", bond: 2500, ..tworld() }).await?;
    let w = &cw.w;
    bench("A87", "the credit asset differs from the cell's, or is swapped after the guarantor signed", "CREDIT_ASSET_MISMATCH, BAD_ATTESTATION", "CREDIT_ASSET_MISMATCH, BAD_ATTESTATION", gain(w).await);
    let card = cw.card().await;
    assert_eq!(card["asset"], cw.tk().id().as_str());
    assert_eq!(card["near_reserve"], NEAR_RESERVE.to_string());
    assert_eq!(card["guarantor_stake"], (50 * T).to_string());
    cw.token_books_match().await;
    let n0: Value = w.writ.view("solvency").await?.json()?;
    assert_eq!(n0["solvent"], true);

    // metered order: cap 5 tokens, actual 4 tokens
    let id = cw.opened(5, 5, 3600, "INV-USDC").await;
    let c = cw.credit(&id).await;
    assert_eq!(c["asset"], cw.tk().id().as_str());
    let card = cw.card().await;
    assert!(card["near_reserve"].as_str().unwrap().parse::<u128>()? < NEAR_RESERVE, "the order's storage came out of the NEAR reserve");
    let chk: Value = w.writ.view("check_order").args_json(json!({"credit": id})).await?.json()?;
    assert_eq!(chk["ok"], true, "{}", chk);
    assert_eq!(chk["order"]["seller_receives"], (5 * T - 5 * T / 50).to_string());
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    assert_eq!(cw.credit(&id).await["bond_locked"], (5 * T / 4).to_string());
    assert_eq!(cw.tstake().await["earned"], "0", "nothing charged at accept");
    cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32]), "final_amount": (4 * T).to_string()})).await.unwrap();
    assert_eq!(cw.credit(&id).await["bond_locked"], T.to_string());
    let v: Value = cw.agent.call(w.writ.id(), "settle").args_json(json!({"credit": id})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["CreditSettled"]["amount"], (4 * T).to_string());
    let fee = 4 * T / 50;
    assert_eq!(cw.tclaim(w.merchant.id()).await, 4 * T - fee);
    let st = cw.tstake().await;
    assert_eq!((st["amount"].as_str().unwrap().parse::<u128>()?, st["earned"].as_str().unwrap().parse::<u128>()?), (50 * T + fee, fee));
    cw.token_books_match().await;
    // the seller's withdrawal really gets the tokens
    let before = cw.fbal(w.merchant.id()).await;
    cw.seller("withdraw", json!({"asset": cw.tk().id()})).await.unwrap();
    assert_eq!(cw.fbal(w.merchant.id()).await - before, 4 * T - fee);
    cw.token_books_match().await;
    bench("B35", "credit in a 6-decimal stablecoin: seller pays the fee, usage order, NEAR reserve pays storage", "seller received 3.92 of 4", "seller received 3.92 of 4", 0);
    Ok(())
}

#[tokio::test]
async fn b36_a_stablecoin_default_is_paid_by_the_token_stake_and_recovered_in_the_token() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { vault: 2 * T, ..tworld() }).await?;
    let w = &cw.w;
    let id = cw.delivered(5, 5, 1, "INV-TD").await;
    let other = cw.opened(6, 1, 3600, "INV-OPEN").await;
    cw.seller("accept_credit", json!({"credit": other})).await.unwrap();
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let debt: u128 = cw.credit(&id).await["debt"].as_str().unwrap().parse()?;
    assert_eq!(debt, 3 * T);
    assert_eq!(cw.tclaim(w.merchant.id()).await, 5 * T, "the seller is whole");
    let st = cw.tstake().await;
    assert_eq!(st["amount"], (47 * T).to_string());
    assert_eq!(st["claims_paid"], (3 * T).to_string());
    assert_eq!(cw.card().await["frozen"], true);
    cw.token_books_match().await;
    // the company revokes to leave: the vault money is gone but still owed, the reserve is refunded as NEAR withdrawable, the debt remains
    let f0 = cw.fbal(w.funder.id()).await;
    cw.funder("revoke", json!({"cell": cw.cell.to_string(), "evidence": "skip town"}), 0).await.unwrap();
    assert_eq!(cw.fbal(w.funder.id()).await, f0, "no token comes back while it owes");
    let c: Value = w.writ.view("claimable_of").args_json(json!({"account": w.funder.id()})).await?.json()?;
    assert!(c.as_str().unwrap().parse::<u128>()? > 0, "the unused NEAR reserve is the company's");
    let n0 = balance(&w.funder).await;
    cw.funder("withdraw", json!({}), 0).await.unwrap();
    assert!(balance(&w.funder).await > n0);
    // repay: one token short is not enough, the excess is recorded as withdrawable
    let f0 = cw.fbal(w.funder.id()).await;
    assert_eq!(cw.ftcall(&w.funder, debt - 1, format!("reimburse:{}", id)).await, 0, "refunded in full");
    assert_eq!(cw.fbal(w.funder.id()).await, f0);
    assert_eq!(cw.ftcall(&w.funder, debt + 5, format!("reimburse:{}", id)).await, debt + 5);
    assert_eq!(cw.credit(&id).await["status"], "Reimbursed");
    assert_eq!(cw.tclaim(w.funder.id()).await, 5);
    assert_eq!(cw.tstake().await["recovered"], debt.to_string());
    assert_eq!(cw.card().await["frozen"], false);
    // another order is still open: finish after it settles
    assert_eq!(cw.ftcall(&w.funder, T, format!("settle:{}", other)).await, T);
    assert_eq!(cw.card().await["outstanding"], "0");
    cw.token_books_match().await;
    let b: Value = w.writ.view("guarantor_book").args_json(json!({"account": w.verifier.id(), "asset": cw.tk().id()})).await?.json()?;
    assert_eq!(b["net_loss"], "0");
    assert_eq!(cw.solvent().await["solvent"], true);
    bench("B36", "stablecoin default: the token stake pays the seller, the company repays in the token, revoking does not escape", "seller whole, debt repaid", "seller whole, debt repaid", 0);
    Ok(())
}

#[tokio::test]
async fn b37_a_token_tree_hires_disputes_and_closes_per_asset() -> anyhow::Result<()> {
    let cw = credit_world_x(tworld()).await?;
    let w = &cw.w;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    let until = c["valid_until"].as_str().unwrap().to_string();
    let reserve0 = cw.card().await["near_reserve"].as_str().unwrap().parse::<u128>()?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let cpw = Payword::new(3);
    let v = hire(&cw.agent, w.writ.id(), &cw.pw.link(3), 3, hire_args(&sk.public_key(), &cpw, &[w.merchant.id()], &until, 3, 3)).await;
    let child: u64 = v["Hired"]["child"].as_str().unwrap_or_else(|| panic!("{}", v)).parse()?;
    let cagent = Account::from_secret_key(w.writ.id().clone(), sk, &w.worker);
    let ch: Value = w.writ.view("get_cell").args_json(json!({"cell": child.to_string()})).await?.json()?;
    assert_eq!(ch["vault"], (3 * T).to_string());
    assert_eq!(ch["asset"], cw.tk().id().as_str());
    let reserve1 = cw.card().await["near_reserve"].as_str().unwrap().parse::<u128>()?;
    assert_eq!(reserve0 - reserve1, 100_000_000_000_000_000_000_000 + 20_000_000_000_000_000_000_000 + 3_000_000_000_000_000_000_000, "the hire fee is NEAR from the reserve");
    let m0 = cw.fbal(w.merchant.id()).await;
    let v = spend(&cagent, w.writ.id(), &cpw.link(1), 1, w.merchant.id()).await.unwrap();
    assert!(v.get("Paid").is_some(), "{}", v);
    assert_eq!(cw.fbal(w.merchant.id()).await - m0, T, "the sub-agent pays in the token");
    cw.token_books_match().await;

    // dispute: the deposit is tokens; ruled for the company refunds everything, ruled for the seller pays the seller
    let lose = cw.delivered(4, 1, 3600, "INV-D1").await;
    assert_eq!(cw.ftcall(&w.funder, T, format!("dispute:{}:{}", lose, hex::encode([2u8; 32]))).await, T);
    assert_eq!(cw.credit(&lose).await["dispute_escrow"], T.to_string());
    cw.arbiter.call(w.writ.id(), "resolve_dispute").args_json(json!({"credit": lose, "to_seller": false})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    assert_eq!(cw.tclaim(w.funder.id()).await, T);
    let win = cw.delivered(5, 1, 3600, "INV-D2").await;
    assert_eq!(cw.ftcall(&w.funder, T + 3, format!("dispute:{}:{}", win, hex::encode([2u8; 32]))).await, T + 3);
    cw.arbiter.call(w.writ.id(), "resolve_dispute").args_json(json!({"credit": win, "to_seller": true})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    assert_eq!(cw.tclaim(w.merchant.id()).await, T);
    assert_eq!(cw.tclaim(w.funder.id()).await, T + 3);
    cw.token_books_match().await;

    // the whole tree is shut down: tokens go back to the legal entity, the reserve goes back as NEAR withdrawable, both books are cleared
    let open_one = cw.delivered(6, 1, 3600, "INV-KEEP").await;
    let f0 = cw.fbal(w.funder.id()).await;
    let vault = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json::<Value>()?["vault"].as_str().unwrap().parse::<u128>()?;
    cw.funder("revoke", json!({"cell": cw.cell.to_string(), "evidence": "fired"}), 0).await.unwrap();
    assert_eq!(cw.fbal(w.funder.id()).await, f0, "held back while an order is open");
    let r: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert_eq!(r["vault"], (vault + 2 * T).to_string(), "the sub-agent's tokens came home to the root");
    let ckid: Value = w.writ.view("get_cell").args_json(json!({"cell": child.to_string()})).await?.json()?;
    assert_eq!(ckid["vault"], "0");
    cw.seller("claim_default", json!({"credit": open_one})).await.unwrap_err();
    assert_eq!(cw.ftcall(&w.funder, T, format!("settle:{}", open_one)).await, T);
    let r: Value = w.writ.view("get_cell").args_json(json!({"cell": cw.cell.to_string()})).await?.json()?;
    assert_eq!((r["vault"].as_str().unwrap(), r["unclaimed"].as_str().unwrap().parse::<u128>()?), ("0", vault + 2 * T), "released");
    cw.funder("claim_refund", json!({"cell": cw.cell.to_string()}), 0).await.unwrap();
    assert_eq!(cw.fbal(w.funder.id()).await, f0 - T + vault + 2 * T);
    cw.token_books_match().await;
    bench("B37", "token tree: hire, sub-agent pays, disputes in escrow, retention and release per asset", "books match the token balance", "books match the token balance", 0);
    Ok(())
}

#[tokio::test]
async fn a88_near_cannot_stand_in_for_the_token() -> anyhow::Result<()> {
    let cw = credit_world_x(tworld()).await?;
    let w = &cw.w;
    let id = cw.delivered(5, 5, 3600, "INV-CONFUSE").await;
    // The smallest unit of 5 stablecoin tokens is 5,000,000: 5,000,000 yoctoNEAR is almost worthless. The contract must not treat it as 5 tokens
    let e = cw.funder("settle_by_funder", json!({"credit": id}), 5 * T).await.unwrap_err();
    assert!(e.contains("USE_FT_TRANSFER_CALL"), "{}", e);
    let e = cw.funder("dispute", json!({"credit": id, "reason_hash": hex::encode([2u8; 32])}), 5 * T).await.unwrap_err();
    assert!(e.contains("USE_FT_TRANSFER_CALL"), "{}", e);
    assert_eq!(cw.credit(&id).await["status"], "Delivered");
    bench("A88", "company settles a 5-token order with 5,000,000 yoctoNEAR", "USE_FT_TRANSFER_CALL", "USE_FT_TRANSFER_CALL", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a89_a_fake_token_cannot_credit_itself() -> anyhow::Result<()> {
    let cw = credit_world_x(tworld()).await?;
    let w = &cw.w;
    let id = cw.delivered(5, 5, 3600, "INV-FAKE").await;
    // the attacker acts as the "token contract" itself and calls ft_on_transfer directly, claiming the company paid
    let call = |sender: &AccountId, msg: String| {
        let (a, wr, s) = (w.attacker.clone(), w.writ.id().clone(), sender.clone());
        async move { a.call(&wr, "ft_on_transfer").args_json(json!({"sender_id": s, "amount": (5 * T).to_string(), "msg": msg})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await.unwrap().into_result() }
    };
    let e = call(w.funder.id(), format!("settle:{}", id)).await;
    assert!(format!("{:?}", e).contains("WRONG_ASSET"), "{:?}", e);
    let e = call(w.verifier.id(), "stake".to_string()).await;
    assert!(format!("{:?}", e).contains("STAKE_ASSET_UNKNOWN"), "{:?}", e);
    let st: Value = w.writ.view("stake_of").args_json(json!({"account": w.verifier.id(), "asset": w.attacker.id()})).await?.json()?;
    assert_eq!(st, Value::Null, "a fake token opens no stake record");
    assert_eq!(cw.credit(&id).await["status"], "Delivered");
    // another real token is the same: refunded in full after a panic
    let other = w.worker.dev_deploy(&std::fs::read(FT_WASM)?).await?;
    other.call("new").args_json(json!({"owner_id": w.funder.id(), "total_supply": (100 * T).to_string()})).transact().await?.into_result()?;
    w.funder.call(other.id(), "storage_deposit").args_json(json!({"account_id": w.writ.id()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    let v: String = w.funder.call(other.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": (5 * T).to_string(), "msg": format!("settle:{}", id)}))
        .deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?.json()?;
    assert_eq!(v, "0");
    assert_eq!(ft_balance(w, &other, w.funder.id()).await, 100 * T, "refunded");
    assert_eq!(cw.credit(&id).await["status"], "Delivered");
    // a stranger tries to run the dispute for the company: cannot take anything and cannot stop the seller
    w.funder.call(cw.tk().id(), "ft_transfer").args_json(json!({"receiver_id": w.attacker.id(), "amount": (5 * T).to_string()})).deposit(NearToken::from_yoctonear(1)).transact().await?.into_result()?;
    assert_eq!(cw.ftcall(&w.attacker, 5 * T, format!("dispute:{}:{}", id, hex::encode([2u8; 32]))).await, 0);
    assert_eq!(cw.fbal(w.attacker.id()).await, 5 * T);
    assert_eq!(cw.credit(&id).await["status"], "Delivered");
    bench("A89", "attacker poses as the token, or pays with another token, to settle or stake", "WRONG_ASSET, STAKE_ASSET_UNKNOWN", "WRONG_ASSET, STAKE_ASSET_UNKNOWN", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a90_a_failed_token_withdrawal_neither_loses_nor_duplicates() -> anyhow::Result<()> {
    let cw = credit_world_x(tworld()).await?;
    let w = &cw.w;
    let id = cw.delivered(5, 5, 3600, "INV-FAIL").await;
    cw.funder("settle_by_funder", json!({"credit": id}), 0).await.unwrap();
    assert_eq!(cw.tclaim(w.merchant.id()).await, 5 * T);
    // the seller leaves the token: ft_transfer must fail
    w.merchant.call(cw.tk().id(), "storage_unregister").args_json(json!({})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    let t0 = cw.ttotal().await;
    let _ = cw.seller("withdraw", json!({"asset": cw.tk().id()})).await;
    assert_eq!(cw.tclaim(w.merchant.id()).await, 5 * T, "credited back");
    assert_eq!(cw.ttotal().await, t0);
    cw.token_books_match().await;
    // after coming back and registering it is paid out, and only once
    w.funder.call(cw.tk().id(), "storage_deposit").args_json(json!({"account_id": w.merchant.id()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    cw.seller("withdraw", json!({"asset": cw.tk().id()})).await.unwrap();
    assert_eq!(cw.fbal(w.merchant.id()).await, 5 * T);
    let e = cw.seller("withdraw", json!({"asset": cw.tk().id()})).await.unwrap_err();
    assert!(e.contains("NOTHING_TO_WITHDRAW"), "{}", e);
    cw.token_books_match().await;
    bench("A90", "a token transfer that fails is used to lose or double the seller's money", "credited back once", "credited back once", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a91_a_stake_in_near_does_not_back_a_token_order() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { stake: 0, ..tworld() }).await?;
    let w = &cw.w;
    w.verifier.call(w.writ.id(), "stake").deposit(NearToken::from_near(5)).transact().await?.into_result()?;
    let id = cw.opened(1, 1, 3600, "INV-MISMATCH").await;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("GUARANTOR_CAPACITY"), "{}", e);
    bench("A91", "guarantor backs a stablecoin order with a stake in NEAR", "GUARANTOR_CAPACITY", "GUARANTOR_CAPACITY", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a92_a_token_cell_without_credit_stays_as_it_was() -> anyhow::Result<()> {
    let w = world().await?;
    let token = w.worker.dev_deploy(&std::fs::read(FT_WASM)?).await?;
    token.call("new").args_json(json!({"owner_id": w.funder.id(), "total_supply": (1_000 * T).to_string()})).transact().await?.into_result()?;
    w.funder.call(token.id(), "storage_deposit").args_json(json!({"account_id": w.writ.id()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    let mut o = default_opts(&w);
    o.asset = Some(token.id().clone());
    o.unit = T / 10;
    let (cell, agent, pw) = open_cell(&w, o).await?;
    w.funder.call(token.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": (5 * T).to_string(), "msg": cell.to_string()})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
    let c: Value = w.writ.view("get_cell").args_json(json!({"cell": cell.to_string()})).await?.json()?;
    assert_eq!(c["near_reserve"], "0", "no credit terms, no reserve");
    let v = hire(&agent, w.writ.id(), &pw.link(1), 1, hire_args(&SecretKey::from_random(KeyType::ED25519).public_key(), &Payword::new(1), &[w.merchant.id()], c["valid_until"].as_str().unwrap(), 1, 1)).await;
    assert_eq!(v["Rejected"]["reason"], "HIRE_TOKEN");
    let r = w.funder.call(w.writ.id(), "top_up").args_json(json!({"cell": cell.to_string()})).deposit(NearToken::from_near(1)).transact().await?.into_result();
    assert!(format!("{:?}", r).contains("TOKEN_CELL_USE_FT_TRANSFER_CALL"));
    let t: String = w.writ.view("token_total").args_json(json!({"asset": token.id()})).await?.json()?;
    assert_eq!(t, (5 * T).to_string());
    bench("A92", "a plain token cell with no credit terms hires, or takes NEAR it could never return", "HIRE_TOKEN, TOKEN_CELL_USE_FT_TRANSFER_CALL", "HIRE_TOKEN, TOKEN_CELL_USE_FT_TRANSFER_CALL", gain(&w).await);
    Ok(())
}

/// Whether receipt storage is enough for real usage: includes the seller exposure record that appears for the first time.
#[tokio::test]
async fn b38_the_order_fee_covers_the_storage_it_uses() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { accept_ttl: 3600, ..Default::default() }).await?;
    let w = &cw.w;
    let a = w.writ.view_account().await?.storage_usage as u128;
    let id = cw.delivered(1, 1, 3600, "INV-STORAGE").await;
    let b = w.writ.view_account().await?.storage_usage as u128;
    let cost = (b - a) * 10_000_000_000_000_000_000u128;
    println!("WRIT_GAS|order_storage_bytes={}", b - a);
    // invoice record prepaid per link + receipt storage fee
    let paid = 7_000_000_000_000_000_000_000u128 + 1_000_000_000_000_000_000_000u128;
    assert!(cost <= paid, "{} bytes cost {} > paid {}", b - a, cost, paid);
    assert_eq!(cw.credit(&id).await["status"], "Delivered");
    bench("B38", "an order's storage, including the per-seller record, is paid by the order", "cost <= fee", &format!("{} bytes", b - a), 0);
    Ok(())
}

#[tokio::test]
async fn b39_the_contract_says_where_its_source_is_and_check_order_gives_a_seller_ui_its_fields() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { bond: 2500, premium: 200, fee_payer: "Seller", accept_ttl: 3600, ..Default::default() }).await?;
    let w = &cw.w;
    let m: Value = w.writ.view("contract_source_metadata").await?.json()?;
    assert_eq!(m["version"], "0.2.0");
    assert_eq!(m["link"], "https://github.com/zuemen/writ");
    assert!(m["standards"].as_array().unwrap().iter().any(|s| s["standard"] == "nep330"), "{}", m);
    let id = cw.opened(4, 4, 3600, "INV-UI").await;
    let c: Value = w.writ.view("check_order").args_json(json!({"credit": id})).await?.json()?;
    let o = &c["order"];
    assert_eq!(o["amount"], (4 * UNIT).to_string());
    assert_eq!(o["asset"], Value::Null, "null means NEAR");
    assert!(o["tenor_secs"].as_str().unwrap().parse::<u64>()? <= 3600);
    assert_eq!(o["bond"], UNIT.to_string());
    assert_eq!(o["exposure"], (3 * UNIT).to_string());
    assert_eq!(o["fee"], (4 * UNIT / 50).to_string());
    assert_eq!(o["fee_payer"], "Seller");
    bench("B39", "NEP-330 source metadata; check_order gives amount, asset, tenor, bond, exposure, fee, payer", "all present", "all present", 0);
    Ok(())
}

#[tokio::test]
async fn a93_terms_with_an_unbounded_tenor_are_refused() -> anyhow::Result<()> {
    // When the due date is close to the u64 limit, due date plus time window overflows, so cancel and claim would fail forever
    let r = credit_world_x(CwOpts { max_tenor: 10 * 365 * 86_400 + 1, ..Default::default() }).await;
    let e = match r { Ok(_) => panic!("register must refuse"), Err(e) => format!("{:?}", e) };
    assert!(e.contains("BAD_CREDIT_TERMS"), "{}", e);
    let cw = credit_world_x(CwOpts { max_tenor: 10 * 365 * 86_400, ..Default::default() }).await?;
    bench("A93", "guarantor signs a tenor long enough to overflow the deadlines, so an order can never end", "BAD_CREDIT_TERMS", "BAD_CREDIT_TERMS", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a94_a_rule_catches_the_wrong_asset_a_high_fee_and_an_unknown_arbiter() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { premium: 2000, fee_payer: "Seller", max_tenor: 200 * 86_400, accept_ttl: 3600, ..tworld() }).await?;
    let w = &cw.w;
    // The NEAR-unit cap is effectively no cap for a 6-decimal token: a rule that does not name this token does not accept it
    let rule = json!({"max_amount": (100u128 * 1_000_000_000_000_000_000_000_000).to_string(), "max_tenor_secs": "20000000", "min_bond_bps": 0, "max_defaults": 0, "guarantors": [], "asset": null, "max_fee_bps": 500, "arbiters": [w.attacker.id()]});
    // a rule without an asset cannot open
    let mut missing = rule.clone();
    missing.as_object_mut().unwrap().remove("asset");
    let r = w.merchant.call(w.writ.id(), "set_seller_policy").args_json(json!({"policy": missing})).deposit(NearToken::from_millinear(15)).transact().await?.into_result();
    assert!(r.is_err(), "a rule must name its asset");
    w.merchant.call(w.writ.id(), "set_seller_policy").args_json(json!({"policy": rule})).deposit(NearToken::from_millinear(15)).transact().await?.into_result()?;
    let due = now_ns(w).await? + 150 * 86_400 * SEC;
    let v: Value = cw.agent.call(w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(5), "j": 5, "to": w.merchant.id(), "invoice_hash": hex::encode(Sha256::digest("INV-EMPTY")), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    let id = v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
    let c: Value = w.writ.view("check_order").args_json(json!({"credit": id})).await?.json()?;
    assert_eq!(c["reasons"], json!(["ASSET_NOT_APPROVED", "FEE_TOO_HIGH", "ARBITER_NOT_APPROVED"]), "{}", c);
    assert_eq!(c["would_accept"], false);
    assert_eq!(c["order"]["seller_receives"], "0", "five periods at 20% take the whole amount");
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("POLICY:ASSET_NOT_APPROVED"), "{}", e);
    bench("A94", "an order in a scaled or fake asset, with a fee that empties it or a friendly arbiter, passes the seller's rule", "ASSET_NOT_APPROVED, FEE_TOO_HIGH, ARBITER_NOT_APPROVED", "ASSET_NOT_APPROVED, FEE_TOO_HIGH, ARBITER_NOT_APPROVED", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a95_one_yocto_cannot_create_a_row_and_a_delisted_guarantor_takes_no_order() -> anyhow::Result<()> {
    let cw = credit_world_x(CwOpts { accept_ttl: 3600, ..Default::default() }).await?;
    let w = &cw.w;
    let s0 = w.writ.view_account().await?.storage_usage;
    let t0 = cw.solvent().await["vault_total"].clone();
    w.attacker.call(w.writ.id(), "set_seller_policy").args_json(json!({"policy": null})).deposit(NearToken::from_yoctonear(1)).transact().await?.into_result()?;
    assert_eq!(w.writ.view_account().await?.storage_usage, s0, "no row for one yocto");
    assert_eq!(cw.solvent().await["vault_total"], t0);
    let c: Value = w.writ.view("claimable_of").args_json(json!({"account": w.attacker.id()})).await?.json()?;
    assert_eq!(c, "0");
    bench("A95", "throwaway accounts make the contract store a row for one yocto each", "no row, excess returned", "no row, excess returned", gain(w).await);
    let id = cw.opened(1, 1, 3600, "INV-DELIST").await;
    w.writ.call("set_verifier").args_json(json!({"account": w.verifier.id()})).transact().await?.into_result()?;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("GUARANTOR_DELISTED"), "{}", e);
    bench("A96", "a seller's order is accepted on a guarantor the owner has delisted", "GUARANTOR_DELISTED", "GUARANTOR_DELISTED", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a78_a_company_with_no_money_for_the_fee_gets_no_guarantee() -> anyhow::Result<()> {
    let cw = credit_world_fee(0, 2000, 5, 0, 1, UNIT, LEI, 0).await?;
    // 1 link of vault minus receipt storage is less than 1 link; 20% of 5 links is 1 link, cannot afford it
    let id = cw.opened(5, 5, 3600, "INV-NOFEE").await;
    let e = cw.seller("accept_credit", json!({"credit": id})).await.unwrap_err();
    assert!(e.contains("PREMIUM_SHORT"), "{}", e);
    let st: Value = cw.w.writ.view("stake_of").args_json(json!({"account": cw.w.verifier.id()})).await?.json()?;
    assert_eq!(st["exposure"], "0");
    bench("A78", "a company with an empty vault takes a guarantee without paying for it", "PREMIUM_SHORT", "PREMIUM_SHORT", gain(&cw.w).await);
    Ok(())
}

// ---------------------------------------------------------------- round 15: fooled-agent cover

const COVER_LINK: u128 = 4_000_000_000_000_000_000_000; // COVER_STORAGE_PER_LINK
fn cover_fee(n: u32) -> u128 { fee(n) + n as u128 * COVER_LINK }
fn h(s: &str) -> String { hex::encode(Sha256::digest(s)) }
const TG: u64 = 150;

/// Options of a mandate with cover. Limits are in links. Defaults: 100 links of 5 at most, limit 50 links, 20% share, no fee.
#[derive(Clone)]
struct CvOpts { n: u32, max_links: u32, limit_links: u128, ded: u32, premium: u32, window: u64, dispute: u64, valid_secs: u64, vault: u128, stake: u128, token: bool, credit: bool, bond: u32, max_strikes: u32 }
impl Default for CvOpts {
    fn default() -> Self {
        Self { n: 100, max_links: 5, limit_links: 50, ded: 2000, premium: 0, window: 600, dispute: 5, valid_secs: 3600, vault: 200 * UNIT, stake: 5, token: false, credit: false, bond: 0, max_strikes: 3 }
    }
}

struct CoverWorld { w: World, cell: u64, agent: Account, pw: Payword, arbiter: Account, token: Option<Contract>, x: CvOpts }

/// Builds the signed register arguments for this world.
async fn cover_args(w: &World, x: &CvOpts, arbiter: &AccountId, asset: Option<&AccountId>, unit: u128) -> anyhow::Result<(Value, SecretKey, Payword)> {
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let pw = Payword::new(x.n);
    let until = now_ns(w).await? + x.valid_secs * SEC;
    let o = default_opts(w);
    let mut args = json!({
        "amc_said": format!("EAMC_COVER_{}", rand::random::<u32>()), "issuer_aid": o.issuer_aid, "issuer_pk": o.issuer_pk, "max_links": x.max_links, "max_strikes": x.max_strikes,
        "attested_at": ATTESTED_NOW.to_string(), "agent_pk": agent_sk.public_key(), "w0": pw.w0(), "n": x.n, "unit": unit.to_string(),
        "scope": [w.merchant.id()], "valid_until": until.to_string(), "daily_links": x.n,
        "lei_commit": hex::encode(Sha256::digest(format!("{}|{}", LEI, LEI_SALT))), "ecr_commit": o.ecr_commit, "verifier": w.verifier.id(),
        "cover": {"limit": (x.limit_links * unit).to_string(), "deductible_bps": x.ded, "premium_bps": x.premium, "claim_window": x.window.to_string(), "arbiter": arbiter, "terms_hash": h("cover terms")},
    });
    if let Some(t) = asset { args["asset"] = json!(t); }
    if x.credit {
        args["credit"] = json!({"limit": (20 * unit).to_string(), "bond_bps": x.bond, "premium_bps": 0, "min_tenor": "0", "max_tenor": "3600", "terms_hash": hex::encode([0xabu8; 32]),
            "terms_sig": "00".repeat(64), "entity_tag": "ENTITY-7", "arbiter": arbiter, "fee_payer": "Buyer", "seller_cap_bps": 0});
        if let Some(t) = asset { args["credit"]["asset"] = json!(t); }
    }
    sign_args(w, &mut args);
    Ok((args, agent_sk, pw))
}

fn sign_args(w: &World, args: &mut Value) {
    args["signature"] = json!(hex::encode(w.verifier_sk.sign(attest_msg(args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
}

async fn try_register(w: &World, args: &Value, deposit: u128) -> Result<String, String> {
    let r = w.funder.call(w.writ.id(), "register").args_json(json!({"args": args})).deposit(NearToken::from_yoctonear(deposit)).max_gas().transact().await.map_err(|e| e.to_string())?;
    match r.into_result() { Ok(v) => Ok(v.json::<String>().unwrap()), Err(e) => Err(format!("{:?}", e)) }
}

async fn cover_world(x: CvOpts) -> anyhow::Result<CoverWorld> {
    let worker = near_workspaces::sandbox().await?;
    let writ = worker.dev_deploy(&wasm_bytes()?).await?;
    writ.call("new").args_json(json!({"owner": writ.id(), "unseal_delay_secs": 5,
        "windows": {"accept_ttl": "3600", "inspect": "0", "grace": "0", "recourse": "1", "dispute_timeout": x.dispute.to_string(), "unstake_delay": "1"}}))
        .transact().await?.into_result()?;
    let verifier = worker.dev_create_account().await?;
    let funder = worker.dev_create_account().await?;
    let merchant = worker.dev_create_account().await?;
    let attacker = worker.dev_create_account().await?;
    let arbiter = worker.dev_create_account().await?;
    let verifier_sk = SigningKey::generate(&mut rand::thread_rng());
    writ.call("set_verifier").args_json(json!({"account": verifier.id(), "pk_hex": hex::encode(verifier_sk.verifying_key().to_bytes())})).transact().await?.into_result()?;
    if x.stake > 0 && !x.token {
        verifier.call(writ.id(), "stake").deposit(NearToken::from_near(x.stake)).transact().await?.into_result()?;
    }
    let attacker_start = balance(&attacker).await;
    let w = World { worker, writ, verifier, verifier_sk, funder, merchant, attacker, attacker_start };
    let token = if x.token {
        let t = w.worker.dev_deploy(&std::fs::read(FT_WASM)?).await?;
        t.call("new").args_json(json!({"owner_id": w.funder.id(), "total_supply": (1_000_000 * T).to_string()})).transact().await?.into_result()?;
        for who in [w.writ.id(), w.merchant.id(), w.verifier.id(), w.attacker.id()] {
            w.funder.call(t.id(), "storage_deposit").args_json(json!({"account_id": who})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
        }
        Some(t)
    } else { None };
    let unit = if x.token { T } else { UNIT };
    let (args, agent_sk, pw) = cover_args(&w, &x, arbiter.id(), token.as_ref().map(|t| t.id()), unit).await?;
    // A token mandate's excess NEAR is refunded or becomes the reserve; a NEAR mandate's excess is the vault
    let deposit = if x.token { cover_fee(x.n) + NEAR_RESERVE } else { cover_fee(x.n) + x.vault };
    let id = try_register(&w, &args, deposit).await.map_err(|e| anyhow::anyhow!(e))?;
    let agent = Account::from_secret_key(w.writ.id().clone(), agent_sk, &w.worker);
    if let Some(t) = &token {
        w.funder.call(t.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": x.vault.to_string(), "msg": id.clone()})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
        if x.stake > 0 {
            w.funder.call(t.id(), "ft_transfer").args_json(json!({"receiver_id": w.verifier.id(), "amount": (x.stake * T).to_string()})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
            w.verifier.call(t.id(), "ft_transfer_call").args_json(json!({"receiver_id": w.writ.id(), "amount": (x.stake * T).to_string(), "msg": "stake"})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
        }
    }
    Ok(CoverWorld { w, cell: id.parse()?, agent, pw, arbiter, token, x })
}

impl CoverWorld {
    fn root(&self) -> String { self.cell.to_string() }
    async fn act(&self, who: &Account, method: &str, args: Value) -> Result<(), String> {
        let r = who.call(self.w.writ.id(), method).args_json(args).gas(near_workspaces::types::Gas::from_tgas(TG)).transact().await.map_err(|e| e.to_string())?;
        r.into_result().map(|_| ()).map_err(|e| format!("{:?}", e))
    }
    async fn activate(&self) -> Result<(), String> { self.act(&self.w.verifier, "activate_cover", json!({"root": self.root()})).await }
    async fn pay(&self, agent: &Account, pre: String, j: u32, inv: &str) -> Value {
        agent.call(self.w.writ.id(), "spend").args_json(json!({"preimage": pre, "j": j, "to": self.w.merchant.id(), "invoice_hash": h(inv), "context_hash": h(&format!("invoice text and model output of {}", inv))}))
            .gas(near_workspaces::types::Gas::from_tgas(80)).transact().await.unwrap().into_result().unwrap().json().unwrap()
    }
    /// Pays from the root and requires it to go through.
    async fn paid(&self, link: u32, j: u32, inv: &str) {
        let v = self.pay(&self.agent, self.pw.link(link), j, inv).await;
        assert!(v.get("Paid").is_some(), "{}", v);
    }
    async fn file(&self, inv: &str) -> Result<(), String> { self.act(&self.w.funder, "file_claim", json!({"root": self.root(), "invoice_hash": h(inv), "evidence_hash": h("evidence")})).await }
    async fn rule(&self, inv: &str, ruling: Value) -> Result<(), String> { self.act(&self.arbiter, "resolve_claim", json!({"root": self.root(), "invoice_hash": h(inv), "ruling": ruling, "ruling_hash": h("the reasons")})).await }
    async fn uphold(&self, inv: &str, loss: u128) -> Result<(), String> { self.rule(inv, json!({"Uphold": {"loss": loss.to_string()}})).await }
    async fn deny(&self, inv: &str) -> Result<(), String> { self.rule(inv, json!("Deny")).await }
    async fn clear(&self) -> Result<(), String> { self.act(&self.w.funder, "clear_agent", json!({"root": self.root()})).await }
    async fn cover(&self) -> Value { self.w.writ.view("cover_of").args_json(json!({"cell": self.root()})).await.unwrap().json().unwrap() }
    async fn rec(&self, inv: &str) -> Value { self.w.writ.view("payment_of").args_json(json!({"cell": self.root(), "invoice_hash": h(inv)})).await.unwrap().json().unwrap() }
    async fn stake(&self) -> Value {
        let a = self.token.as_ref().map(|t| t.id().clone());
        self.w.writ.view("stake_of").args_json(json!({"account": self.w.verifier.id(), "asset": a})).await.unwrap().json().unwrap()
    }
    async fn claim(&self, who: &AccountId) -> u128 {
        let a = self.token.as_ref().map(|t| t.id().clone());
        let v: String = self.w.writ.view("claimable_of").args_json(json!({"account": who, "asset": a})).await.unwrap().json().unwrap();
        v.parse().unwrap()
    }
    async fn cell_state(&self) -> Value { self.w.writ.view("get_cell").args_json(json!({"cell": self.root()})).await.unwrap().json().unwrap() }
    async fn solvent(&self) -> bool { let v: Value = self.w.writ.view("solvency").await.unwrap().json().unwrap(); v["solvent"] == true }
    async fn open_order(&self, link: u32, j: u32, due_in: u64, inv: &str) -> String {
        let due = now_ns(&self.w).await.unwrap() + due_in * SEC;
        let v: Value = self.agent.call(self.w.writ.id(), "open_credit").args_json(json!({"preimage": self.pw.link(link), "j": j, "to": self.w.merchant.id(), "invoice_hash": h(inv), "due_at": due.to_string()}))
            .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await.unwrap().into_result().unwrap().json().unwrap();
        v["CreditOpened"]["credit"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string()
    }
    async fn seller(&self, method: &str, args: Value) -> Result<(), String> { self.act(&self.w.merchant, method, args).await }
}
#[track_caller]
fn must(r: Result<(), String>, code: &str) {
    let e = r.expect_err(code);
    assert!(e.contains(code), "{} vs {}", e, code);
}

#[tokio::test]
async fn a97_dismissing_the_sub_agent_that_paid_does_not_escape_the_stop() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    cw.activate().await.unwrap();
    let child_sk = SecretKey::from_random(KeyType::ED25519);
    let child_pw = Payword::new(5);
    let until = cw.cell_state().await["valid_until"].as_str().unwrap().to_string();
    let v = hire(&cw.agent, cw.w.writ.id(), &cw.pw.link(5), 5, json!({"agent_pk": child_sk.public_key(), "w0": child_pw.w0(), "scope": [cw.w.merchant.id()], "valid_until": until, "daily_links": 5, "max_links": 5})).await;
    let child: String = v["Hired"]["child"].as_str().unwrap_or_else(|| panic!("{}", v)).to_string();
    let child_agent = Account::from_secret_key(cw.w.writ.id().clone(), child_sk, &cw.w.worker);
    let v = cw.pay(&child_agent, child_pw.link(2), 2, "INV-CHILD").await;
    assert!(v.get("Paid").is_some(), "{}", v);
    cw.agent.call(cw.w.writ.id(), "dismiss").args_json(json!({"child": child})).gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?;
    cw.file("INV-CHILD").await.unwrap();
    assert_eq!(cw.cover().await["open_claim"], h("INV-CHILD"));
    let v = cw.pay(&cw.agent, cw.pw.link(6), 1, "INV-AFTER").await;
    assert_eq!(v["Rejected"]["reason"], "UNDER_CLAIM", "{}", v);
    assert_eq!(v["Rejected"]["strikes"], 0, "the claim costs the agent nothing");
    let cell: Value = cw.w.writ.view("cover_of").args_json(json!({"cell": child})).await?.json()?;
    assert_eq!(cell["open_claim"], h("INV-CHILD"), "the dismissed cell still finds the cover");
    bench("A97", "agent hires a sub-agent, it pays, it is dismissed, the company claims: the stop lands on a closed cell", "whole tree UNDER_CLAIM", "whole tree UNDER_CLAIM", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a98_a_claim_gets_the_loss_not_the_payment() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    cw.activate().await.unwrap();
    cw.paid(3, 3, "INV-OVER").await;
    cw.file("INV-OVER").await.unwrap();
    must(cw.uphold("INV-OVER", 3 * UNIT + 1).await, "BAD_LOSS");
    bench("A98", "the arbiter awards more than the payment", "BAD_LOSS", "BAD_LOSS", gain(&cw.w).await);
    // The invoice was 2 and the agent paid 3, and the goods arrived: the loss is 1, not 3
    let (st0, cl0) = (cw.stake().await, cw.claim(cw.w.funder.id()).await);
    cw.uphold("INV-OVER", UNIT).await.unwrap();
    let want = UNIT * 8 / 10;
    let st = cw.stake().await;
    assert_eq!(st["amount"].as_str().unwrap().parse::<u128>()?, st0["amount"].as_str().unwrap().parse::<u128>()? - want);
    assert_eq!(st["cover_paid"], want.to_string());
    assert_eq!(cw.claim(cw.w.funder.id()).await - cl0, want);
    let c = cw.cover().await;
    assert_eq!(c["paid"], want.to_string());
    assert_eq!(c["needs_clear"], true);
    assert_eq!(cw.rec("INV-OVER").await["claim"]["Upheld"]["payout"], want.to_string());
    bench("B40", "partial loss: paid 3, lost 1, 20% share: the guarantor pays 0.8, no more", "0.8 of a link", "0.8 of a link", 0);
    Ok(())
}

#[tokio::test]
async fn a126_guarantor_cannot_swap_signers_to_skip_the_fee_it_owes() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { valid_secs: 30, window: 12, dispute: 2, premium: 1000, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    must(cw.act(&cw.w.verifier, "update_signers", json!({"cell": cw.root(), "issuer_aid": "x", "issuer_pk": "ab".repeat(32), "ecr_commit": "cd".repeat(32)})).await, "COVER_ACTIVE");
    bench("A126", "guarantor names itself as signer, to revoke by KEL and skip the fee it owes", "COVER_ACTIVE", "COVER_ACTIVE", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a99_revoking_cannot_release_the_lock_early() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { valid_secs: 30, window: 12, dispute: 2, premium: 1000, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    let earned = cw.stake().await["earned"].clone();
    cw.act(&cw.w.verifier, "revoke", json!({"cell": cw.root(), "evidence": "guarantor walks away"})).await.unwrap();
    let release = || cw.act(&cw.w.verifier, "release_cover", json!({"root": cw.root()}));
    must(release().await, "TOO_EARLY");
    assert_eq!(cw.stake().await["exposure"], (50 * UNIT).to_string(), "the lock stays");
    bench("A99", "guarantor collects the fee, revokes and takes its lock back", "TOO_EARLY", "TOO_EARLY", gain(&cw.w).await);
    wait_secs(44).await;
    release().await.unwrap();
    let st = cw.stake().await;
    assert_eq!((st["exposure"].clone(), st["earned"].clone()), (json!("0"), earned));
    assert_eq!(cw.cover().await["state"], "Released");
    bench("B41", "after valid_until + claim_window the lock comes back; the fee stays", "Released", "Released", 0);
    Ok(())
}

#[tokio::test]
async fn a100_an_upheld_claim_cannot_jump_the_guarantors_debt() -> anyhow::Result<()> {
    // Little in the vault: a 5-link default reaches the guarantor and freezes the company
    let cw = cover_world(CvOpts { credit: true, vault: 6 * UNIT, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    cw.paid(1, 1, "INV-PAID").await;
    let id = cw.open_order(6, 5, 1, "INV-DEFAULT").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    cw.seller("mark_delivered", json!({"credit": id, "delivery_hash": hex::encode([1u8; 32])})).await.unwrap();
    wait_secs(2).await;
    cw.seller("claim_default", json!({"credit": id})).await.unwrap();
    let cr: Value = cw.w.writ.view("credit_of").args_json(json!({"credit": id})).await?.json()?;
    assert_ne!(cr["debt"], "0", "{}", cr);
    let v0: u128 = cw.cell_state().await["vault"].as_str().unwrap().parse()?;
    cw.file("INV-PAID").await.unwrap();
    cw.uphold("INV-PAID", UNIT).await.unwrap();
    let want = UNIT * 8 / 10;
    assert_eq!(cw.claim(cw.w.funder.id()).await, 0, "nothing to take");
    must(cw.act(&cw.w.funder, "withdraw", json!({})).await, "NOTHING_TO_WITHDRAW");
    assert_eq!(cw.cell_state().await["vault"].as_str().unwrap().parse::<u128>()?, v0 + want, "it stays in the root's vault");
    assert!(cw.solvent().await);
    bench("A100", "company in default gets a claim upheld and withdraws the money past its debt", "payout stays in the vault", "payout stays in the vault", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn b42_cover_alone_works_from_activation_to_withdrawal_in_near() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { premium: 200, ..Default::default() }).await?;
    assert_eq!(cw.cover().await["state"], "Offered");
    let card: Value = cw.w.writ.view("risk_card").args_json(json!({"cell": cw.root()})).await?.json()?;
    assert!(card.is_null(), "no credit, no credit card");
    let p: Value = cw.w.writ.view("present").args_json(json!({"cell": cw.root()})).await?.json()?;
    assert_eq!((p["cover"].clone(), p["credit"].clone()), (json!(false), json!(false)), "offered: no money behind it yet");
    let v0: u128 = cw.cell_state().await["vault"].as_str().unwrap().parse()?;
    cw.activate().await.unwrap();
    let premium = 50 * UNIT * 200 / 10_000;
    assert_eq!(cw.cell_state().await["vault"].as_str().unwrap().parse::<u128>()?, v0 - premium);
    let p: Value = cw.w.writ.view("present").args_json(json!({"cell": cw.root()})).await?.json()?;
    assert_eq!(p["cover"], true);
    let st = cw.stake().await;
    assert_eq!((st["earned"].clone(), st["exposure"].clone()), (json!(premium.to_string()), json!((50 * UNIT).to_string())));
    cw.paid(2, 2, "INV-1").await;
    let rec = cw.rec("INV-1").await;
    assert_eq!(rec["context_hash"], h("invoice text and model output of INV-1"), "bound at payment");
    assert_eq!(rec["amount"], (2 * UNIT).to_string());
    cw.file("INV-1").await.unwrap();
    cw.uphold("INV-1", 2 * UNIT).await.unwrap();
    let v = cw.pay(&cw.agent, cw.pw.link(3), 1, "INV-2").await;
    assert_eq!(v["Rejected"]["reason"], "NOT_CLEARED");
    cw.clear().await.unwrap();
    cw.paid(3, 1, "INV-2").await;
    assert_eq!(cw.claim(cw.w.funder.id()).await, 2 * UNIT * 8 / 10);
    cw.act(&cw.w.funder, "withdraw", json!({})).await.unwrap();
    assert_eq!(cw.claim(cw.w.funder.id()).await, 0, "the company took its money");
    assert!(cw.solvent().await);
    bench("B42", "mandate with cover only, in NEAR: fee, lock, payment, claim, repayment, clear, pay again", "works end to end", "works end to end", 0);
    Ok(())
}

#[tokio::test]
async fn b43_cover_alone_works_in_a_token_with_no_near_reserve() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { token: true, vault: 30 * T, stake: 60, premium: 200, ..Default::default() }).await?;
    let t = cw.token.as_ref().unwrap();
    assert_eq!(cw.cell_state().await["near_reserve"], "0", "the extra NEAR goes back");
    cw.activate().await.unwrap();
    let premium = 50 * T * 200 / 10_000;
    assert_eq!(cw.cell_state().await["vault"].as_str().unwrap().parse::<u128>()?, 30 * T - premium);
    assert_eq!(cw.stake().await["amount"], (60 * T + premium).to_string());
    cw.paid(2, 2, "INV-T").await;
    assert_eq!(ft_balance(&cw.w, t, cw.w.merchant.id()).await, 2 * T);
    cw.file("INV-T").await.unwrap();
    cw.uphold("INV-T", 2 * T).await.unwrap();
    let want = 2 * T * 8 / 10;
    assert_eq!(cw.claim(cw.w.funder.id()).await, want);
    let f0 = ft_balance(&cw.w, t, cw.w.funder.id()).await;
    cw.act(&cw.w.funder, "withdraw", json!({"asset": t.id()})).await.unwrap();
    assert_eq!(ft_balance(&cw.w, t, cw.w.funder.id()).await - f0, want);
    let total: String = cw.w.writ.view("token_total").args_json(json!({"asset": t.id()})).await?.json()?;
    assert_eq!(total.parse::<u128>()?, ft_balance(&cw.w, t, cw.w.writ.id()).await, "books match the token balance");
    assert!(cw.solvent().await);
    bench("B43", "mandate with cover only, in a token, no NEAR reserve: same story, paid in the token", "works end to end", "works end to end", 0);
    Ok(())
}

// M7: how much storage one payment really takes, measured on the worst case: the longest account name, a context hash, and an upheld claim.
#[tokio::test]
async fn b44_the_storage_fee_pays_for_the_largest_record() -> anyhow::Result<()> {
    let mut cw = cover_world(CvOpts { n: 10, max_links: 1, limit_links: 10, ded: 1000, window: 3600, dispute: 60, stake: 1, vault: UNIT * 10, ..Default::default() }).await?;
    // A 64-character implicit account as the payee: a NEAR transfer creates it. Needs a mandate of its own.
    let long: AccountId = "ab".repeat(32).parse()?;
    cw.x.n = 10;
    let mut x = cw.x.clone();
    x.stake = 0;
    let (mut args, agent_sk, pw) = cover_args(&cw.w, &x, cw.arbiter.id(), None, UNIT).await?;
    args["scope"] = json!([long]);
    sign_args(&cw.w, &mut args);
    let base = cw.w.writ.view_account().await?.storage_usage;
    let id = try_register(&cw.w, &args, cover_fee(10) + 2 * NEAR_RESERVE).await.map_err(|e| anyhow::anyhow!(e))?;
    let opened = cw.w.writ.view_account().await?.storage_usage - base;
    cw.cell = id.parse()?;
    cw.agent = Account::from_secret_key(cw.w.writ.id().clone(), agent_sk, &cw.w.worker);
    cw.pw = pw;
    cw.w.verifier.call(cw.w.writ.id(), "stake").deposit(NearToken::from_near(1)).transact().await?.into_result()?;
    cw.activate().await.unwrap();
    // The first claim also opens the company's claimable row, so measure from the second
    let mut per_payment = 0u64;
    for k in 1..=10u32 {
        let inv = format!("INV-{}", k);
        let s0 = cw.w.writ.view_account().await?.storage_usage;
        let v: Value = cw.agent.call(cw.w.writ.id(), "spend").args_json(json!({"preimage": cw.pw.link(k), "j": 1, "to": long, "invoice_hash": h(&inv), "context_hash": h("largest context")}))
            .gas(near_workspaces::types::Gas::from_tgas(80)).transact().await?.into_result()?.json()?;
        assert!(v.get("Paid").is_some(), "{}", v);
        cw.file(&inv).await.unwrap();
        cw.uphold(&inv, UNIT).await.unwrap();
        cw.clear().await.unwrap();
        let used = cw.w.writ.view_account().await?.storage_usage - s0;
        if k > 1 { assert!(per_payment == 0 || per_payment == used, "{} then {}", per_payment, used); per_payment = used; }
    }
    // The payment also takes one row in paid_invoices (45 of key, 40 of overhead), which the base fee pays for
    let record = per_payment - 85;
    assert!(record as u128 * 10_000_000_000_000_000_000 <= COVER_LINK, "a record of {} bytes is more than the fee pays", record);
    assert!(per_payment as u128 * 10_000_000_000_000_000_000 <= COVER_LINK + 1_000_000_000_000_000_000_000);
    // And the whole mandate, keys aside, is paid for by what register kept
    let all = cw.w.writ.view_account().await?.storage_usage - base;
    let kept = cover_fee(10) - 250_000_000_000_000_000_000_000;
    assert!(all as u128 * 10_000_000_000_000_000_000 <= kept, "{} bytes", all);
    assert!(cw.solvent().await, "solvency holds after every link was used and claimed");
    println!("COVER_STORAGE|record={}|per_payment={}|mandate_open={}|mandate_total={}", record, per_payment, opened, all);
    bench("B44", "storage per payment: longest account, context hash, upheld claim", "fee covers it", &format!("{} bytes per record, {} yocto per link", record, COVER_LINK), 0);
    Ok(())
}

#[tokio::test]
async fn a101_one_open_claim_one_claim_per_payment_inside_the_window() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { window: 14, dispute: 4, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    cw.paid(1, 1, "INV-1").await;
    cw.paid(2, 1, "INV-2").await;
    cw.paid(3, 1, "INV-3").await;
    must(cw.file("INV-NEVER-PAID").await, "NO_PAYMENT");
    cw.file("INV-1").await.unwrap();
    must(cw.file("INV-2").await, "CLAIM_OPEN");
    bench("A101", "company files twenty claims before the arbiter rules on the first", "CLAIM_OPEN", "CLAIM_OPEN", gain(&cw.w).await);
    cw.deny("INV-1").await.unwrap();
    must(cw.file("INV-1").await, "ALREADY_CLAIMED");
    bench("A102", "company files again on a payment the arbiter denied", "ALREADY_CLAIMED", "ALREADY_CLAIMED", gain(&cw.w).await);
    wait_secs(15).await;
    must(cw.file("INV-3").await, "WINDOW_CLOSED");
    bench("A103", "company claims on an old payment after the window", "WINDOW_CLOSED", "WINDOW_CLOSED", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a104_a_late_ruling_is_refused_and_a_timeout_can_be_filed_again() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { window: 60, dispute: 6, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    cw.paid(1, 1, "INV-1").await;
    cw.file("INV-1").await.unwrap();
    let timeout = || cw.act(&cw.w.attacker, "claim_timeout", json!({"root": cw.root()}));
    must(timeout().await, "ARBITER_STILL_HAS_TIME");
    wait_secs(7).await;
    must(cw.uphold("INV-1", UNIT).await, "RULING_TOO_LATE");
    bench("A104", "arbiter rules after its time ran out", "RULING_TOO_LATE", "RULING_TOO_LATE", gain(&cw.w).await);
    let exposure = cw.stake().await["exposure"].clone();
    timeout().await.unwrap();
    let c = cw.cover().await;
    assert_eq!((c["timed_out"].clone(), c["denied"].clone(), c["open_claim"].clone()), (json!(1), json!(0), Value::Null));
    assert_eq!(cw.stake().await["exposure"], exposure, "nothing paid, nothing released");
    assert_eq!(cw.rec("INV-1").await["claim"], "None");
    cw.paid(2, 1, "INV-2").await;
    cw.file("INV-1").await.unwrap();
    cw.deny("INV-1").await.unwrap();
    assert_eq!(cw.cover().await["denied"], 1);
    bench("B45", "arbiter runs out of time: no payment, no denial, the company can file again, the count is public", "filed again", "filed again", 0);
    Ok(())
}

#[tokio::test]
async fn a105_void_needs_a_denied_claim_and_ends_the_records() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { premium: 100, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    cw.paid(1, 1, "INV-1").await;
    cw.paid(2, 1, "INV-2").await;
    let void = |inv: &'static str| cw.act(&cw.arbiter, "void_cover", json!({"root": cw.root(), "invoice_hash": h(inv)}));
    must(void("INV-1").await, "NOT_DENIED");
    bench("A105", "arbiter ends a company's cover with no denied claim to point at", "NOT_DENIED", "NOT_DENIED", gain(&cw.w).await);
    cw.file("INV-1").await.unwrap();
    cw.deny("INV-1").await.unwrap();
    let earned = cw.stake().await["earned"].clone();
    void("INV-1").await.unwrap();
    let c = cw.cover().await;
    assert_eq!((c["state"].clone(), c["remaining"].clone()), (json!("Voided"), json!("0")));
    let st = cw.stake().await;
    assert_eq!((st["exposure"].clone(), st["earned"].clone()), (json!("0"), earned), "lock back, fee kept");
    cw.paid(3, 1, "INV-3").await;
    assert!(cw.rec("INV-3").await.is_null(), "no record after void");
    must(cw.file("INV-2").await, "COVER_NOT_ACTIVE");
    bench("A106", "company keeps claiming after the arbiter found fraud", "COVER_NOT_ACTIVE", "COVER_NOT_ACTIVE", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a107_a_stop_costs_no_strike_settle_works_and_a_seller_cannot_accept() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { credit: true, max_strikes: 2, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    let accepted = cw.open_order(1, 1, 3600, "INV-A").await;
    cw.seller("accept_credit", json!({"credit": accepted})).await.unwrap();
    let waiting = cw.open_order(2, 1, 3600, "INV-W").await;
    cw.paid(3, 1, "INV-P").await;
    cw.file("INV-P").await.unwrap();
    for k in 0..4 {
        let v = cw.pay(&cw.agent, cw.pw.link(4), 1, &format!("INV-R{}", k)).await;
        assert_eq!((v["Rejected"]["reason"].clone(), v["Rejected"]["strikes"].clone(), v["Rejected"]["tripped"].clone()), (json!("UNDER_CLAIM"), json!(0), json!(false)), "{}", v);
    }
    assert_eq!(cw.cell_state().await["status"], "Active");
    bench("A107", "retrying during its company's claim gets the agent's key deleted", "no strike, key stays", "no strike, key stays", gain(&cw.w).await);
    must(cw.seller("accept_credit", json!({"credit": waiting})).await, "UNDER_CLAIM");
    bench("A108", "seller takes on the guarantor's money while the agent is under a claim", "UNDER_CLAIM", "UNDER_CLAIM", gain(&cw.w).await);
    // Settling is not stopped: that would manufacture a default
    let v: Value = cw.agent.call(cw.w.writ.id(), "settle").args_json(json!({"credit": accepted})).gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert!(v.get("CreditSettled").is_some(), "{}", v);
    bench("B46", "a claim on the tree does not stop settling an order", "settled", "settled", 0);
    Ok(())
}

#[tokio::test]
async fn a109_cover_and_credit_draw_on_one_stake() -> anyhow::Result<()> {
    // Cover locks everything: stake exactly the limit, 5 NEAR = 500 links
    let cw = cover_world(CvOpts { credit: true, n: 600, limit_links: 500, stake: 5, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    let id = cw.open_order(1, 1, 3600, "INV-C").await;
    must(cw.seller("accept_credit", json!({"credit": id})).await, "GUARANTOR_CAPACITY");
    cw.act(&cw.w.verifier, "request_unstake", json!({})).await.unwrap();
    wait_secs(2).await;
    must(cw.act(&cw.w.verifier, "withdraw_stake", json!({"amount": "1"})).await, "STAKE_EXPOSED");
    bench("A109", "cover locks the whole stake, then a seller's order or a withdrawal draws on it again", "GUARANTOR_CAPACITY, STAKE_EXPOSED", "GUARANTOR_CAPACITY, STAKE_EXPOSED", gain(&cw.w).await);
    // The other way: an order takes capacity before the cover locks. 1 NEAR = 100 links of stake, limit 100 links
    let cw = cover_world(CvOpts { credit: true, n: 200, limit_links: 100, stake: 1, ..Default::default() }).await?;
    let id = cw.open_order(1, 1, 3600, "INV-C").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    must(cw.activate().await, "GUARANTOR_CAPACITY");
    assert_eq!(cw.cover().await["state"], "Offered");
    bench("A110", "an order holds the stake, then the guarantor locks the same stake for cover", "GUARANTOR_CAPACITY", "GUARANTOR_CAPACITY", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a111_one_invoice_one_record() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts { credit: true, ..Default::default() }).await?;
    cw.activate().await.unwrap();
    let id = cw.open_order(1, 1, 3600, "INV-1").await;
    let v = cw.pay(&cw.agent, cw.pw.link(2), 1, "INV-1").await;
    assert_eq!(v["Rejected"]["reason"], "DUPLICATE");
    assert!(cw.rec("INV-1").await.is_null(), "credit keeps no payment record");
    cw.act(&cw.w.funder, "cancel_open", json!({"credit": id})).await.unwrap();
    cw.paid(2, 1, "INV-1").await;
    let first = cw.rec("INV-1").await;
    assert_eq!(first["amount"], UNIT.to_string());
    let due = now_ns(&cw.w).await? + 3600 * SEC;
    let v: Value = cw.agent.call(cw.w.writ.id(), "open_credit").args_json(json!({"preimage": cw.pw.link(3), "j": 1, "to": cw.w.merchant.id(), "invoice_hash": h("INV-1"), "due_at": due.to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(50)).transact().await?.into_result()?.json()?;
    assert_eq!(v["Rejected"]["reason"], "DUPLICATE");
    assert_eq!(cw.rec("INV-1").await, first, "the record is not replaced");
    bench("A111", "cancelled order and payment on one invoice make two claims; a paid invoice is reopened as an order", "one record, DUPLICATE", "one record, DUPLICATE", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a112_a_short_vault_buys_no_cover_and_the_bond_does_not_pay() -> anyhow::Result<()> {
    // 20% of 50 links is 10 links; the vault holds 5 and all of it would be a bond
    let cw = cover_world(CvOpts { credit: true, premium: 2000, bond: 10_000, vault: 11 * UNIT, ..Default::default() }).await?;
    let id = cw.open_order(5, 5, 3600, "INV-B").await;
    cw.seller("accept_credit", json!({"credit": id})).await.unwrap();
    let (vault0, st0) = (cw.cell_state().await["vault"].clone(), cw.stake().await);
    must(cw.activate().await, "PREMIUM_SHORT");
    assert_eq!(cw.cover().await["state"], "Offered");
    assert_eq!(cw.cell_state().await["vault"], vault0, "state unchanged, bond untouched");
    assert_eq!(cw.stake().await["amount"], st0["amount"]);
    bench("A112", "guarantor activates against a vault that can only pay from a seller's bond", "PREMIUM_SHORT", "PREMIUM_SHORT", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a113_every_cover_field_is_signed_and_register_refuses_bad_terms() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    let w = &cw.w;
    let x = CvOpts::default();
    let dep = cover_fee(x.n) + UNIT;
    let (good, _, _) = cover_args(w, &x, cw.arbiter.id(), None, UNIT).await?;
    let tampers: Vec<(&str, Value)> = vec![
        ("limit", json!((60 * UNIT).to_string())), ("deductible_bps", json!(1000)), ("premium_bps", json!(1)), ("claim_window", json!("601")),
        ("arbiter", json!(w.attacker.id())), ("terms_hash", json!(h("other terms"))),
    ];
    for (field, value) in tampers {
        let mut bad = good.clone();
        bad["cover"][field] = value;
        let e = try_register(w, &bad, dep).await.unwrap_err();
        assert!(e.contains("BAD_ATTESTATION"), "{}: {}", field, e);
    }
    let mut bad = good.clone();
    bad["cover"] = Value::Null;
    assert!(try_register(w, &bad, dep).await.unwrap_err().contains("BAD_ATTESTATION"), "cover cannot be dropped");
    bench("A113", "company changes any cover term after the guarantor signed", "BAD_ATTESTATION", "BAD_ATTESTATION", gain(w).await);

    // Each term a guarantor could sign by mistake, one by one, with a good signature
    let bad_terms: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
        ("COVER_SCOPE", Box::new({ let s = json!([w.merchant.id(), cw.arbiter.id()]); move |a| a["scope"] = s.clone() })),
        ("COVER_SCOPE", Box::new({ let s = json!([w.merchant.id(), w.funder.id()]); move |a| a["scope"] = s.clone() })),
        ("COVER_LIMIT_THIN", Box::new(|a| a["cover"]["limit"] = json!((50 * UNIT - 1).to_string()))),
        ("COVER_LIMIT_HIGH", Box::new(|a| a["cover"]["limit"] = json!((100 * UNIT + 1).to_string()))),
        ("COVER_DEDUCTIBLE", Box::new(|a| a["cover"]["deductible_bps"] = json!(999))),
    ];
    for (code, edit) in bad_terms {
        let (mut args, _, _) = cover_args(w, &x, cw.arbiter.id(), None, UNIT).await?;
        edit(&mut args);
        sign_args(w, &mut args);
        let e = try_register(w, &args, dep).await.unwrap_err();
        assert!(e.contains(code), "{}: {}", code, e);
    }
    bench("A114", "cover signed over a scope with the arbiter or the company, a thin limit, or under 10% share", "COVER_SCOPE, COVER_LIMIT_THIN, COVER_DEDUCTIBLE", "COVER_SCOPE, COVER_LIMIT_THIN, COVER_DEDUCTIBLE", gain(w).await);

    // The arbiter cannot be any party with a stake in the ruling, including the owner
    for (who, code) in [(w.writ.id(), "COVER_ARBITER"), (w.verifier.id(), "COVER_ARBITER"), (w.funder.id(), "COVER_ARBITER")] {
        let (args, _, _) = cover_args(w, &x, who, None, UNIT).await?;
        let e = try_register(w, &args, dep).await.unwrap_err();
        assert!(e.contains(code), "{}", e);
    }
    bench("A115", "the arbiter is the owner, the guarantor or the company", "COVER_ARBITER", "COVER_ARBITER", gain(w).await);
    // Fee for the records: one yocto below is refused, whatever else is attached
    let (args, _, _) = cover_args(w, &x, cw.arbiter.id(), None, UNIT).await?;
    let e = try_register(w, &args, cover_fee(x.n)).await.unwrap_err();
    assert!(e.contains("DEPOSIT_BELOW_FEE"), "{}", e);
    bench("A116", "a mandate with cover opens without paying for its payment records", "DEPOSIT_BELOW_FEE", "DEPOSIT_BELOW_FEE", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a117_only_the_named_party_can_act_on_a_claim() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    let a = &cw.w.attacker;
    must(cw.act(a, "activate_cover", json!({"root": cw.root()})).await, "ONLY_GUARANTOR");
    cw.activate().await.unwrap();
    must(cw.activate().await, "COVER_NOT_OFFERED");
    cw.paid(1, 1, "INV-1").await;
    cw.paid(2, 1, "INV-2").await;
    let file = json!({"root": cw.root(), "invoice_hash": h("INV-1"), "evidence_hash": h("e")});
    must(cw.act(a, "file_claim", file.clone()).await, "ONLY_FUNDER");
    must(cw.act(&cw.arbiter, "file_claim", file).await, "ONLY_FUNDER");
    cw.file("INV-1").await.unwrap();
    let rule = json!({"root": cw.root(), "invoice_hash": h("INV-1"), "ruling": {"Uphold": {"loss": UNIT.to_string()}}, "ruling_hash": h("r")});
    for who in [a, &cw.w.funder, &cw.w.verifier] {
        must(cw.act(who, "resolve_claim", rule.clone()).await, "ONLY_ARBITER");
    }
    must(cw.act(a, "void_cover", json!({"root": cw.root(), "invoice_hash": h("INV-1")})).await, "ONLY_ARBITER");
    must(cw.act(a, "clear_agent", json!({"root": cw.root()})).await, "ONLY_FUNDER");
    must(cw.act(a, "release_cover", json!({"root": cw.root()})).await, "ONLY_GUARANTOR");
    cw.uphold("INV-1", UNIT).await.unwrap();
    must(cw.act(a, "clear_agent", json!({"root": cw.root()})).await, "ONLY_FUNDER");
    bench("A117", "a stranger files, rules on, voids, clears or releases a cover; the company rules on its own claim", "ONLY_FUNDER, ONLY_ARBITER, ONLY_GUARANTOR", "ONLY_FUNDER, ONLY_ARBITER, ONLY_GUARANTOR", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a118_no_claim_without_a_covered_payment_and_no_bad_context() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    // Paid before the guarantor activated: nothing to claim on, however it is reported later
    cw.paid(1, 1, "INV-OLD").await;
    must(cw.file("INV-OLD").await, "COVER_NOT_ACTIVE");
    cw.activate().await.unwrap();
    must(cw.file("INV-OLD").await, "NO_PAYMENT");
    bench("A118", "company claims on a payment made before the cover was active", "NO_PAYMENT", "NO_PAYMENT", gain(&cw.w).await);
    let v: Value = cw.agent.call(cw.w.writ.id(), "spend").args_json(json!({"preimage": cw.pw.link(2), "j": 1, "to": cw.w.merchant.id(), "invoice_hash": h("INV-X"), "context_hash": "not-a-hash"}))
        .gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?.into_result()?.json()?;
    assert_eq!(v["Rejected"]["reason"], "INVOICE");
    bench("A119", "agent pays with a context hash nobody can check later", "Rejected:INVOICE", "Rejected:INVOICE", gain(&cw.w).await);
    Ok(())
}

// The worst case for gas: a sub-agent three levels down (each parent is read), a full scope of 64-character accounts in every cell (each cell is read and written),
// and the callback writing the largest record, on the 80 Tgas the SDK and the site attach. NEAR and token.
async fn worst_case_spend(token: bool) -> anyhow::Result<u64> {
    let x = if token { CvOpts { token: true, credit: true, vault: 30 * T, stake: 60, ..Default::default() } } else { CvOpts { credit: true, ..Default::default() } };
    let mut cw = cover_world(x.clone()).await?;
    let unit = if token { T } else { UNIT };
    let longest: Vec<AccountId> = (0..16u8).map(|k| format!("{:02x}", 0xa0 + k).repeat(32).parse().unwrap()).collect();
    let (mut args, agent_sk, pw) = cover_args(&cw.w, &cw.x, cw.arbiter.id(), cw.token.as_ref().map(|t| t.id()), unit).await?;
    args["scope"] = json!(longest);
    sign_args(&cw.w, &mut args);
    let until = args["valid_until"].as_str().unwrap().to_string();
    let deposit = if token { cover_fee(x.n) + NEAR_RESERVE } else { cover_fee(x.n) + x.vault };
    let id = try_register(&cw.w, &args, deposit).await.map_err(|e| anyhow::anyhow!(e))?;
    cw.cell = id.parse()?;
    cw.pw = pw;
    cw.agent = Account::from_secret_key(cw.w.writ.id().clone(), agent_sk, &cw.w.worker);
    if let Some(t) = &cw.token {
        cw.w.funder.call(t.id(), "ft_transfer_call").args_json(json!({"receiver_id": cw.w.writ.id(), "amount": x.vault.to_string(), "msg": id})).deposit(NearToken::from_yoctonear(1)).max_gas().transact().await?.into_result()?;
        cw.w.funder.call(t.id(), "storage_deposit").args_json(json!({"account_id": longest[3]})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    }
    cw.activate().await.unwrap();
    // Three hires, each a level down
    let mut agent = Account::from_secret_key(cw.w.writ.id().clone(), cw.agent.secret_key().clone(), &cw.w.worker);
    let mut chain = Payword::new(0);
    let mut link = cw.pw.link(9);
    for (level, j) in [(1u32, 9u32), (2, 7), (3, 5)] {
        let sk = SecretKey::from_random(KeyType::ED25519);
        let next = Payword::new(j);
        let v = hire(&agent, cw.w.writ.id(), &link, j, json!({"agent_pk": sk.public_key(), "w0": next.w0(), "scope": longest, "valid_until": until, "daily_links": 9, "max_links": 5})).await;
        assert!(v.get("Hired").is_some(), "level {}: {}", level, v);
        agent = Account::from_secret_key(cw.w.writ.id().clone(), sk, &cw.w.worker);
        chain = next;
        if level < 3 { link = chain.link(if level == 1 { 7 } else { 5 }); }
    }
    let out = agent.call(cw.w.writ.id(), "spend").args_json(json!({"preimage": chain.link(3), "j": 3, "to": longest[3], "invoice_hash": h("INV-WORST"), "context_hash": h("largest context")}))
        .gas(near_workspaces::types::Gas::from_tgas(80)).transact().await?;
    let burnt = out.total_gas_burnt.as_gas();
    let v: Value = out.into_result()?.json()?;
    assert!(v.get("Paid").is_some(), "{}", v);
    let rec = cw.rec("INV-WORST").await;
    assert_eq!(rec["context_hash"], h("largest context"), "the callback wrote the record");
    assert_eq!(rec["to"], longest[3].as_str());
    // And the record can be claimed on, from the root
    cw.file("INV-WORST").await.unwrap();
    Ok(burnt)
}

#[tokio::test]
async fn b47_the_worst_payment_fits_in_80_tgas_in_near() -> anyhow::Result<()> {
    let burnt = worst_case_spend(false).await?;
    let tg = burnt / 1_000_000_000_000;
    println!("COVER_GAS|near|{}", burnt);
    bench("B47", "worst payment in NEAR on 80 Tgas: third-level sub-agent, 16 longest accounts, context hash, record written", "Paid and recorded", &format!("Paid and recorded, {} Tgas burnt", tg), 0);
    Ok(())
}

#[tokio::test]
async fn b48_the_worst_payment_fits_in_80_tgas_in_a_token() -> anyhow::Result<()> {
    let burnt = worst_case_spend(true).await?;
    let tg = burnt / 1_000_000_000_000;
    println!("COVER_GAS|token|{}", burnt);
    bench("B48", "worst payment in a token on 80 Tgas: third-level sub-agent, 16 longest accounts, context hash, record written", "Paid and recorded", &format!("Paid and recorded, {} Tgas burnt", tg), 0);
    Ok(())
}

// The audit's terms: what cover costs, when it can start, and who can name it
#[tokio::test]
async fn a120_cover_that_cannot_pay_for_itself_is_refused() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    let w = &cw.w;
    let x = CvOpts { premium: 2000, valid_secs: 121 * 86_400, ..Default::default() };
    let (args, _, _) = cover_args(w, &x, cw.arbiter.id(), None, UNIT).await?;
    let e = try_register(w, &args, cover_fee(x.n) + UNIT).await.unwrap_err();
    assert!(e.contains("COVER_PREMIUM"), "{}", e);
    bench("A120", "a fee as large as the limit, so the company pays for its own guarantee", "COVER_PREMIUM", "COVER_PREMIUM", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a121_a_guarantor_with_no_stake_or_no_time_left_cannot_activate() -> anyhow::Result<()> {
    // The stake is short by what the fee would have added
    let cw = cover_world(CvOpts { n: 200, limit_links: 100, stake: 1, premium: 100, ..Default::default() }).await?;
    cw.act(&cw.w.verifier, "activate_cover", json!({"root": cw.root()})).await.unwrap();
    let cw = cover_world(CvOpts { n: 200, limit_links: 101, stake: 1, premium: 2000, ..Default::default() }).await?;
    must(cw.activate().await, "GUARANTOR_CAPACITY");
    bench("A121", "guarantor with too little stake lets the company's fee back the company's own cover", "GUARANTOR_CAPACITY", "GUARANTOR_CAPACITY", gain(&cw.w).await);
    let cw = cover_world(CvOpts { valid_secs: 8, window: 20, dispute: 2, premium: 200, ..Default::default() }).await?;
    wait_secs(5).await;
    let v0 = cw.cell_state().await["vault"].clone();
    must(cw.activate().await, "ACTIVATION_TOO_LATE");
    assert_eq!(cw.cell_state().await["vault"], v0, "no fee taken");
    bench("A122", "guarantor waits until the term is nearly over, takes a full period's fee, and covers almost nothing", "ACTIVATION_TOO_LATE", "ACTIVATION_TOO_LATE", gain(&cw.w).await);
    Ok(())
}

#[tokio::test]
async fn a123_the_company_cannot_guarantee_itself_or_name_the_contract() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    let w = &cw.w;
    let x = CvOpts::default();
    let dep = cover_fee(x.n) + UNIT;
    // The funder is whitelisted as a verifier and signs for itself
    let sk = SigningKey::generate(&mut rand::thread_rng());
    w.writ.call("set_verifier").args_json(json!({"account": w.funder.id(), "pk_hex": hex::encode(sk.verifying_key().to_bytes())})).transact().await?.into_result()?;
    let (mut args, _, _) = cover_args(w, &x, cw.arbiter.id(), None, UNIT).await?;
    args["verifier"] = json!(w.funder.id());
    args["signature"] = json!(hex::encode(sk.sign(attest_msg(&args, w.funder.id(), w.writ.id()).as_bytes()).to_bytes()));
    let e = try_register(w, &args, dep).await.unwrap_err();
    assert!(e.contains("COVER_GUARANTOR"), "{}", e);
    bench("A123", "a listed verifier guarantees its own company and inflates its record", "COVER_GUARANTOR", "COVER_GUARANTOR", gain(w).await);
    let (mut args, _, _) = cover_args(w, &x, cw.arbiter.id(), None, UNIT).await?;
    args["scope"] = json!([w.merchant.id(), w.writ.id()]);
    sign_args(w, &mut args);
    let e = try_register(w, &args, dep).await.unwrap_err();
    assert!(e.contains("COVER_SCOPE"), "{}", e);
    bench("A124", "the mandate's scope lets the agent pay the contract itself, stranding the money", "COVER_SCOPE", "COVER_SCOPE", gain(w).await);
    Ok(())
}

#[tokio::test]
async fn a125_a_ruling_that_pays_nothing_does_not_use_up_the_claim() -> anyhow::Result<()> {
    let cw = cover_world(CvOpts::default()).await?;
    cw.activate().await.unwrap();
    cw.paid(1, 1, "INV-1").await;
    cw.file("INV-1").await.unwrap();
    must(cw.uphold("INV-1", 1).await, "BAD_LOSS");
    assert_eq!(cw.cover().await["open_claim"], h("INV-1"));
    cw.uphold("INV-1", UNIT).await.unwrap();
    bench("A125", "someone with the arbiter's key upholds a loss of one yocto: it pays nothing and burns the claim", "BAD_LOSS", "BAD_LOSS", gain(&cw.w).await);
    let p: Value = cw.w.writ.view("present").args_json(json!({"cell": cw.root()})).await?.json()?;
    assert_eq!(p["cover"], true);
    let win: Value = cw.w.writ.view("windows").await?.json()?;
    assert_eq!(win["dispute_timeout"], "5");
    let c = cw.cover().await;
    assert_eq!(c["dispute_timeout"], "5");
    Ok(())
}
