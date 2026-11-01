//! D1 spike 2–5：在本機 sandbox 上實證「Keypom 模式」與主機函式。
//! 跑法：先 `cargo build --target wasm32-unknown-unknown --release`，再 `cargo test --test sandbox -- --nocapture`

use near_workspaces::types::{KeyType, NearToken, SecretKey};
use near_workspaces::{Account, Contract, Worker};
use serde_json::json;

const WASM: &str = "target/wasm32-unknown-unknown/release/sealed_mandate.wasm";

/// 把 near-workspaces 的錯誤攤平成字串，方便抓協定層錯誤名稱（這些錯誤沒有 tx hash）。
fn err_string<T>(r: Result<T, near_workspaces::error::Error>) -> String {
    match r {
        Ok(_) => "OK".to_string(),
        Err(e) => format!("{:?}", e),
    }
}

async fn deploy() -> anyhow::Result<(Worker<near_workspaces::network::Sandbox>, Contract)> {
    let worker = near_workspaces::sandbox().await?;
    let wasm = std::fs::read(WASM)?;
    let contract = worker.dev_deploy(&wasm).await?;
    contract.call("new").transact().await?.into_result()?;
    Ok((worker, contract))
}

/// 用「agent 的私鑰」扮演合約帳號 —— 這就是 Keypom 模式：帳號是合約自己，鑰匙是 agent 的。
fn agent_as_contract(worker: &Worker<near_workspaces::network::Sandbox>, contract: &Contract, sk: &SecretKey) -> Account {
    Account::from_secret_key(contract.id().clone(), sk.clone(), worker)
}

#[tokio::test]
async fn spike2_keypom_mode_signer_pk_and_policy() -> anyhow::Result<()> {
    let (worker, contract) = deploy().await?;
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let agent_pk = agent_sk.public_key();

    // 驗證者（owner＝合約自己，因為 new 由合約帳號呼叫）開格並掛 FC key
    contract
        .call("register")
        .args_json(json!({"agent_pk": agent_pk, "label": "treasury-agent-1", "allowance_yocto": NearToken::from_near(1)}))
        .transact().await?.into_result()?;

    // 合約帳號上現在應有一把 FunctionCall key，method_names = spend,present
    let keys = worker.view_access_keys(contract.id()).await?;
    let found = keys.iter().find(|k| k.public_key == agent_pk).expect("agent key should be on contract account");
    println!("[spike2] access key on contract: {:?}", found.access_key.permission);
    let perm = format!("{:?}", found.access_key.permission);
    assert!(perm.contains("spend") && perm.contains("present"), "method_names should be spend,present");

    // agent 用自己的鑰匙、以合約帳號身分呼叫 spend → 合約靠 signer_account_pk 認出它
    let agent = agent_as_contract(&worker, &contract, &agent_sk);
    let out = agent.call(contract.id(), "spend")
        .args_json(json!({"to": "merchant.test.near", "amount": NearToken::from_millinear(10)}))
        .transact().await?;
    println!("[spike2] spend logs: {:?}", out.logs());
    let v: serde_json::Value = out.json()?;
    assert_eq!(v, json!({"Paid": {"spends": 1}}));

    // 被 prompt injection 的 agent 想付給攻擊者 → 政策拒絕，但交易成功、狀態留下（rejects=1）
    let out = agent.call(contract.id(), "spend")
        .args_json(json!({"to": "attacker.test.near", "amount": NearToken::from_millinear(10)}))
        .transact().await?;
    println!("[spike2] injected spend logs: {:?} | tx hash exists: {}", out.logs(), out.outcome().transaction_hash);
    let v: serde_json::Value = out.json()?;
    assert_eq!(v, json!({"Rejected": {"reason": "SCOPE", "rejects": 1}}));
    let cell: serde_json::Value = contract.view("present").args_json(json!({"agent_pk": agent_pk})).await?.json()?;
    assert_eq!(cell["spends"], 1); assert_eq!(cell["rejects"], 1);
    println!("[spike2] cell after both calls: {}", cell);

    // agent 鑰匙去呼叫非白名單方法 register → 協定層 MethodNameMismatch（RPC 直接拒絕）
    let r = agent.call(contract.id(), "register")
        .args_json(json!({"agent_pk": agent_pk, "label": "x", "allowance_yocto": null}))
        .transact().await;
    let s = err_string(r);
    println!("[spike2] agent calls register → {}", s);
    assert!(s.contains("MethodNameMismatch"), "expected MethodNameMismatch, got {}", s);

    // agent 鑰匙附 deposit → DepositWithFunctionCall
    let r = agent.call(contract.id(), "spend")
        .args_json(json!({"to": "merchant.test.near", "amount": NearToken::from_millinear(1)}))
        .deposit(NearToken::from_yoctonear(1))
        .transact().await;
    let s = err_string(r);
    println!("[spike2] agent attaches 1 yocto → {}", s);
    assert!(s.contains("DepositWithFunctionCall"), "expected DepositWithFunctionCall, got {}", s);
    Ok(())
}

#[tokio::test]
async fn spike3_revoke_refresh_and_allowance_strings() -> anyhow::Result<()> {
    let (worker, contract) = deploy().await?;
    let agent_sk = SecretKey::from_random(KeyType::ED25519);
    let agent_pk = agent_sk.public_key();
    let agent = agent_as_contract(&worker, &contract, &agent_sk);

    contract.call("register")
        .args_json(json!({"agent_pk": agent_pk, "label": "a", "allowance_yocto": NearToken::from_near(1)}))
        .transact().await?.into_result()?;
    agent.call(contract.id(), "spend")
        .args_json(json!({"to": "merchant.x", "amount": NearToken::from_millinear(1)}))
        .transact().await?.into_result()?;

    // 撤銷：合約刪自己帳號上的 key —— 這筆有 receipt／tx hash（demo 裡「撤銷」唯一的鏈上證據）
    let out = contract.call("revoke").args_json(json!({"agent_pk": agent_pk})).transact().await?;
    println!("[spike3] revoke tx hash: {}", out.outcome().transaction_hash);
    out.into_result()?;
    let keys = worker.view_access_keys(contract.id()).await?;
    assert!(keys.iter().all(|k| k.public_key != agent_pk), "key must be gone");

    // agent 再簽 → 協定層錯誤，抄下精確字串給 CLI 貼標
    let r = agent.call(contract.id(), "spend")
        .args_json(json!({"to": "merchant.x", "amount": NearToken::from_millinear(1)}))
        .transact().await;
    let s = err_string(r);
    println!("[spike3] after revoke → {}", s);
    assert!(s.contains("AccessKeyNotFound") || s.contains("AccessKeyDoesNotExist"), "got {}", s);

    // 撤銷後同一把 pk 可以重新 register（key 已不在，不會 AddKeyAlreadyExists）
    contract.call("register")
        .args_json(json!({"agent_pk": agent_pk, "label": "a2", "allowance_yocto": NearToken::from_yoctonear(1)}))
        .transact().await?.into_result()?;

    // allowance 只有 1 yocto → 第一筆就 NotEnoughAllowance（demo 要跟撤銷分開貼標）
    let r = agent.call(contract.id(), "spend")
        .args_json(json!({"to": "merchant.x", "amount": NearToken::from_millinear(1)}))
        .transact().await;
    let s = err_string(r);
    println!("[spike3] tiny allowance → {}", s);
    assert!(s.contains("NotEnoughAllowance"), "got {}", s);

    // 續命：同 batch 先刪後加；之後 agent 又能簽
    contract.call("refresh_key")
        .args_json(json!({"agent_pk": agent_pk, "allowance_yocto": NearToken::from_near(1)}))
        .transact().await?.into_result()?;
    let out = agent.call(contract.id(), "spend")
        .args_json(json!({"to": "merchant.x", "amount": NearToken::from_millinear(1)}))
        .transact().await?;
    let v: serde_json::Value = out.json()?;
    println!("[spike3] after refresh_key → {}", v);
    assert_eq!(v["Paid"]["spends"], 1); // 新格從 0 起算（register 時重建）
    Ok(())
}

#[tokio::test]
async fn spike4_ed25519_verify_keri_vector_and_spike5_hash_chain_gas() -> anyhow::Result<()> {
    let (_worker, contract) = deploy().await?;

    // 4a. 隨機向量（ed25519-dalek 簽）
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::generate(&mut rand::thread_rng());
    let msg = b"KERI10JSON00013a_{\"t\":\"ixn\"}";
    let sig = sk.sign(msg).to_bytes();
    let pk = sk.verifying_key().to_bytes();
    let b64 = |b: &[u8]| near_sdk::base64::Engine::encode(&near_sdk::base64::prelude::BASE64_STANDARD, b);
    let ok: bool = contract.view("verify_ed25519")
        .args_json(json!({"msg": b64(msg), "sig": b64(&sig), "pk": b64(&pk)})).await?.json()?;
    assert!(ok);
    let mut bad = sig; bad[0] ^= 1;
    let ok2: bool = contract.view("verify_ed25519")
        .args_json(json!({"msg": b64(msg), "sig": b64(&bad), "pk": b64(&pk)})).await?.json()?;
    assert!(!ok2);
    println!("[spike4] random vector: valid=true, flipped=false ✓");

    // 4b. 真的 KERI 向量：human 簽發者對「錨定 AMC 撤銷的 ixn 事件」的簽章（spike 7 產出）
    if let Ok(txt) = std::fs::read_to_string("tests/fixtures/vectors.json") {
        let v: serde_json::Value = serde_json::from_str(&txt)?;
        let msg = hex::decode(v["ixn"]["raw_hex"].as_str().unwrap())?;
        let sig = hex::decode(v["ixn"]["sig_hex"].as_str().unwrap())?;
        let pk = hex::decode(v["issuer"]["pk_hex"].as_str().unwrap())?;
        let ok: bool = contract.view("verify_ed25519")
            .args_json(json!({"msg": b64(&msg), "sig": b64(&sig), "pk": b64(&pk)})).await?.json()?;
        assert!(ok, "KERI ixn signature must verify on-chain");
        // seal 內容也在 msg 裡：合約 v1 revoke 要解析的就是這段
        let s = String::from_utf8_lossy(&msg);
        assert!(s.contains(v["ixn"]["seal"]["d"].as_str().unwrap()));
        println!("[spike4] KERI ixn (sn={}) signed by issuer verifies on NEAR ✓; seal d={} present in body",
                 v["ixn"]["sn"], v["ixn"]["seal"]["d"]);
        // agent 委派 AID 的鑰匙 == NEAR 公鑰字串
        println!("[spike4] agent KERI AID {} → NEAR key {}", v["agent"]["aid"], v["agent"]["near_pk"]);
    } else {
        println!("[spike4] (no KERI vectors.json found; skipped 4b)");
    }

    // 5. sha256 鏈 j=100 的 gas（view 也會回報 gas；用 call 看 gas_burnt 更準）
    let out = contract.call("hash_chain")
        .args_json(json!({"preimage_hex": "00".repeat(32), "j": 100}))
        .transact().await?;
    println!("[spike5] hash_chain j=100 logs={:?} total_gas_burnt={} Tgas", out.logs(), out.total_gas_burnt.as_tgas());
    assert!(out.total_gas_burnt.as_tgas() < 30, "one spend-equivalent must stay well under 30 Tgas");
    // 對照：鏈下算同樣的值
    use sha2::{Digest, Sha256};
    let mut cur = vec![0u8; 32];
    for _ in 0..100 { cur = Sha256::digest(&cur).to_vec(); }
    let onchain: String = out.json()?;
    assert_eq!(onchain, hex::encode(cur));
    Ok(())
}
