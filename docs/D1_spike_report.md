# D1 Spike 報告（2026-11-02 00:20–01:00 台北）

結論：**整題成立。** 八個 spike 全部通過，沒有一個需要退回原始 D（子帳號 cell）。四個協定層錯誤字串已實測抄下。

| # | 驗什麼 | 結果 | 證據（可重跑） |
|---|---|---|---|
| 1 | Rust wasm32 + sandbox | ✅ `cargo build --target wasm32-unknown-unknown --release` 54 秒，wasm 305 KB；near-workspaces 0.24 + near-sandbox 2.14.0 啟動並部署 | `make -C contract test` |
| 2 | Keypom 模式 | ✅ 合約對自己 `add_access_key_allowance(agent_pk, limited(1 NEAR), self, "spend,present")`；agent 用自己的 key、以合約帳號為 signer 呼叫 `spend`，合約 `env::signer_account_pk()` 查到對應的 Cell；agent 呼叫 `register` → RPC 拒絕 `InvalidAccessKeyError(MethodNameMismatch { method_name: "register" })`；附 1 yocto → `InvalidAccessKeyError(DepositWithFunctionCall)` | `contract/tests/sandbox.rs::spike2` |
| 3 | 撤銷／續命／allowance | ✅ `revoke` 的 DeleteKey 交易有 tx hash（demo 的撤銷證據）；之後 agent 再簽 → `InvalidAccessKeyError(AccessKeyNotFound { account_id, public_key })`；allowance=1 yocto → `InvalidAccessKeyError(NotEnoughAllowance { allowance: 1, cost: 10919008102589200000000 })`（一筆 spend 的 gas 成本約 0.0109 NEAR）；同一 batch `delete_key + add_access_key` 續命成功、不出 AddKeyAlreadyExists | `spike3` |
| 4 | `env::ed25519_verify` | ✅ 隨機向量 true／翻一個 bit 為 false；**真 KERI 向量**：human（AMC 簽發者）KEL 上錨定撤銷的 `ixn` 事件（314 bytes 原始序列化）＋附在 KEL 上的索引簽章去索引後的 64 bytes＋32 bytes 公鑰 → 鏈上驗證 **true**；seal 的 `d` 字串確實在事件本體裡 | `spike4` + `contract/tests/fixtures/vectors.json` |
| 5 | sha256 鏈 gas | ✅ j=100：合約內 used_gas 1.21 Tgas，整筆交易 2 Tgas（遠低於 30 Tgas 門檻）→ PayWord 的 j 上限不需要限制 | `spike5` |
| 6 | near-api-js v7 任意 KeyPair 當合約帳號 signer | ✅ `new Account(CONTRACT, provider, new KeyPairSigner(agentKp))` 直接可用；CLI 四種貼標全部命中：POLICY REJECTED（合約回 `{"Rejected":{"reason":"SCOPE","rejects":1}}`，有 tx hash）／PROTOCOL BLOCKED（MethodNameMismatch、DepositWithFunctionCall）／MANDATE REVOKED（AccessKeyNotFound）／GAS ALLOWANCE EXHAUSTED（NotEnoughAllowance） | `agent/spike6.ts` |
| 7 | keripy 1.3.6：LE→ECR→AMC→委派 AID、撤銷、ixn seal | ✅ agent AID 建為 human KEL 之下的委派識別符（`makeHab(delpre=human.pre)` + human `interact` 錨定核准 seal）；AMC 的 edge 指向 ECR；`revoke` 後 TEL 狀態 `rev sn=1`；錨定事件 `ixn` 的 seal 正是 `{i: AMC SAID, s: "1", d: rev SAID}` | `keri/mock_ecosystem.py` |
| 8 | sandbox 二進位可離線重跑 | ✅ near-workspaces 把 2.14.0 下載到 `target/debug/build/near-sandbox-*/out/.near/`；複製到 `tools/near-sandbox` 後可手動 `init`／`run`（spike 6 就是這樣跑的） | `tools/` |

## 踩到的坑（已解，寫進 README 的「環境」節）

1. **cargo-near 從原始碼編譯超過 10 分鐘**（2 核）。一鍵安裝腳本（curl | sh）在我這個環境被擋。結論：**合約不需要 cargo-near 也能建**（plain `cargo build --target wasm32-unknown-unknown --release`）；cargo-near 只在要做 reproducible build／ABI 時才需要，排到 D10。
2. **neard 啟動堅持 fd 上限 65535**，容器硬上限 20000 → `couldn't set the file descriptor limit`。寫了 `tools/fakerlimit.c`（LD_PRELOAD shim，NOFILE 的 setrlimit 假裝成功）。一般電腦（硬上限 524288）不需要。Makefile 提供 `test-lowfd`。
3. **near-api-js v7 的 `nearToYocto()` 回 bigint**，放進 args 會 `Do not know how to serialize a BigInt`；合約的 `NearToken` 參數要用字串 yocto。`deposit` 參數同理。
4. **tsx 預設 cjs 不支援 top-level await** → package.json 設 `"type": "module"`。
5. `#[handle_result]` 的 Err 會 panic 回滾狀態 → rejects 計數器留不住。改成回傳 `Verdict::{Paid, Rejected}`，拒絕也是成功交易（有 hash、有事件、狀態留下），tripwire 才做得到。這改寫了 v2 第 5.5 節的描述。
6. keripy 1.3.6 API 位移：`Salter` 在 `keri.core.signing`、`Siger` 在 `keri.core.indexing`、ACDC 用 `.sad` 不是 `.ked`。

## 對 v2 設計的修正

- 5.5 `spend`：政策拒絕回傳 `Verdict::Rejected`（不是 Result<Err>）。
- 5.5 `register`：spike 證明 owner 可直接是合約帳號本身（部署者）；正式版白名單驗證者仍用 `assert_owner` 或驗證者 pk 清單。
- 5.9 D2–4 可以直接從這個 spike 合約長出來，不用重寫。
- 「一把鑰匙兩個世界」已實證：`keri/mock_ecosystem.py` 印出的 `agent.near_pk`（`ed25519:<base58>`）就是要掛到合約上的 FC key。
