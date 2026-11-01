"""
Spike 7 —— 用 keripy 直接建立 mock 鏈：
  LE（法人 AID）→ 發 ECR 給 human（人 AID）→ human 發 AMC 給 agent（agent 是 human KEL 之下的委派 AID）
  然後 human 撤銷 AMC，印出錨定撤銷的 ixn 事件與 seal {i, s, d}。

同時輸出三組「一把鑰匙兩個世界」的向量，給 Rust 合約的 ed25519_verify spike 用：
  1. agent 委派 AID 的 Ed25519 原始公鑰（32 bytes）＋它對任意訊息的簽章（64 bytes）
  2. human（AMC 簽發者）的 Ed25519 原始公鑰＋它對 ixn 原始序列化 bytes 的簽章
  3. ixn 的原始 bytes 與 seal

執行：/home/claude/keri-venv/bin/python spike7_keri.py
"""
import json, sys, os, hashlib
from keri.app import habbing
from keri.core import coring, eventing, serdering, signing, indexing
from keri.vdr import credentialing
from keri.vc import proving
from keri.core.eventing import SealEvent

OUT = os.path.join(os.path.dirname(__file__), "..", "contract", "tests", "fixtures")

def b58(b: bytes) -> str:
    """Bitcoin/NEAR 的 base58（無 checksum）。"""
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); out = ""
    while n: n, r = divmod(n, 58); out = A[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out
os.makedirs(OUT, exist_ok=True)

# vLEI 正式 schema SAID（ECR）。proving.credential() 不會抓 schema 內容，只把 SAID 寫進 ACDC 的 s 欄位，
# 驗證端要查 schema 時才需要 schema 本體。spike 只需要 SAID。
SCHEMA_ECR = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"
# AMC 還沒有正式 schema（GLEIF 討論稿 p.45 明寫「formal ACDC schema for the AMC needs to be defined」）。
# 這裡用一個合法格式的占位 SAID；之後 D7 自己寫 schema 再換。
SCHEMA_AMC = "EAMCplaceholderplaceholderplaceholderplaceh"

def anchor(hab, registry, serder, sn):
    """把 TEL 事件（vcp / iss / rev）用 ixn 錨進 hab 的 KEL，回傳 ixn 的原始 msg bytes。"""
    seal = SealEvent(serder.pre, sn, serder.said)._asdict()
    msg = hab.interact(data=[seal])          # 這裡產生 ixn 事件並簽章
    seqner = coring.Seqner(sn=hab.kever.sn)
    saider = coring.Saider(qb64=hab.kever.serder.said)
    registry.anchorMsg(pre=serder.pre, regd=serder.said, seqner=seqner, saider=saider)
    return msg, seal

def split_msg(msg: bytes):
    """CESR 串流 = JSON 事件本體 + 附件（計數碼 + 索引簽章）。版本字串裡有長度，用它切。"""
    serder = serdering.SerderKERI(raw=msg)
    body = msg[:serder.size]
    attach = msg[serder.size:]
    return serder, body, attach

with habbing.openHby(name="spike7", temp=True, salt=signing.Salter(raw=b"0123456789abcdef").qb64) as hby:
    le = hby.makeHab(name="le")                      # 法人 AID（mock，實際應由 QVI 發 LE vLEI）
    human = hby.makeHab(name="human")                # 職員 AID（ECR 持有人）
    print("LE    AID:", le.pre)
    print("human AID:", human.pre)

    # ---- 1. agent 是 human KEL 之下的委派 AID（GLEIF 討論稿 Annex A p.44 / §6-3 p.36）----
    agent = hby.makeHab(name="agent", delpre=human.pre)
    # 委派者 human 以 ixn 錨定委派核准 seal {i: agent.pre, s: "0", d: agent 的 icp SAID}
    approve_seal = dict(i=agent.pre, s="0", d=agent.kever.serder.said if agent.kever else None)
    if approve_seal["d"] is None:
        # kever 尚未建立：從 db 取 icp
        icp = hby.db.getEvt(eventing.dgKey(agent.pre, hby.db.getKeLast(eventing.snKey(agent.pre, 0))))
        approve_seal["d"] = serdering.SerderKERI(raw=bytes(icp)).said
    human.interact(data=[approve_seal])
    hby.kvy.processEscrows()
    print("agent AID (delegated under human):", agent.pre, "| delegator:", agent.kever.delpre if agent.kever else "(pending)")

    # ---- 2. 登錄簿與憑證 ----
    rgy = credentialing.Regery(hby=hby, name="spike7", temp=True)
    reg_le = rgy.makeRegistry(name="le-reg", prefix=le.pre)
    anchor(le, reg_le, reg_le.vcp, "0"); rgy.processEscrows()
    reg_hu = rgy.makeRegistry(name="human-reg", prefix=human.pre)
    anchor(human, reg_hu, reg_hu.vcp, "0"); rgy.processEscrows()

    # LE → human：ECR（mock 欄位對齊 vLEI ECR schema 的 a 區塊）
    ecr = proving.credential(issuer=le.pre, schema=SCHEMA_ECR, recipient=human.pre,
                             data=dict(LEI="5493001KJTIIGC8Y1R12", personLegalName="Chu Ting-Yi",
                                       engagementContextRole="Treasury Operations"),
                             status=reg_le.regk)
    iss = reg_le.issue(said=ecr.said); anchor(le, reg_le, iss, "0"); rgy.processEscrows()
    print("ECR SAID:", ecr.said, "| TEL state sn=0 (iss)")

    # human → agent：AMC（欄位照 GLEIF 討論稿 p.44 四項：行動類別、上限、對手、有效期）＋ edge 指向 ECR
    amc = proving.credential(issuer=human.pre, schema=SCHEMA_AMC, recipient=agent.pre,
                             data=dict(actionClass="supplier-payment", limitUnit="100000000000000000000000",
                                       limitN=20, scope=["merchant.testnet"], validUntil="2026-12-31T00:00:00Z",
                                       paywordRoot="(w0 填在 D2)"),
                             source=dict(ecr=dict(n=ecr.said, s=SCHEMA_ECR)),
                             status=reg_hu.regk)
    iss2 = reg_hu.issue(said=amc.said); anchor(human, reg_hu, iss2, "0"); rgy.processEscrows()
    print("AMC SAID:", amc.said, "| TEL state sn=0 (iss)")

    # ---- 3. 撤銷 AMC：rev 事件 + human 的 ixn 錨定 ----
    rev = reg_hu.revoke(said=amc.said)
    ixn_msg, seal = anchor(human, reg_hu, rev, "1"); rgy.processEscrows()
    ixn, ixn_body, ixn_attach = split_msg(ixn_msg)
    print("\n== rev 事件（TEL，本身無簽章）==")
    print(json.dumps(rev.ked, indent=1))
    print("\n== 錨定 rev 的 ixn 事件（KEL，有簽章）==")
    print(json.dumps(ixn.ked, indent=1))
    print("seal:", seal)
    state = reg_hu.tever.vcState(amc.said)
    print("AMC TEL state after revoke:", state.et if state else None, "sn=", state.s if state else None)

    # ---- 4. 一把鑰匙兩個世界：原始 Ed25519 bytes ----
    agent_pk = agent.kever.verfers[0].raw
    msg_for_agent = b"spend|cell=1|j=3|to=merchant.testnet"
    agent_sig = agent.sign(ser=msg_for_agent, indexed=False)[0].raw
    human_pk = human.kever.verfers[0].raw
    # 真正附在 KEL 上的那個索引簽章（不是重簽）：從 db 取出，去掉索引碼只留 64 bytes 原始簽章
    ixn_body = bytes(ixn_body)
    sigs = hby.db.getSigs(eventing.dgKey(human.pre, ixn.said))
    siger = indexing.Siger(qb64b=bytes(sigs[0]))
    human_sig_on_ixn = siger.raw
    # 用純 Ed25519 驗一次，確認「原始 bytes + 原始簽章 + 原始公鑰」三者就是 NEAR 合約要收的東西
    import pysodium
    pysodium.crypto_sign_verify_detached(human_sig_on_ixn, ixn_body, human_pk)
    pysodium.crypto_sign_verify_detached(agent_sig, msg_for_agent, agent_pk)
    assert len(agent_pk) == 32 and len(agent_sig) == 64 and len(human_pk) == 32 and len(human_sig_on_ixn) == 64
    print("純 Ed25519 驗簽：ixn 由 human 簽 ✓；測試訊息由 agent 簽 ✓")

    vectors = dict(
        agent=dict(aid=agent.pre, pk_hex=agent_pk.hex(), msg=msg_for_agent.decode(), sig_hex=agent_sig.hex(),
                   near_pk="ed25519:" + b58(agent_pk)),   # NEAR 的公鑰字串格式：ed25519:<base58(32 bytes)>
        issuer=dict(aid=human.pre, pk_hex=human_pk.hex()),
        ixn=dict(raw_hex=ixn_body.hex(), said=ixn.said, sn=ixn.ked["s"], seal=seal,
                 sig_hex=human_sig_on_ixn.hex(), attach_hex=ixn_attach.hex()),
        rev=dict(ked=rev.ked, said=rev.said),
        amc=dict(said=amc.said, sad=amc.sad),
        ecr=dict(said=ecr.said),
    )
    with open(os.path.join(OUT, "vectors.json"), "w") as f:
        json.dump(vectors, f, indent=1)
    with open(os.path.join(OUT, "ixn_revoke.cesr"), "wb") as f:
        f.write(ixn_msg)
    # 匯出完整 KEL/TEL/ACDC 串流（給 TS verifier 讀的 fixture）
    stream = b""
    for h in (le, human, agent):
        stream += h.replay()
    stream += reg_le.tever.serder.raw if False else b""
    with open(os.path.join(OUT, "kel_all.cesr"), "wb") as f:
        f.write(stream)
    print("\n寫出:", os.listdir(OUT))
    print("agent 在 NEAR 上的公鑰字串:", vectors["agent"]["near_pk"])
