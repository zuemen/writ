"""
Generate fixed KERI vectors for the contract tests (contract/tests/fixtures/), built directly with keripy as a mock chain:
  LE (legal entity AID) -> issues ECR to human (person AID) -> human issues AMC to agent (the agent is a delegated AID under the human KEL)
  then human revokes the AMC, prints the ixn event anchoring the revocation and the seal {i, s, d}.

Also outputs three sets of "one key, two worlds" vectors for the Rust contract's ed25519_verify spike:
  1. raw Ed25519 public key (32 bytes) of the agent's delegated AID + its signature (64 bytes) over any message
  2. raw Ed25519 public key of the human (AMC issuer) + its signature over the raw serialized bytes of the ixn
  3. raw bytes and seal of the ixn

Run: /home/claude/keri-venv/bin/python spike7_keri.py
"""
import json, sys, os, hashlib
from keri.app import habbing
from keri.core import coring, eventing, serdering, signing, indexing
from keri.vdr import credentialing
from keri.vc import proving
from keri.core.eventing import SealEvent

OUT = os.path.join(os.path.dirname(__file__), "..", "contract", "tests", "fixtures")

def b58(b: bytes) -> str:
    """Bitcoin/NEAR base58 (no checksum)."""
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); out = ""
    while n: n, r = divmod(n, 58); out = A[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out
os.makedirs(OUT, exist_ok=True)

# Official vLEI schema SAID (ECR). proving.credential() does not fetch the schema content, it only writes the SAID into the ACDC s field,
# the schema body is needed only when the verifier looks up the schema. The spike needs only the SAID.
SCHEMA_ECR = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw"
# The AMC has no formal schema yet (GLEIF discussion paper p.45 states "formal ACDC schema for the AMC needs to be defined").
# A placeholder SAID in a valid format is used here; replaced once D7 writes the schema ourselves.
SCHEMA_AMC = "EAMCplaceholderplaceholderplaceholderplaceh"

def anchor(hab, registry, serder, sn):
    """Anchor a TEL event (vcp / iss / rev) into the hab's KEL with an ixn, return the raw msg bytes of the ixn."""
    seal = SealEvent(serder.pre, sn, serder.said)._asdict()
    msg = hab.interact(data=[seal])          # the ixn event is created and signed here
    seqner = coring.Seqner(sn=hab.kever.sn)
    saider = coring.Saider(qb64=hab.kever.serder.said)
    registry.anchorMsg(pre=serder.pre, regd=serder.said, seqner=seqner, saider=saider)
    return msg, seal

def split_msg(msg: bytes):
    """CESR stream = JSON event body + attachments (counter code + indexed signatures). The version string contains the length, use it to cut."""
    serder = serdering.SerderKERI(raw=msg)
    body = msg[:serder.size]
    attach = msg[serder.size:]
    return serder, body, attach

with habbing.openHby(name="spike7", temp=True, salt=signing.Salter(raw=b"0123456789abcdef").qb64) as hby:
    le = hby.makeHab(name="le")                      # legal entity AID (mock; in reality the QVI should issue the LE vLEI)
    human = hby.makeHab(name="human")                # staff AID (ECR holder)
    print("LE    AID:", le.pre)
    print("human AID:", human.pre)

    # ---- 1. the agent is a delegated AID under the human KEL (GLEIF discussion paper Annex A p.44 / section 6-3 p.36)----
    agent = hby.makeHab(name="agent", delpre=human.pre)
    # The delegator human anchors the delegation approval with an ixn seal {i: agent.pre, s: "0", d: the agent's icp SAID}
    approve_seal = dict(i=agent.pre, s="0", d=agent.kever.serder.said if agent.kever else None)
    if approve_seal["d"] is None:
        # kever not yet created: take the icp from the db
        icp = hby.db.getEvt(eventing.dgKey(agent.pre, hby.db.getKeLast(eventing.snKey(agent.pre, 0))))
        approve_seal["d"] = serdering.SerderKERI(raw=bytes(icp)).said
    human.interact(data=[approve_seal])
    hby.kvy.processEscrows()
    print("agent AID (delegated under human):", agent.pre, "| delegator:", agent.kever.delpre if agent.kever else "(pending)")

    # ---- 2. registry and credentials ----
    rgy = credentialing.Regery(hby=hby, name="spike7", temp=True)
    reg_le = rgy.makeRegistry(name="le-reg", prefix=le.pre)
    anchor(le, reg_le, reg_le.vcp, "0"); rgy.processEscrows()
    reg_hu = rgy.makeRegistry(name="human-reg", prefix=human.pre)
    anchor(human, reg_hu, reg_hu.vcp, "0"); rgy.processEscrows()

    # LE -> human: ECR (mock fields aligned with the a block of the vLEI ECR schema)
    ecr = proving.credential(issuer=le.pre, schema=SCHEMA_ECR, recipient=human.pre,
                             data=dict(LEI="WRITDEMO000000000017", personLegalName="Alex Example",
                                       engagementContextRole="Treasury Operations"),
                             status=reg_le.regk)
    iss = reg_le.issue(said=ecr.said); anchor(le, reg_le, iss, "0"); rgy.processEscrows()
    print("ECR SAID:", ecr.said, "| TEL state sn=0 (iss)")

    # human -> agent: AMC (fields follow the four items on GLEIF discussion paper p.44: action class, cap, counterparties, validity) + edge pointing to the ECR
    amc = proving.credential(issuer=human.pre, schema=SCHEMA_AMC, recipient=agent.pre,
                             data=dict(actionClass="supplier-payment", limitUnit="100000000000000000000000",
                                       limitN=20, scope=["merchant.testnet"], validUntil="2026-12-31T00:00:00Z",
                                       paywordRoot="(w0 填在 D2)"),
                             source=dict(ecr=dict(n=ecr.said, s=SCHEMA_ECR)),
                             status=reg_hu.regk)
    iss2 = reg_hu.issue(said=amc.said); iss_msg, iss_seal = anchor(human, reg_hu, iss2, "0"); rgy.processEscrows()
    # issuance anchor (seal s="0"): the contract must refuse to take it as revocation evidence
    iss_ixn = serdering.SerderKERI(raw=bytes(iss_msg))
    iss_body = bytes(iss_msg[:iss_ixn.size])
    iss_sig = indexing.Siger(qb64b=bytes(hby.db.getSigs(eventing.dgKey(human.pre, iss_ixn.said))[0])).raw
    print("AMC SAID:", amc.said, "| TEL state sn=0 (iss)")

    # ---- 3. revoke the AMC: rev event + human's ixn anchor ----
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

    # ---- 3b. HR path: the LE revokes the employee's ECR ----
    rev_e = reg_le.revoke(said=ecr.said)
    ixn_e_msg, seal_e = anchor(le, reg_le, rev_e, "1"); rgy.processEscrows()
    ixn_e = serdering.SerderKERI(raw=bytes(ixn_e_msg))
    ixn_e_body = bytes(ixn_e_msg[:ixn_e.size])
    ixn_e_sig = indexing.Siger(qb64b=bytes(hby.db.getSigs(eventing.dgKey(le.pre, ixn_e.said))[0])).raw

    # ---- 4. one key, two worlds: raw Ed25519 bytes ----
    agent_pk = agent.kever.verfers[0].raw
    msg_for_agent = b"spend|cell=1|j=3|to=merchant.testnet"
    agent_sig = agent.sign(ser=msg_for_agent, indexed=False)[0].raw
    human_pk = human.kever.verfers[0].raw
    # the indexed signature actually attached to the KEL (not re-signed): take it from the db and strip the index code, leaving the 64-byte raw signature
    ixn_body = bytes(ixn_body)
    sigs = hby.db.getSigs(eventing.dgKey(human.pre, ixn.said))
    siger = indexing.Siger(qb64b=bytes(sigs[0]))
    human_sig_on_ixn = siger.raw
    # verify once with plain Ed25519 to confirm that "raw bytes + raw signature + raw public key" are what the NEAR contract takes
    import pysodium
    pysodium.crypto_sign_verify_detached(human_sig_on_ixn, ixn_body, human_pk)
    pysodium.crypto_sign_verify_detached(agent_sig, msg_for_agent, agent_pk)
    assert len(agent_pk) == 32 and len(agent_sig) == 64 and len(human_pk) == 32 and len(human_sig_on_ixn) == 64
    print("純 Ed25519 驗簽：ixn 由 human 簽 ✓；測試訊息由 agent 簽 ✓")

    vectors = dict(
        agent=dict(aid=agent.pre, pk_hex=agent_pk.hex(), msg=msg_for_agent.decode(), sig_hex=agent_sig.hex(),
                   near_pk="ed25519:" + b58(agent_pk)),   # NEAR public key string format: ed25519:<base58(32 bytes)>
        issuer=dict(aid=human.pre, pk_hex=human_pk.hex()),
        ixn=dict(raw_hex=ixn_body.hex(), said=ixn.said, sn=ixn.ked["s"], seal=seal,
                 sig_hex=human_sig_on_ixn.hex(), attach_hex=ixn_attach.hex()),
        rev=dict(ked=rev.ked, said=rev.said),
        iss_ixn=dict(raw_hex=iss_body.hex(), sig_hex=iss_sig.hex(), seal=iss_seal),
        amc=dict(said=amc.said, sad=amc.sad),
        ecr=dict(said=ecr.said),
        ecr_revocation=dict(ecr_said=ecr.said, le_aid=le.pre, le_pk_hex=le.kever.verfers[0].raw.hex(),
                            raw_hex=ixn_e_body.hex(), sig_hex=ixn_e_sig.hex(), seal=seal_e),
    )
    with open(os.path.join(OUT, "vectors.json"), "w") as f:
        json.dump(vectors, f, indent=1)
    with open(os.path.join(OUT, "ixn_revoke.cesr"), "wb") as f:
        f.write(ixn_msg)
    # export the full KEL/TEL/ACDC stream (a fixture for the TS verifier to read)
    stream = b""
    for h in (le, human, agent):
        stream += h.replay()
    stream += reg_le.tever.serder.raw if False else b""
    with open(os.path.join(OUT, "kel_all.cesr"), "wb") as f:
        f.write(stream)
    print("\n寫出:", os.listdir(OUT))
    print("agent 在 NEAR 上的公鑰字串:", vectors["agent"]["near_pk"])
