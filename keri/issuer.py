"""
Issuer side (simulates the legal entity's side): built and persisted with keripy:

  LE (legal entity AID) --ECR--> human (staff AID, ECR holder) --AMC--> agent (delegated AID under the human KEL)

The AMC attributes bind the "limit" into the credential: paywordRoot (w0), paywordLength (n), unitYocto, dailyLinks,
counterparties (allowed counterparties), validUntil, settlementRail (the funding NEAR account).

Commands
  python issuer.py init --scope merchant.test.near --rail acme.test.near [--n 50 --unit 1e23 --daily 20 --days 30]
  python issuer.py export            # export to keri/bundle/ the public CESR (the verifier takes only this)
  python issuer.py release K         # the human releases links: prints links[K] (the preimage the agent needs to pay up to link K)
  python issuer.py revoke            # the human revokes the AMC: TEL rev + KEL ixn anchor; prints revocation.json
  python issuer.py revoke-ecr        # HR (LE) revokes the employee's ECR: also produces revocation.json, without needing the employee's key
  python issuer.py status

Private data (agent private key, PayWord seed) is written only to keri/.keystore/ (.gitignore). This is the demo's mock ecosystem:
the QVI / GLEIF root above the LE is out of scope (disclosed in the README).
"""
import argparse, datetime, decimal, hashlib, json, os, secrets, sys

from keri.app import habbing, signing
from keri.core import coring, eventing, serdering, indexing
from keri.core.eventing import SealEvent
from keri.vc import proving
from keri.vdr import credentialing, viring

from common import AMC, BUNDLE, ECR, KEYSTORE, LEV, PRIVATE, QVI, REGISTRAR, b58, block, cover_message, read_json, rules_for, write_json

LEI = "WRITDEMO000000000017"  # fictional LEI: ISO 17442 check digits correct, but belongs to no real legal entity
QVI_LEI = "WRITDEMOQVI00000000" + "0"  # fictional QVI identifier, used only in the mock chain
STATE = os.path.join(KEYSTORE, "state.json")


def open_all():
    os.makedirs(KEYSTORE, exist_ok=True)
    hby = habbing.Habery(name="writ-issuer", headDirPath=KEYSTORE, temp=False)
    reger = viring.Reger(name="writ-issuer", headDirPath=KEYSTORE, reopen=True, db=hby.db)
    rgy = credentialing.Regery(hby=hby, name="writ-issuer", reger=reger)
    return hby, rgy


def anchor(hab, registry, serder, sn: str):
    """A TEL event is anchored into the hab's KEL with an ixn; returns the full CESR message of the ixn."""
    seal = SealEvent(serder.pre, sn, serder.said)._asdict()
    msg = hab.interact(data=[seal])
    registry.anchorMsg(pre=serder.pre, regd=serder.said,
                       seqner=coring.Seqner(sn=hab.kever.sn), saider=coring.Saider(qb64=hab.kever.serder.said))
    return msg


def payword(seed: bytes, n: int):
    """links[n] = seed, links[k] = sha256(links[k+1]); links[0] = w0."""
    links = [b""] * (n + 1)
    links[n] = seed
    for k in range(n - 1, -1, -1):
        links[k] = hashlib.sha256(links[k + 1]).digest()
    return links


# Demo terms: a real deployment needs the company and its lawyers to finalize them
TERMS = "Writ demo credit terms. Not reviewed by counsel. Governing law and arbitration are placeholders. The company consents to disclosure of its LEI after an unpaid recourse period."
TERMS_HASH = hashlib.sha256(TERMS.encode()).hexdigest()


# What an arbiter rules on. Placeholder text: a real deployment needs the guarantor, the company and their lawyers to finalize it.
COVER_TERMS = ("Writ demo cover terms. Not reviewed by counsel. Covered: a payment by the agent inside its mandate that the company did not owe, made because the agent was deceived, such as a duplicate "
               "invoice under a new number. Excluded: a purchase the company wanted, a payment to the company's own accounts, loss from a stolen key unless the arbiter finds otherwise. "
               "Process: the seller gets a chance to respond and refund first. The company states it has not been refunded. After repayment, the company's rights against the seller pass to the guarantor.")


def cover_doc(a, le, amc_said):
    """The legal entity signs the cover terms for this contract and this AMC."""
    if not a.cover_limit:
        return None
    if not (a.contract and a.cover_arbiter):
        sys.exit("--cover-limit needs --contract and --cover-arbiter")
    c = dict(limit=str(int(decimal.Decimal(a.cover_limit))), deductible_bps=a.cover_deductible_bps, premium_bps=a.cover_premium_bps,
             claim_window=str(a.cover_claim_window), arbiter=a.cover_arbiter, terms_hash=hashlib.sha256(COVER_TERMS.encode()).hexdigest())
    return dict(c, terms_text=COVER_TERMS, le_sig=le.sign(ser=cover_message(a.contract, amc_said, c), indexed=False)[0].raw.hex())


def credit_attrs(a):
    if not a.credit_limit:
        return {}
    return dict(creditLimitYocto=str(int(decimal.Decimal(a.credit_limit))), bondBps=a.bond_bps, premiumBps=a.premium_bps, feePayer=a.fee_payer, sellerCapBps=a.seller_cap_bps, minTenorSecs=a.min_tenor,
                maxTenorSecs=a.max_tenor, termsHash=TERMS_HASH, arbiter=a.arbiter,
                **({"creditAsset": a.credit_asset or a.asset} if (a.credit_asset or a.asset) else {}))


def cmd_init(a):
    if os.path.exists(STATE):
        sys.exit("already initialized (rm -rf keri/.keystore to start over)")
    hby, rgy = open_all()
    root = hby.makeHab(name="root")   # mock GLEIF root
    qvi = hby.makeHab(name="qvi")     # mock QVI
    le = hby.makeHab(name="le")
    human = hby.makeHab(name="human")
    agent = hby.makeHab(name="agent", delpre=human.pre)
    # The human approves the delegation with an ixn: seal {i: agent, s: 0, d: agent icp SAID}
    icp = serdering.SerderKERI(raw=bytes(hby.db.getEvt(eventing.dgKey(agent.pre, hby.db.getKeLast(eventing.snKey(agent.pre, 0))))))
    human.interact(data=[dict(i=agent.pre, s="0", d=icp.said)])
    hby.kvy.processEscrows()
    assert agent.kever is not None and agent.kever.delpre == human.pre, "delegation not completed"

    reg_rt = rgy.makeRegistry(name="root-reg", prefix=root.pre, noBackers=True)
    anchor(root, reg_rt, reg_rt.vcp, "0")
    reg_qv = rgy.makeRegistry(name="qvi-reg", prefix=qvi.pre, noBackers=True)
    anchor(qvi, reg_qv, reg_qv.vcp, "0")
    reg_le = rgy.makeRegistry(name="le-reg", prefix=le.pre, noBackers=True)
    anchor(le, reg_le, reg_le.vcp, "0")
    reg_hu = rgy.makeRegistry(name="human-reg", prefix=human.pre, noBackers=True)
    anchor(human, reg_hu, reg_hu.vcp, "0")
    rgy.processEscrows()

    # root -> QVI -> legal entity
    qvc = proving.credential(issuer=root.pre, schema=QVI.said, recipient=qvi.pre, status=reg_rt.regk, data=dict(LEI=QVI_LEI),
                             rules=block(**rules_for(QVI)))
    iss_q = reg_rt.issue(said=qvc.said)
    anchor(root, reg_rt, iss_q, "0")
    lev = proving.credential(issuer=qvi.pre, schema=LEV.said, recipient=le.pre, status=reg_qv.regk, data=dict(LEI=LEI),
                             source=block(qvi=dict(n=qvc.said, s=QVI.said)), rules=block(**rules_for(LEV)))
    iss_l = reg_qv.issue(said=lev.said)
    anchor(qvi, reg_qv, iss_l, "0")
    rgy.processEscrows()

    # LE -> human: ECR
    # private=True: adds a u salt so the SAID cannot be dictionary-attacked (the ecr_said becomes public when the ECR path is revoked)
    ecr = proving.credential(issuer=le.pre, schema=ECR.said, recipient=human.pre, status=reg_le.regk, private=True,
                             data=dict(LEI=LEI, personLegalName="Alex Example", engagementContextRole="Treasury Operations"),
                             source=block(le=dict(n=lev.said, s=LEV.said)), rules=block(**rules_for(ECR)))
    iss_e = reg_le.issue(said=ecr.said)
    anchor(le, reg_le, iss_e, "0")

    # human -> agent: AMC, limit bound into the credential
    seed = secrets.token_bytes(32)
    links = payword(seed, a.n)
    valid_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=a.days)
    amc = proving.credential(
        issuer=human.pre, schema=AMC.said, recipient=agent.pre, status=reg_hu.regk, private=True,
        data=dict(actionClass="supplier-payment", counterparties=a.scope.split(","),
                  validUntil=valid_until.isoformat(timespec="seconds"), unitYocto=str(int(decimal.Decimal(a.unit))),
                  paywordRoot=links[0].hex(), paywordLength=a.n, dailyLinks=a.daily, maxLinksPerPayment=a.max_links, maxStrikes=a.max_strikes, settlementRail=a.rail,
                  **credit_attrs(a),
                  **({"settlementAsset": a.asset} if a.asset else {})),
        source=block(ecr=dict(n=ecr.said, s=ECR.said, o="I2I")),
    )
    iss_a = reg_hu.issue(said=amc.said)
    anchor(human, reg_hu, iss_a, "0")
    rgy.processEscrows()

    # agent private key (= NEAR key). keripy's Signer.raw is a 32-byte seed; the NEAR private key string = base58(seed ‖ pk)
    pub = agent.kever.verfers[0]
    signer = hby.mgr.ks.pris.get(pub.qb64)
    near_sk = "ed25519:" + b58(signer.raw + pub.raw)
    near_pk = "ed25519:" + b58(pub.raw)

    # The LE agrees to these credit terms: signs (contract, AMC, terms, LEI). The contract checks it only at default disclosure, so the guarantor cannot frame another company
    terms_sig = ""
    if a.credit_limit:
        msg = f"writ:terms:v1\ncontract={a.contract}\namc={amc.said}\nterms={TERMS_HASH}\nlei={LEI}".encode()
        terms_sig = le.sign(ser=msg, indexed=False)[0].raw.hex()
    write_json(os.path.join(KEYSTORE, "terms.json"), dict(terms_sig=terms_sig))
    cover = cover_doc(a, le, amc.said)
    if cover:
        write_json(os.path.join(KEYSTORE, "cover.json"), cover)

    write_json(PRIVATE, dict(agent_near_secret_key=near_sk, payword_seed=seed.hex(), lei_salt_hint="verifier picks its own salt"))
    write_json(STATE, dict(root=root.pre, qvi=qvi.pre, le=le.pre, human=human.pre, agent=agent.pre, agent_near_pk=near_pk,
                           reg_rt=reg_rt.regk, reg_qv=reg_qv.regk, reg_le=reg_le.regk, reg_hu=reg_hu.regk,
                           qvc=qvc.said, lev=lev.said, ecr=ecr.said, amc=amc.said,
                           qvc_iss=iss_q.said, lev_iss=iss_l.said, ecr_iss=iss_e.said, amc_iss=iss_a.said, n=a.n))
    # keep a copy of the credential body (with SAID), serialized with its anchor on export
    write_json(os.path.join(KEYSTORE, "qvc.json"), qvc.sad)
    write_json(os.path.join(KEYSTORE, "lev.json"), lev.sad)
    write_json(os.path.join(KEYSTORE, "ecr.json"), ecr.sad)
    write_json(os.path.join(KEYSTORE, "amc.json"), amc.sad)
    print(json.dumps(dict(root=root.pre, le=le.pre, human=human.pre, agent=agent.pre, agent_near_pk=near_pk,
                          ecr=ecr.said, amc=amc.said, w0=links[0].hex()), indent=1))
    hby.close(); rgy.close()
    cmd_export(a)


def cmd_export(a):
    st = read_json(STATE)
    hby, rgy = open_all()
    os.makedirs(BUNDLE, exist_ok=True)

    def kel(pre):
        return b"".join(bytes(m) for m in hby.db.clonePreIter(pre=pre))

    def tel(pre):
        return b"".join(bytes(m) for m in rgy.reger.clonePreIter(pre=pre))

    def acdc(path, iss_said):
        sad = read_json(path)
        creder = serdering.SerderACDC(sad=sad, makify=False)
        return signing.serialize(creder, coring.Prefixer(qb64=creder.said), coring.Seqner(sn=0),
                                 coring.Saider(qb64=iss_said))

    # the order is the verifier's parsing order: KEL -> TEL -> ACDC
    kels = kel(st["root"]) + kel(st["qvi"]) + kel(st["le"]) + kel(st["human"])
    tels = b"".join(tel(st[k]) for k in ("reg_rt", "reg_qv", "reg_le", "reg_hu", "qvc", "lev", "ecr", "amc"))
    stream = kels + kel(st["agent"]) + tels
    for name, iss in (("qvc", "qvc_iss"), ("lev", "lev_iss"), ("ecr", "ecr_iss"), ("amc", "amc_iss")):
        stream += acdc(os.path.join(KEYSTORE, f"{name}.json"), st[iss])
    with open(os.path.join(BUNDLE, "chain.cesr"), "wb") as f:
        f.write(stream)
    write_json(os.path.join(BUNDLE, "schemas.json"), {ECR.said: ECR.sed, AMC.said: AMC.sed})
    # the holder presents "which one I want verified"; the trust anchor is not here, the verifier pins it itself (verify.py pin)
    write_json(os.path.join(BUNDLE, "terms.json"), read_json(os.path.join(KEYSTORE, "terms.json")))
    if os.path.exists(os.path.join(KEYSTORE, "cover.json")):
        write_json(os.path.join(BUNDLE, "cover.json"), read_json(os.path.join(KEYSTORE, "cover.json")))
    write_json(os.path.join(BUNDLE, "presentation.json"), dict(qvi_said=st["qvc"], lev_said=st["lev"], ecr_said=st["ecr"], amc_said=st["amc"], agent_aid=st["agent"]))
    # the issuer's public state: the verifier reads the latest KEL/TEL here directly, so a holder with an old bundle cannot hide a revocation
    os.makedirs(REGISTRAR, exist_ok=True)
    with open(os.path.join(REGISTRAR, "state.cesr"), "wb") as f:
        f.write(kels + tels)
    print(f"exported {len(stream)} bytes → keri/bundle/chain.cesr")
    hby.close(); rgy.close()


def cmd_release(a):
    st = read_json(STATE)
    pv = read_json(PRIVATE)
    k = int(a.k)
    if not 0 < k <= st["n"]:
        sys.exit(f"k must be in 1..{st['n']}")
    links = payword(bytes.fromhex(pv["payword_seed"]), st["n"])
    print(links[k].hex())


def cmd_revoke(a):
    st = read_json(STATE)
    hby, rgy = open_all()
    human = hby.habByName("human")
    reg_hu = rgy.registryByName("human-reg")
    rev = reg_hu.revoke(said=st["amc"])
    msg = anchor(human, reg_hu, rev, "1")
    rgy.processEscrows()
    ixn = serdering.SerderKERI(raw=bytes(msg))
    body = bytes(msg[:ixn.size])
    # take the indexed signature attached to the KEL, strip the index code -> 64-byte raw Ed25519 signature
    siger = indexing.Siger(qb64b=bytes(hby.db.getSigs(eventing.dgKey(human.pre, ixn.said))[0]))
    out = dict(cell_hint="pass --cell", amc_said=st["amc"], rev_said=rev.said,
               ixn_hex=body.hex(), ixn_said=ixn.said, ixn_sn=ixn.sn, sig_hex=siger.raw.hex(),
               seal=ixn.ked["a"][0], issuer_pk_hex=human.kever.verfers[0].raw.hex())
    write_json(os.path.join(BUNDLE, "revocation.json"), out)
    print(json.dumps(dict(rev=rev.said, ixn=ixn.said, seal=ixn.ked["a"][0]), indent=1))
    hby.close(); rgy.close()
    cmd_export(a)


def cmd_revoke_ecr(a):
    """HR (the legal entity) revokes the employee's ECR: TEL rev + LE KEL ixn anchor. No employee key needed."""
    st = read_json(STATE)
    hby, rgy = open_all()
    le = hby.habByName("le")
    reg_le = rgy.registryByName("le-reg")
    rev = reg_le.revoke(said=st["ecr"])
    msg = anchor(le, reg_le, rev, "1")
    rgy.processEscrows()
    ixn = serdering.SerderKERI(raw=bytes(msg))
    body = bytes(msg[:ixn.size])
    siger = indexing.Siger(qb64b=bytes(hby.db.getSigs(eventing.dgKey(le.pre, ixn.said))[0]))
    out = dict(ecr_said=st["ecr"], rev_said=rev.said, ixn_hex=body.hex(), ixn_said=ixn.said, ixn_sn=ixn.sn,
               sig_hex=siger.raw.hex(), seal=ixn.ked["a"][0], le_pk_hex=le.kever.verfers[0].raw.hex())
    write_json(os.path.join(BUNDLE, "revocation.json"), out)
    print(json.dumps(dict(rev=rev.said, ixn=ixn.said, seal=ixn.ked["a"][0]), indent=1))
    hby.close(); rgy.close()
    cmd_export(a)


def cmd_status(a):
    st = read_json(STATE)
    hby, rgy = open_all()
    for name in ("ecr", "amc"):
        reg = rgy.registryByName("le-reg" if name == "ecr" else "human-reg")
        s = reg.tever.vcState(st[name])
        print(f"{name.upper()} {st[name]}: {s.et if s else None} sn={s.s if s else None}")
    print("agent delegated by human:", hby.habByName("agent").kever.delpre == st["human"])
    hby.close(); rgy.close()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest="cmd", required=True)
    i = sp.add_parser("init")
    i.add_argument("--scope", required=True, help="允許的交易對手 NEAR 帳號，逗號分隔")
    i.add_argument("--rail", required=True, help="出資的 NEAR 帳號（法人金庫）")
    i.add_argument("--n", type=int, default=50)
    i.add_argument("--unit", default="1e23", help="每鏈節 yoctoNEAR（預設 0.1 NEAR）")
    i.add_argument("--daily", type=int, default=20)
    i.add_argument("--days", type=int, default=30)
    i.add_argument("--max-links", type=int, default=10, help="單筆最多幾節")
    i.add_argument("--credit-limit", default=None, help="可賒總額（yocto）；省略 = 這張 AMC 不能賒帳")
    i.add_argument("--bond-bps", type=int, default=5000)
    i.add_argument("--premium-bps", type=int, default=0, help="保證費，每 30 天的萬分比，不滿一期算一期")
    i.add_argument("--fee-payer", choices=["Buyer", "Seller"], default="Buyer", help="Buyer：賣方接受時從公司金庫收；Seller：賣方收款時從貨款扣")
    i.add_argument("--seller-cap-bps", type=int, default=0, help="單一賣方的曝險上限（質押的萬分比）；0 = 不限")
    i.add_argument("--credit-asset", default=None, help="信用的計價資產（NEP-141 合約）；省略 = 跟 --asset 相同。必須等於格的資產")
    i.add_argument("--cover-limit", default=None, help="fooled-agent cover: most the guarantor pays in total (yocto or token units); omit = no cover. Not in the AMC; the legal entity signs it separately")
    i.add_argument("--cover-deductible-bps", type=int, default=2000, help="the company's share of each loss, 1000 to 9000")
    i.add_argument("--cover-premium-bps", type=int, default=200, help="fee on the limit per 30 days, at most 2000")
    i.add_argument("--cover-claim-window", type=int, default=2419200, help="seconds after a payment during which it can be claimed; at least twice the contract's dispute_timeout")
    i.add_argument("--cover-arbiter", default=None, help="who rules on claims; not the company, the guarantor or the contract owner")
    i.add_argument("--min-tenor", type=int, default=60)
    i.add_argument("--max-tenor", type=int, default=2592000)
    i.add_argument("--arbiter", default=None)
    i.add_argument("--contract", default=None)
    i.add_argument("--max-strikes", type=int, default=3, help="連續拒絕幾次刪鑰匙；0 = 不自動刪")
    i.add_argument("--asset", default=None, help="NEP-141 代幣合約帳號（省略 = NEAR）")
    sp.add_parser("export")
    r = sp.add_parser("release"); r.add_argument("k")
    sp.add_parser("revoke")
    sp.add_parser("revoke-ecr")
    sp.add_parser("status")
    a = p.parse_args()
    dict(init=cmd_init, export=cmd_export, release=cmd_release, revoke=cmd_revoke, status=cmd_status, **{"revoke-ecr": cmd_revoke_ecr})[a.cmd](a)
