"""
發行端（模擬法人那一側）—— 用 keripy 建立並持久保存：

  LE（法人 AID）──ECR──▶ human（職員 AID，ECR 持有人）──AMC──▶ agent（human KEL 之下的委派 AID）

AMC 的屬性把「額度」綁進憑證：paywordRoot（w0）、paywordLength（n）、unitYocto、dailyLinks、
counterparties（允許的交易對手）、validUntil、settlementRail（出資的 NEAR 帳號）。

指令
  python issuer.py init --scope merchant.test.near --rail acme.test.near [--n 50 --unit 1e23 --daily 20 --days 30]
  python issuer.py export            # 匯出公開 CESR 到 keri/bundle/（驗證端只吃這個）
  python issuer.py release K         # human 撥鏈節：印出 links[K]（agent 付到第 K 節所需的 preimage）
  python issuer.py revoke            # human 撤銷 AMC：TEL rev + KEL ixn 錨定；印出 revocation.json
  python issuer.py status

私密資料（agent 私鑰、PayWord 種子）只寫在 keri/.keystore/（.gitignore）。這是 demo 的 mock 生態系：
LE 之上的 QVI／GLEIF 根不在範圍內（README 揭露）。
"""
import argparse, datetime, decimal, hashlib, json, os, secrets, sys

from keri.app import habbing, signing
from keri.core import coring, eventing, serdering, indexing
from keri.core.eventing import SealEvent
from keri.vc import proving
from keri.vdr import credentialing, viring

from common import AMC, BUNDLE, ECR, KEYSTORE, PRIVATE, b58, read_json, write_json

LEI = "5493001KJTIIGC8Y1R12"  # mock LEI（格式正確的範例值）
STATE = os.path.join(KEYSTORE, "state.json")


def open_all():
    os.makedirs(KEYSTORE, exist_ok=True)
    hby = habbing.Habery(name="writ-issuer", headDirPath=KEYSTORE, temp=False)
    reger = viring.Reger(name="writ-issuer", headDirPath=KEYSTORE, reopen=True, db=hby.db)
    rgy = credentialing.Regery(hby=hby, name="writ-issuer", reger=reger)
    return hby, rgy


def anchor(hab, registry, serder, sn: str):
    """TEL 事件以 ixn 錨定進 hab 的 KEL；回傳 ixn 的完整 CESR 訊息。"""
    seal = SealEvent(serder.pre, sn, serder.said)._asdict()
    msg = hab.interact(data=[seal])
    registry.anchorMsg(pre=serder.pre, regd=serder.said,
                       seqner=coring.Seqner(sn=hab.kever.sn), saider=coring.Saider(qb64=hab.kever.serder.said))
    return msg


def payword(seed: bytes, n: int):
    """links[n] = seed，links[k] = sha256(links[k+1])；links[0] = w0。"""
    links = [b""] * (n + 1)
    links[n] = seed
    for k in range(n - 1, -1, -1):
        links[k] = hashlib.sha256(links[k + 1]).digest()
    return links


def cmd_init(a):
    if os.path.exists(STATE):
        sys.exit("already initialized (rm -rf keri/.keystore to start over)")
    hby, rgy = open_all()
    le = hby.makeHab(name="le")
    human = hby.makeHab(name="human")
    agent = hby.makeHab(name="agent", delpre=human.pre)
    # human 以 ixn 核准委派：seal {i: agent, s: 0, d: agent icp SAID}
    icp = serdering.SerderKERI(raw=bytes(hby.db.getEvt(eventing.dgKey(agent.pre, hby.db.getKeLast(eventing.snKey(agent.pre, 0))))))
    human.interact(data=[dict(i=agent.pre, s="0", d=icp.said)])
    hby.kvy.processEscrows()
    assert agent.kever is not None and agent.kever.delpre == human.pre, "delegation not completed"

    reg_le = rgy.makeRegistry(name="le-reg", prefix=le.pre, noBackers=True)
    anchor(le, reg_le, reg_le.vcp, "0")
    reg_hu = rgy.makeRegistry(name="human-reg", prefix=human.pre, noBackers=True)
    anchor(human, reg_hu, reg_hu.vcp, "0")
    rgy.processEscrows()

    # LE → human：ECR
    ecr = proving.credential(issuer=le.pre, schema=ECR.said, recipient=human.pre, status=reg_le.regk,
                             data=dict(LEI=LEI, personLegalName="Chu Ting-Yi", engagementContextRole="Treasury Operations"))
    iss_e = reg_le.issue(said=ecr.said)
    anchor(le, reg_le, iss_e, "0")

    # human → agent：AMC，額度綁進憑證
    seed = secrets.token_bytes(32)
    links = payword(seed, a.n)
    valid_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=a.days)
    amc = proving.credential(
        issuer=human.pre, schema=AMC.said, recipient=agent.pre, status=reg_hu.regk,
        data=dict(actionClass="supplier-payment", counterparties=a.scope.split(","),
                  validUntil=valid_until.isoformat(timespec="seconds"), unitYocto=str(int(decimal.Decimal(a.unit))),
                  paywordRoot=links[0].hex(), paywordLength=a.n, dailyLinks=a.daily, settlementRail=a.rail,
                  **({"settlementAsset": a.asset} if a.asset else {})),
        source=dict(d="", ecr=dict(n=ecr.said, s=ECR.said)),
    )
    iss_a = reg_hu.issue(said=amc.said)
    anchor(human, reg_hu, iss_a, "0")
    rgy.processEscrows()

    # agent 私鑰（= NEAR 金鑰）。keripy 的 Signer.raw 是 32 bytes seed；NEAR 私鑰字串 = base58(seed ‖ pk)
    pub = agent.kever.verfers[0]
    signer = hby.mgr.ks.pris.get(pub.qb64)
    near_sk = "ed25519:" + b58(signer.raw + pub.raw)
    near_pk = "ed25519:" + b58(pub.raw)

    write_json(PRIVATE, dict(agent_near_secret_key=near_sk, payword_seed=seed.hex(), lei_salt_hint="verifier picks its own salt"))
    write_json(STATE, dict(le=le.pre, human=human.pre, agent=agent.pre, agent_near_pk=near_pk,
                           reg_le=reg_le.regk, reg_hu=reg_hu.regk, ecr=ecr.said, amc=amc.said,
                           ecr_iss=iss_e.said, amc_iss=iss_a.said, n=a.n))
    # 憑證本體（含 SAID）留一份，export 時序列化附錨點
    write_json(os.path.join(KEYSTORE, "ecr.json"), ecr.sad)
    write_json(os.path.join(KEYSTORE, "amc.json"), amc.sad)
    print(json.dumps(dict(le=le.pre, human=human.pre, agent=agent.pre, agent_near_pk=near_pk,
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

    # 順序即驗證端的解析順序：KEL → TEL → ACDC
    stream = kel(st["le"]) + kel(st["human"]) + kel(st["agent"])
    stream += tel(st["reg_le"]) + tel(st["reg_hu"]) + tel(st["ecr"]) + tel(st["amc"])
    stream += acdc(os.path.join(KEYSTORE, "ecr.json"), st["ecr_iss"]) + acdc(os.path.join(KEYSTORE, "amc.json"), st["amc_iss"])
    with open(os.path.join(BUNDLE, "chain.cesr"), "wb") as f:
        f.write(stream)
    write_json(os.path.join(BUNDLE, "schemas.json"), {ECR.said: ECR.sed, AMC.said: AMC.sed})
    # 驗證端唯一的「信任錨」：mock LE 的 AID（正式版由 QVI 發的 LE vLEI 鏈回 GLEIF 根）
    write_json(os.path.join(BUNDLE, "trust.json"), dict(le_aid=st["le"], amc_said=st["amc"], agent_aid=st["agent"]))
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
    # 取附在 KEL 上的那個索引簽章，去掉索引碼 → 64 bytes 原始 Ed25519 簽章
    siger = indexing.Siger(qb64b=bytes(hby.db.getSigs(eventing.dgKey(human.pre, ixn.said))[0]))
    out = dict(cell_hint="pass --cell", amc_said=st["amc"], rev_said=rev.said,
               ixn_hex=body.hex(), ixn_said=ixn.said, ixn_sn=ixn.sn, sig_hex=siger.raw.hex(),
               seal=ixn.ked["a"][0], issuer_pk_hex=human.kever.verfers[0].raw.hex())
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
    i.add_argument("--asset", default=None, help="NEP-141 代幣合約帳號（省略 = NEAR）")
    sp.add_parser("export")
    r = sp.add_parser("release"); r.add_argument("k")
    sp.add_parser("revoke")
    sp.add_parser("status")
    a = p.parse_args()
    dict(init=cmd_init, export=cmd_export, release=cmd_release, revoke=cmd_revoke, status=cmd_status)[a.cmd](a)
