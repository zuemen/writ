"""
make keri-check 的反例：驗證端必須拒絕每一張偽造或過期的憑證。

每個情境都在暫存資料夾裡用真 keripy 產生憑證，再交給 verify.verify_chain()。
第一項是誠實的鏈，必須通過，證明其他情境不是因為環境壞掉才被拒。
最後一行 KERI_FORGERIES|PASS|<n> 給機器檢查。
"""
import os, secrets, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = tempfile.mkdtemp(prefix="writ-forge-")
for name in ("common.py", "verify.py"):
    shutil.copy(os.path.join(HERE, name), WORK)
sys.path.insert(0, WORK)
os.environ["WRIT_VERIFIER_POLICY"] = os.path.join(WORK, "policy.json")

from keri.app import habbing, signing
from keri.core import coring, eventing, serdering
from keri.core.eventing import SealEvent
from keri.vc import proving
from keri.vdr import credentialing

import common
from common import AMC, BUNDLE, ECR, REGISTRAR, write_json
import verify as V


def anchor(hab, reg, serder, sn):
    seal = SealEvent(serder.pre, sn, serder.said)._asdict()
    msg = hab.interact(data=[seal])
    reg.anchorMsg(pre=serder.pre, regd=serder.said, seqner=coring.Seqner(sn=hab.kever.sn),
                  saider=coring.Saider(qb64=hab.kever.serder.said))
    return msg


def build(name, forge_ecr=False, forge_amc=False, schema=None, edge_s=None, edge_o="I2I", pin_other=False,
          revoke_after_bundle=None):
    """建一條鏈並寫出 bundle／registrar。參數決定哪裡造假。"""
    with habbing.openHby(name=name, temp=True) as hby:
        rgy = credentialing.Regery(hby=hby, name=name, temp=True)
        le = hby.makeHab(name="le")
        human = hby.makeHab(name="human")
        agent = hby.makeHab(name="agent", delpre=human.pre)
        icp = serdering.SerderKERI(raw=bytes(hby.db.getEvt(eventing.dgKey(agent.pre, hby.db.getKeLast(eventing.snKey(agent.pre, 0))))))
        human.interact(data=[dict(i=agent.pre, s="0", d=icp.said)])
        hby.kvy.processEscrows()

        reg_hu = rgy.makeRegistry(name="human-reg", prefix=human.pre, noBackers=True)
        anchor(human, reg_hu, reg_hu.vcp, "0")
        reg_ag = rgy.makeRegistry(name="agent-reg", prefix=agent.pre, noBackers=True)
        anchor(agent, reg_ag, reg_ag.vcp, "0")
        reg_le = rgy.makeRegistry(name="le-reg", prefix=le.pre, noBackers=True)
        anchor(le, reg_le, reg_le.vcp, "0")
        rgy.processEscrows()

        # forge_ecr：員工用自己的登錄簿發一張 i = 真 LE 的 ECR，LE 什麼都沒簽
        reg_e, hab_e = (reg_hu, human) if forge_ecr else (reg_le, le)
        sch = schema or ECR
        ecr = proving.credential(issuer=le.pre, schema=sch.said, recipient=human.pre, status=reg_e.regk, private=True,
                                 data=dict(LEI="WRITDEMO000000000017", personLegalName="Alex Example", engagementContextRole="Treasury"))
        iss_e = reg_e.issue(said=ecr.said)
        anchor(hab_e, reg_e, iss_e, "0")

        # forge_amc：拿著 agent 鑰匙的人自己發一張 i = 員工 的 AMC，替自己加額度
        reg_a, hab_a = (reg_ag, agent) if forge_amc else (reg_hu, human)
        amc = proving.credential(issuer=human.pre, schema=AMC.said, recipient=agent.pre, status=reg_a.regk, private=True,
                                 data=dict(actionClass="supplier-payment", counterparties=["merchant.test.near"],
                                           validUntil="2099-01-01T00:00:00+00:00", unitYocto="1", paywordRoot="00" * 32,
                                           paywordLength=5, dailyLinks=5, maxLinksPerPayment=5, maxStrikes=3, settlementRail="acme.test.near"),
                                 source=dict(d="", ecr=dict(n=ecr.said, s=edge_s or sch.said, o=edge_o)))
        iss_a = reg_a.issue(said=amc.said)
        anchor(hab_a, reg_a, iss_a, "0")
        rgy.processEscrows()

        def kel(p): return b"".join(bytes(m) for m in hby.db.clonePreIter(pre=p))
        def tel(p): return b"".join(bytes(m) for m in rgy.reger.clonePreIter(pre=p))
        def acdc(c, iss): return signing.serialize(c, coring.Prefixer(qb64=c.said), coring.Seqner(sn=0), coring.Saider(qb64=iss))
        regs = [reg_le.regk, reg_hu.regk, reg_ag.regk]

        def registrar():
            os.makedirs(REGISTRAR, exist_ok=True)
            with open(os.path.join(REGISTRAR, "state.cesr"), "wb") as f:
                f.write(kel(le.pre) + kel(human.pre) + kel(agent.pre) + b"".join(tel(r) for r in regs) + tel(ecr.said) + tel(amc.said))

        os.makedirs(BUNDLE, exist_ok=True)
        with open(os.path.join(BUNDLE, "chain.cesr"), "wb") as f:
            f.write(kel(le.pre) + kel(human.pre) + kel(agent.pre) + b"".join(tel(r) for r in regs) + tel(ecr.said) + tel(amc.said)
                    + acdc(ecr, iss_e.said) + acdc(amc, iss_a.said))
        write_json(os.path.join(BUNDLE, "presentation.json"), dict(ecr_said=ecr.said, amc_said=amc.said, agent_aid=agent.pre))
        write_json(V.POLICY, dict(le_aid=("E" + secrets.token_urlsafe(32)[:43]) if pin_other else le.pre))

        # 撤銷發生在持有人拿到 bundle 之後：只有 registrar 看得到
        if revoke_after_bundle == "ecr":
            anchor(le, reg_le, reg_le.revoke(said=ecr.said), "1")
        elif revoke_after_bundle == "amc":
            anchor(human, reg_hu, reg_hu.revoke(said=amc.said), "1")
        rgy.processEscrows()
        registrar()


OTHER = common._schema("Totally Not An ECR", {"LEI": {"type": "string"}, "personLegalName": {"type": "string"}, "engagementContextRole": {"type": "string"}},
                       ["LEI", "personLegalName", "engagementContextRole"], None)

CASES = [
    ("honest chain", dict(), True),
    ("F1 employee forges an ECR naming the real legal entity as issuer", dict(forge_ecr=True), False),
    ("F2 agent key holder issues itself an AMC naming the employee as issuer", dict(forge_amc=True), False),
    ("F3 chain roots in a legal entity the verifier did not pin", dict(pin_other=True), False),
    ("F4 legal entity's credential is not an ECR (other schema)", dict(schema=OTHER), False),
    ("F5 AMC edge names the wrong schema for the ECR", dict(edge_s=AMC.said), False),
    ("F6 AMC edge is not I2I", dict(edge_o="NI2I"), False),
    ("F7 holder shows an old bundle after HR revoked the ECR", dict(revoke_after_bundle="ecr"), False),
    ("F8 holder shows an old bundle after the employee revoked the AMC", dict(revoke_after_bundle="amc"), False),
]

fails = 0
for i, (label, kw, expect_ok) in enumerate(CASES):
    shutil.rmtree(BUNDLE, ignore_errors=True)
    shutil.rmtree(REGISTRAR, ignore_errors=True)
    build(f"forge{i}", **kw)
    try:
        V.verify_chain()
        accepted, why = True, ""
    except V.ChainError as e:
        accepted, why = False, str(e)
    except Exception as e:  # 解析階段被 keripy 擋下也算拒絕，但要看得到原因
        accepted, why = False, f"{type(e).__name__}: {e}"
    good = accepted == expect_ok
    fails += not good
    print(f"{'✓' if good else '✗'} {label} → {'accepted' if accepted else 'REFUSED: ' + why[:90]}")

shutil.rmtree(WORK, ignore_errors=True)
print(f"KERI_FORGERIES|{'PASS' if not fails else 'FAIL'}|{len(CASES) - 1}")
sys.exit(1 if fails else 0)
