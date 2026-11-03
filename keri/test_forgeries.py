"""
Counter-examples for make keri-check: the verifier must reject every forged or expired credential.

Each scenario builds credentials with real keripy in a temporary folder, then hands them to verify.verify_chain().
The first case is an honest chain and must pass, proving the other cases are not rejected only because the environment is broken.
The last line KERI_FORGERIES|PASS|<n> is for machine checking.
"""
import os, secrets, shutil, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = tempfile.mkdtemp(prefix="writ-forge-")
for name in ("common.py", "verify.py"):
    shutil.copy(os.path.join(HERE, name), WORK)
shutil.copytree(os.path.join(HERE, "schemas"), os.path.join(WORK, "schemas"))
sys.path.insert(0, WORK)
os.environ["WRIT_VERIFIER_POLICY"] = os.path.join(WORK, "policy.json")

from keri.app import habbing, signing
from keri.core import coring, eventing, serdering
from keri.core.eventing import SealEvent
from keri.vc import proving
from keri.vdr import credentialing

import common
from common import AMC, BUNDLE, ECR, LEV, QVI, REGISTRAR, block, rules_for, write_json
import verify as V


def anchor(hab, reg, serder, sn):
    seal = SealEvent(serder.pre, sn, serder.said)._asdict()
    msg = hab.interact(data=[seal])
    reg.anchorMsg(pre=serder.pre, regd=serder.said, seqner=coring.Seqner(sn=hab.kever.sn),
                  saider=coring.Saider(qb64=hab.kever.serder.said))
    return msg


def build(name, forge_ecr=False, forge_amc=False, schema=None, edge_s=None, edge_o="I2I", pin_other=False,
          revoke_after_bundle=None, rogue_qvi=False, ecr_lei="WRITDEMO000000000017", no_rules=False, bad_edge_said=False, altered_rules=False):
    """Build a chain and write the bundle/registrar. The parameters decide where to forge."""
    with habbing.openHby(name=name, temp=True) as hby:
        rgy = credentialing.Regery(hby=hby, name=name, temp=True)
        root = hby.makeHab(name="root")
        qvi = hby.makeHab(name="qvi")
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
        reg_rt = rgy.makeRegistry(name="root-reg", prefix=root.pre, noBackers=True)
        anchor(root, reg_rt, reg_rt.vcp, "0")
        reg_qv = rgy.makeRegistry(name="qvi-reg", prefix=qvi.pre, noBackers=True)
        anchor(qvi, reg_qv, reg_qv.vcp, "0")
        rgy.processEscrows()

        # rogue_qvi: the QVI credential was issued by an imposter root, not the root the verifier pinned
        fake_root = hby.makeHab(name="fakeroot") if rogue_qvi else None
        reg_fr = rgy.makeRegistry(name="fake-reg", prefix=fake_root.pre, noBackers=True) if rogue_qvi else None
        if rogue_qvi:
            anchor(fake_root, reg_fr, reg_fr.vcp, "0"); rgy.processEscrows()
        reg_q, hab_q = (reg_fr, fake_root) if rogue_qvi else (reg_rt, root)
        qvc = proving.credential(issuer=hab_q.pre, schema=QVI.said, recipient=qvi.pre, status=reg_q.regk, data=dict(LEI="WRITDEMOQVI000000000"),
                                 rules=block(**rules_for(QVI)))
        iss_q = reg_q.issue(said=qvc.said); anchor(hab_q, reg_q, iss_q, "0")
        lev = proving.credential(issuer=qvi.pre, schema=LEV.said, recipient=le.pre, status=reg_qv.regk, data=dict(LEI="WRITDEMO000000000017"),
                                 source=block(qvi=dict(n=qvc.said, s=QVI.said)), rules=block(**rules_for(LEV)))
        iss_l = reg_qv.issue(said=lev.said); anchor(qvi, reg_qv, iss_l, "0")
        rgy.processEscrows()

        # forge_ecr: the employee issues an ECR with i = the real LE from their own registry, the LE signed nothing
        reg_e, hab_e = (reg_hu, human) if forge_ecr else (reg_le, le)
        sch = schema or ECR
        ecr = proving.credential(issuer=le.pre, schema=sch.said, recipient=human.pre, status=reg_e.regk, private=True,
                                 data=dict(LEI=ecr_lei, personLegalName="Alex Example", engagementContextRole="Treasury"),
                                 source=block(le=dict(n=lev.said, s=LEV.said)) if not bad_edge_said else dict(d="", le=dict(n=lev.said, s=LEV.said)),
                                 rules=None if no_rules else (block(usageDisclaimer=dict(l="our own terms")) if altered_rules else block(**rules_for(ECR))))
        iss_e = reg_e.issue(said=ecr.said)
        anchor(hab_e, reg_e, iss_e, "0")

        # forge_amc: whoever holds the agent key issues an AMC with i = the employee, adding limit for themselves
        reg_a, hab_a = (reg_ag, agent) if forge_amc else (reg_hu, human)
        amc = proving.credential(issuer=human.pre, schema=AMC.said, recipient=agent.pre, status=reg_a.regk, private=True,
                                 data=dict(actionClass="supplier-payment", counterparties=["merchant.test.near"],
                                           validUntil="2099-01-01T00:00:00+00:00", unitYocto="1", paywordRoot="00" * 32,
                                           paywordLength=5, dailyLinks=5, maxLinksPerPayment=5, maxStrikes=3, settlementRail="acme.test.near"),
                                 source=block(ecr=dict(n=ecr.said, s=edge_s or sch.said, o=edge_o)))
        iss_a = reg_a.issue(said=amc.said)
        anchor(hab_a, reg_a, iss_a, "0")
        rgy.processEscrows()

        def kel(p): return b"".join(bytes(m) for m in hby.db.clonePreIter(pre=p))
        def tel(p): return b"".join(bytes(m) for m in rgy.reger.clonePreIter(pre=p))
        def acdc(c, iss): return signing.serialize(c, coring.Prefixer(qb64=c.said), coring.Seqner(sn=0), coring.Saider(qb64=iss))
        regs = [reg_rt.regk, reg_qv.regk, reg_le.regk, reg_hu.regk, reg_ag.regk] + ([reg_fr.regk] if rogue_qvi else [])
        habs = [root, qvi] + ([fake_root] if rogue_qvi else []) + [le, human, agent]
        allkel = lambda: b"".join(kel(h.pre) for h in habs)
        alltel = lambda: b"".join(tel(r) for r in regs) + tel(qvc.said) + tel(lev.said) + tel(ecr.said) + tel(amc.said)

        def registrar():
            os.makedirs(REGISTRAR, exist_ok=True)
            with open(os.path.join(REGISTRAR, "state.cesr"), "wb") as f:
                f.write(allkel() + alltel())

        os.makedirs(BUNDLE, exist_ok=True)
        with open(os.path.join(BUNDLE, "chain.cesr"), "wb") as f:
            f.write(allkel() + alltel() + acdc(qvc, iss_q.said) + acdc(lev, iss_l.said) + acdc(ecr, iss_e.said) + acdc(amc, iss_a.said))
        write_json(os.path.join(BUNDLE, "presentation.json"), dict(qvi_said=qvc.said, lev_said=lev.said, ecr_said=ecr.said, amc_said=amc.said, agent_aid=agent.pre))
        write_json(V.POLICY, dict(root_aid=("E" + secrets.token_urlsafe(32)[:43]) if pin_other else root.pre))

        # revocation happened after the holder got the bundle: only the registrar shows it
        if revoke_after_bundle == "ecr":
            anchor(le, reg_le, reg_le.revoke(said=ecr.said), "1")
        elif revoke_after_bundle == "lev":
            anchor(qvi, reg_qv, reg_qv.revoke(said=lev.said), "1")
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
    ("F3 chain roots in a root the verifier did not pin", dict(pin_other=True), False),
    ("F4 legal entity's credential is not an ECR (other schema)", dict(schema=OTHER), False),
    ("F5 AMC edge names the wrong schema for the ECR", dict(edge_s=AMC.said), False),
    ("F6 AMC edge is not I2I", dict(edge_o="NI2I"), False),
    ("F7 holder shows an old bundle after HR revoked the ECR", dict(revoke_after_bundle="ecr"), False),
    ("F8 holder shows an old bundle after the employee revoked the AMC", dict(revoke_after_bundle="amc"), False),
    ("F9 QVI credential issued by a fake root", dict(rogue_qvi=True), False),
    ("F10 QVI revoked the legal entity's vLEI after the bundle was made", dict(revoke_after_bundle="lev"), False),
    ("F11 ECR states a different LEI than the legal entity's vLEI", dict(ecr_lei="WRITDEMO999999999999"), False),
    ("F12 ECR has no rules section", dict(no_rules=True), False),
    ("F13 ECR edge section is not self-addressing", dict(bad_edge_said=True), False),
    ("F14 ECR replaces the official rules text with its own", dict(altered_rules=True), False),
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
    except Exception as e:  # rejection by keripy at the parsing stage also counts, but the reason must be visible
        accepted, why = False, f"{type(e).__name__}: {e}"
    good = accepted == expect_ok
    fails += not good
    print(f"{'✓' if good else '✗'} {label} → {'accepted' if accepted else 'REFUSED: ' + why[:90]}")

shutil.rmtree(WORK, ignore_errors=True)
print(f"KERI_FORGERIES|{'PASS' if not fails else 'FAIL'}|{len(CASES) - 1}")
sys.exit(1 if fails else 0)
