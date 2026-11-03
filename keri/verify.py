"""
Verifier side (an allowlisted verifier, corresponds to the PSP role in GLEIF discussion paper Annex A).

Takes the public CESR presented by the holder (keri/bundle/) and re-verifies the whole chain with keripy in a **fresh temporary keystore**;
credential status is looked up separately from the issuer's public source (keri/registrar/), the TEL given by the holder is not trusted:

  1. KEL: signatures and order of the three event logs LE, human, agent; the agent must be a delegated AID under the human (delpre == human)
  2. TEL: both ECR and AMC are in the "issued, not revoked" state
  3. ACDC: credential SAID, official vLEI schema (keri/schemas/), TEL anchor; the AMC's edge points to the ECR, and the ECR's holder == the AMC's issuer
  4. Trust chain: the root pinned by the verifier (verify.py pin; mock, the real one is the GLEIF root) -> QVI -> legal entity -> ECR, I2I at each level, LEI must match
     the credential's i field does not count: the registry's controller must be the issuer; the schema SAID is also decided by the verifier
  5. the agent's current KERI public key == the function-call key to be attached on NEAR

Only when everything passes is an attestation signed (Ed25519, the signed bytes are identical character by character to the contract's attestation_message).

  python verify.py keygen                                    # generate the verifier key (prints pk hex)
  python verify.py pin --root <AID>                          # pin the trust root (verifier configuration, does not come from the holder)
  python verify.py attest --verifier verifier.test.near      # verify the chain + print the args JSON for register
  python verify.py check                                     # verify the chain only, do not sign
  python verify.py reveal --amc <SAID>                       # unseal: print the LEI and salt committed earlier
"""
import argparse, datetime, hashlib, hmac, json, os, secrets, sys

import pysodium
from keri.app import habbing
from keri.core import coring, parsing, scheming
from keri.vdr import credentialing, verifying

from common import AMC, BUNDLE, COVER_FIELDS, ECR, HERE, LEV, QVI, REGISTRAR, b58, cover_line, cover_message, read_json, write_json

_STATE = os.path.join(HERE, "..", os.environ.get("WRIT_DEMO_DIR", ".demo"))
VKEY = os.environ.get("WRIT_VERIFIER_KEY", os.path.join(_STATE, "verifier_key.json"))
RECORDS = os.path.join(_STATE, "verifier_records.json")  # the LEI salt exists only here, at the verifier
POLICY = os.environ.get("WRIT_VERIFIER_POLICY", os.path.join(_STATE, "verifier_policy.json"))  # trust anchor pinned by the verifier itself


class ChainError(Exception):
    pass


def verify_chain():
    """Returns a dict (result); any failing step raises ChainError."""
    if not os.path.exists(POLICY):
        raise ChainError("no pinned trust root: run verify.py pin --root <AID>")
    root_aid = read_json(POLICY)["root_aid"]
    shown = read_json(os.path.join(BUNDLE, "presentation.json"))
    with open(os.path.join(BUNDLE, "chain.cesr"), "rb") as f:
        stream = bytearray(f.read())
    with open(os.path.join(REGISTRAR, "state.cesr"), "rb") as f:
        live = bytearray(f.read())

    with habbing.openHby(name="writ-verifier", temp=True) as hby:
        rgy = credentialing.Regery(hby=hby, name="writ-verifier", temp=True)
        vry = verifying.Verifier(hby=hby, reger=rgy.reger)
        # accept only schemas the verifier itself recognizes, do not take definitions brought by the holder
        for sch in (QVI, LEV, ECR, AMC):
            hby.db.schema.pin(sch.said, scheming.Schemer(sed=sch.sed))
        psr = parsing.Parser(kvy=hby.kvy, tvy=rgy.tvy, vry=vry)
        psr.parse(ims=stream)
        psr.parse(ims=live)
        for _ in range(3):  # delegation, TEL and credentials may all enter escrow first
            hby.kvy.processEscrows(); rgy.tvy.processEscrows(); vry.processEscrows()

        checks = []

        def ok(name, cond, detail=""):
            checks.append(dict(check=name, ok=bool(cond), detail=detail))
            if not cond:
                raise ChainError(f"{name} — failed: {detail}")

        amc_said = shown["amc_said"]
        amc = rgy.reger.creds.get(keys=amc_said)
        # keripy does not accept a credential revoked upstream in the chain: state the real reason, do not just say "AMC parsing failed"
        names = {shown.get("qvi_said"): "QVI credential", shown.get("lev_said"): "legal entity vLEI", shown.get("ecr_said"): "ECR", amc_said: "AMC"}
        for said, name in names.items():
            for tever in rgy.tevers.values():
                st = tever.vcState(said) if said else None
                if st is not None and st.et == "rev":
                    raise ChainError(f"{name} revoked in its TEL ({said})")
        ok("AMC parsed, SAID + schema valid, anchored in TEL", amc is not None, amc_said)
        ecr_said = amc.edge["ecr"]["n"]
        ecr = rgy.reger.creds.get(keys=ecr_said)
        ok("ECR parsed, SAID + schema valid, anchored in TEL", ecr is not None, ecr_said)

        human, agent = amc.issuer, amc.attrib["i"]
        lev = rgy.reger.creds.get(keys=ecr.edge["le"]["n"]) if "le" in (ecr.edge or {}) else None
        ok("legal entity vLEI parsed and anchored", lev is not None, shown.get("lev_said"))
        qvc = rgy.reger.creds.get(keys=lev.edge["qvi"]["n"]) if "qvi" in (lev.edge or {}) else None
        ok("QVI credential parsed and anchored", qvc is not None, shown.get("qvi_said"))
        ok("trust root: QVI credential issued by the pinned root AID", qvc.issuer == root_aid, qvc.issuer)
        ok("I2I: legal entity vLEI issued by the QVI", lev.issuer == qvc.attrib["i"], lev.issuer)
        ok("I2I: ECR issued by the legal entity", ecr.issuer == lev.attrib["i"], ecr.issuer)
        ok("the ECR's LEI is the legal entity vLEI's LEI", ecr.attrib["LEI"] == lev.attrib["LEI"], ecr.attrib["LEI"])
        ok("ECR carries its rules section", "r" in ecr.sad, "")
        def said_ok(section):
            d = section.get("d", "")
            return bool(d) and coring.Saider(qb64=d).verify(section, prefixed=True)
        ok("edge and rules sections are self-addressing", all(said_ok(sec) for sec in (lev.edge, ecr.edge, lev.sad["r"], ecr.sad["r"], amc.edge)), "")
        for label, c in (("QVI credential", qvc), ("legal entity vLEI", lev)):
            ok(f"{label} registry controlled by its issuer", rgy.tevers[c.regi].pre == c.issuer, c.regi)
        ok("ECR registry controlled by its issuer", rgy.tevers[ecr.regi].pre == ecr.issuer, ecr.regi)
        ok("AMC registry controlled by its issuer", rgy.tevers[amc.regi].pre == amc.issuer, amc.regi)
        ok("official vLEI schema SAIDs, plus the AMC schema this verifier accepts", qvc.schema == QVI.said and lev.schema == LEV.said and ecr.schema == ECR.said and amc.schema == AMC.said, f"{ecr.schema} {amc.schema}")
        ok("AMC edge to the ECR: right schema, I2I", amc.edge["ecr"].get("s") == ECR.said and amc.edge["ecr"].get("o") == "I2I", str(amc.edge["ecr"]))
        ok("ECR holder is a natural person who issued the AMC (I2I chain)", ecr.attrib["i"] == human, human)
        ok("AMC holder is the presented agent AID", agent == shown["agent_aid"], agent)

        for name, cred in (("ECR", ecr), ("AMC", amc)):
            st = rgy.tevers[cred.regi].vcState(cred.said)
            ok(f"{name} TEL state is issued (not revoked)", st is not None and st.et == "iss",
           ("revoked (TEL rev)" if st and st.et == "rev" else st.et) if st else "no TEL state")

        hk, ak = hby.kevers.get(human), hby.kevers.get(agent)
        ok("human KEL verified", hk is not None, f"sn={hk.sn if hk else None}")
        ok("agent KEL verified as delegated AID under human", ak is not None and ak.delpre == human,
           f"delpre={ak.delpre if ak else None}")

        a = amc.attrib
        valid_until = datetime.datetime.fromisoformat(a["validUntil"])
        ok("AMC validity window not passed", valid_until > datetime.datetime.now(datetime.timezone.utc), a["validUntil"])

        return dict(
            checks=checks,
            amc_said=amc_said, ecr_said=ecr_said, lei=ecr.attrib["LEI"],
            human=human, agent=agent,
            issuer_aid=human,
            issuer_pk=hk.verfers[0].raw.hex(),
            le_pk=hby.kevers[ecr.issuer].verfers[0].raw.hex(),
            agent_near_pk="ed25519:" + b58(ak.verfers[0].raw),
            w0=a["paywordRoot"], n=a["paywordLength"], unit=a["unitYocto"], daily=a["dailyLinks"],
            credit=dict(limit=a["creditLimitYocto"], bond_bps=a["bondBps"], premium_bps=a.get("premiumBps", 0), fee_payer=a.get("feePayer", "Buyer"), seller_cap_bps=a.get("sellerCapBps", 0), min_tenor=str(a["minTenorSecs"]), max_tenor=str(a["maxTenorSecs"]),
                        terms_hash=a["termsHash"], arbiter=a["arbiter"], asset=a.get("creditAsset")) if a.get("creditLimitYocto") else None,
            max_links=a["maxLinksPerPayment"], max_strikes=a["maxStrikes"], le_aid=ecr.issuer,
            scope=a["counterparties"], funder=a["settlementRail"], asset=a.get("settlementAsset"),
            valid_until_ns=int(valid_until.timestamp()) * 1_000_000_000,
        )


def read_cover(r, verifier, contract):
    """Cover terms offered with this mandate, or None. Refuses anything the legal entity did not sign, and anything the contract would refuse.
    The verifier is the guarantor, so its attestation is its acceptance. The contract also checks the arbiter is not its owner; this script does not know the owner."""
    path = os.path.join(BUNDLE, "cover.json")
    if not os.path.exists(path):
        return None
    doc = read_json(path)
    try:
        c = {k: doc[k] for k in COVER_FIELDS}
        limit, n, unit = int(c["limit"]), int(r["n"]), int(r["unit"])
        window = int(c["claim_window"])
        canonical = str(limit) == c["limit"] and str(window) == c["claim_window"]
    except (KeyError, TypeError, ValueError) as e:
        raise ChainError(f"cover terms malformed: {e}")
    if not canonical or not isinstance(c["deductible_bps"], int) or not isinstance(c["premium_bps"], int):
        raise ChainError("cover terms malformed: not in canonical form")
    try:
        pysodium.crypto_sign_verify_detached(bytes.fromhex(doc.get("le_sig", "")), cover_message(contract, r["amc_said"], c), bytes.fromhex(r["le_pk"]))
    except Exception:
        raise ChainError("the legal entity did not sign these cover terms")
    if hashlib.sha256(doc.get("terms_text", "").encode()).hexdigest() != c["terms_hash"]:
        raise ChainError("cover terms_hash is not the hash of the terms presented")
    if not (10 * r["max_links"] * unit <= limit):
        raise ChainError("cover limit is under ten maximum payments")
    if limit > n * unit:
        raise ChainError("cover limit is more than the links can ever pay")
    if not 1000 <= c["deductible_bps"] <= 9000:
        raise ChainError("cover deductible is outside 10% to 90%")
    if not 0 <= c["premium_bps"] <= 2000:
        raise ChainError("cover fee is above 20% per period")
    if not 0 < window <= 10 * 365 * 86400:
        raise ChainError("cover claim window is outside what the contract accepts")
    if c["arbiter"] in (verifier, r["funder"]):
        raise ChainError("cover arbiter is the guarantor or the company")
    if set(r["scope"]) & {verifier, r["funder"], c["arbiter"]}:
        raise ChainError("mandate scope lets the agent pay the company, the guarantor or the arbiter")
    return c


def credit_line(c):
    if not c:
        return "none"
    return f"{c['limit']},{c['bond_bps']},{c['premium_bps']},{c['min_tenor']},{c['max_tenor']},{c['terms_hash']},{c['terms_sig']},{c['entity_tag']},{c['arbiter']},{c['fee_payer']},{c['seller_cap_bps']},{c.get('asset') or 'near'}"


def attestation_message(r, lei_commit, ecr_commit, verifier, contract, attested_at, credit=None, cover=None):
    """Must be identical character by character to the contract's attestation_message."""
    return (
        "writ:attest:v7\n"
        f"contract={contract}\namc={r['amc_said']}\nissuer_aid={r['issuer_aid']}\nissuer_pk={r['issuer_pk']}\nagent_pk={r['agent_near_pk']}\nw0={r['w0']}\n"
        f"n={r['n']}\nunit={r['unit']}\nscope={','.join(r['scope'])}\nvalid_until={r['valid_until_ns']}\n"
        f"daily_links={r['daily']}\nmax_links={r['max_links']}\nmax_strikes={r['max_strikes']}\nlei_commit={lei_commit}\necr_commit={ecr_commit}\n"
        f"funder={r['funder']}\nverifier={verifier}\nattested_at={attested_at}\n"
        f"asset={r['asset'] or 'near'}\ncredit={credit_line(credit)}\ncover={cover_line(cover)}"
    )


def cmd_keygen(a):
    if os.path.exists(VKEY) and not a.force:
        print(read_json(VKEY)["pk_hex"]); return
    pk, sk = pysodium.crypto_sign_keypair()
    write_json(VKEY, dict(pk_hex=pk.hex(), sk_hex=sk.hex()))
    print(pk.hex())


def cmd_pin(a):
    write_json(POLICY, dict(root_aid=a.root))
    print("pinned trust root", a.root)


def cmd_check(a):
    try:
        r = verify_chain()
    except ChainError as e:
        print(json.dumps(dict(ok=False, error=str(e)), indent=1)); sys.exit(2)
    for c in r["checks"]:
        print(("✓ " if c["ok"] else "✗ ") + c["check"] + (f"  [{c['detail']}]" if c["detail"] else ""))


def cmd_attest(a):
    try:
        r = verify_chain()
        cover = read_cover(r, a.verifier, a.contract)
    except ChainError as e:
        print(json.dumps(dict(ok=False, error=str(e))), file=sys.stderr); sys.exit(2)
    for c in r["checks"]:
        print("✓ " + c["check"], file=sys.stderr)
    if cover:
        print("✓ cover terms signed by the legal entity and within the contract's rules", file=sys.stderr)
    key = read_json(VKEY)
    salt = secrets.token_hex(16)
    lei_commit = hashlib.sha256(f"{r['lei']}|{salt}".encode()).hexdigest()
    # Commitment used when HR revokes the ECR: the LE public key and ECR SAID are normally not on chain; the salt for opening goes to the legal entity (not exclusive to the verifier)
    ecr_salt = secrets.token_hex(16)
    ecr_commit = hashlib.sha256(f"{r['le_aid']}|{r['le_pk']}|{r['ecr_said']}|{ecr_salt}".encode()).hexdigest()
    attested_at = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) * 1_000_000_000
    credit = None
    if r["credit"]:
        if r["credit"].get("asset") != r["asset"]:
            sys.exit("REFUSED: the credit asset differs from the cell's settlement asset")
        # fixed pseudonym: the same company accumulates records across cells; only the guarantor can compute it, others cannot match it to an LEI
        tag = hmac.new(bytes.fromhex(read_json(VKEY)["sk_hex"]), r["lei"].encode(), hashlib.sha256).hexdigest()[:24]
        terms = read_json(os.path.join(BUNDLE, "terms.json"))
        signed = f"writ:terms:v1\ncontract={a.contract}\namc={r['amc_said']}\nterms={r['credit']['terms_hash']}\nlei={r['lei']}".encode()
        try:
            pysodium.crypto_sign_verify_detached(bytes.fromhex(terms["terms_sig"]), signed, bytes.fromhex(r["le_pk"]))
        except Exception:
            sys.exit("REFUSED: the legal entity did not sign these credit terms")
        credit = dict(r["credit"], terms_sig=terms["terms_sig"], entity_tag=tag)
        if not credit.get("asset"):
            credit.pop("asset", None)
    msg = attestation_message(r, lei_commit, ecr_commit, a.verifier, a.contract, attested_at, credit, cover).encode()
    sig = pysodium.crypto_sign_detached(msg, bytes.fromhex(key["sk_hex"]))
    # the LEI and salt stay only at the verifier (used only at unsealing)
    recs = read_json(RECORDS) if os.path.exists(RECORDS) else {}
    recs[r["amc_said"]] = dict(lei=r["lei"], salt=salt, lei_commit=lei_commit)
    write_json(RECORDS, recs)
    args = dict(amc_said=r["amc_said"], issuer_aid=r["issuer_aid"], issuer_pk=r["issuer_pk"], max_links=r["max_links"],
                max_strikes=r["max_strikes"], attested_at=str(attested_at), agent_pk=r["agent_near_pk"], w0=r["w0"],
                n=r["n"], unit=r["unit"], scope=r["scope"], valid_until=str(r["valid_until_ns"]),
                daily_links=r["daily"], lei_commit=lei_commit, ecr_commit=ecr_commit, verifier=a.verifier, signature=sig.hex())
    if r["asset"]:
        args["asset"] = r["asset"]
    if credit:
        args["credit"] = credit
    if cover:
        args["cover"] = cover
    opening = dict(le_aid=r["le_aid"], le_pk=r["le_pk"], ecr_said=r["ecr_said"], salt=ecr_salt)
    print(json.dumps(dict(funder=r["funder"], args=args, ecr_opening=opening), indent=1))


def cmd_reveal(a):
    """Used only at unsealing: print the (LEI, salt) the verifier committed to."""
    recs = read_json(RECORDS)
    r = recs.get(a.amc) or sys.exit("no record for this AMC")
    print(json.dumps(dict(lei=r["lei"], salt=r["salt"])))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest="cmd", required=True)
    k = sp.add_parser("keygen"); k.add_argument("--force", action="store_true")
    sp.add_parser("check")
    pn = sp.add_parser("pin"); pn.add_argument("--root", required=True)
    t = sp.add_parser("attest"); t.add_argument("--verifier", required=True); t.add_argument("--contract", required=True)
    rv = sp.add_parser("reveal"); rv.add_argument("--amc", required=True)
    a = p.parse_args()
    dict(keygen=cmd_keygen, pin=cmd_pin, check=cmd_check, attest=cmd_attest, reveal=cmd_reveal)[a.cmd](a)
