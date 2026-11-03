"""
Writ's shared KERI utilities: schema, paths, base58, CESR stream splitting.

The two roles each have their own keystore and do not share a database:
  - Issuer side (issuer.py): simulates "legal entity LE -> staff member human (ECR) -> agent (AMC)", keystore in keri/.keystore/
  - Verifier side (verify.py): a fresh temporary Habery that takes only the CESR stream exported by the issuer and verifies the whole chain from scratch
"""
import json, os
from keri.core import scheming, coring

HERE = os.path.dirname(os.path.abspath(__file__))
KEYSTORE = os.path.join(HERE, ".keystore")          # issuer's private data (.gitignore)
BUNDLE = os.path.join(HERE, "bundle")                # public CESR presented by the holder
REGISTRAR = os.path.join(HERE, "registrar")          # KEL/TEL published by the issuer (the verifier looks it up itself and does not trust state given by the holder)
PRIVATE = os.path.join(KEYSTORE, "private.json")     # for the demo: agent private key, PayWord seed (.gitignore)


def b58(b: bytes) -> str:
    """base58 for NEAR public/private key strings (Bitcoin alphabet, no checksum)."""
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = A[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def _schema(title: str, attrs: dict, required: list, edges: dict | None, rules: bool = False):
    """Build an ACDC JSON Schema; $id is self-addressed by keripy with Blake3-256 (SAID)."""
    a_props = {"d": {"type": "string"}, "u": {"type": "string"}, "i": {"type": "string"}, "dt": {"type": "string", "format": "date-time"}}
    a_props.update(attrs)
    props = {
        "v": {"type": "string"}, "d": {"type": "string"}, "u": {"type": "string"},
        "i": {"type": "string"}, "ri": {"type": "string"}, "s": {"type": "string"},
        "a": {"oneOf": [{"type": "string"},
                        {"type": "object", "properties": a_props, "required": ["d", "i", "dt"] + required,
                         "additionalProperties": False}]},
    }
    req = ["v", "d", "i", "ri", "s", "a"]
    if edges is not None:
        props["e"] = {"oneOf": [{"type": "string"}, {"type": "object", "properties": edges}]}
        req.append("e")
    if rules:
        props["r"] = {"oneOf": [{"type": "string"}, {"type": "object"}]}
        req.append("r")
    sed = {"$id": "", "$schema": "http://json-schema.org/draft-07/schema#", "title": title,
           "type": "object", "credentialType": title.replace(" ", ""), "properties": props,
           "additionalProperties": False, "required": req}
    schemer = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
    return schemer


# The vLEI trust chain uses the official schemas (keri/schemas/, original files from WebOfTrust/vLEI): GLEIF root -> QVI -> legal entity -> ECR.
# The issuers are mocks, the schemas are real. The ECR uses the le edge issued by the legal entity directly to the employee (one of the two paths in the official schema).
def _official(name: str, said: str):
    with open(os.path.join(HERE, "schemas", name + ".json"), "rb") as f:
        schemer = scheming.Schemer(raw=f.read())
    assert schemer.said == said, f"{name}: not the official schema ({schemer.said})"
    return schemer


QVI = _official("qualified-vLEI-issuer-vLEI-credential", "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")
LEV = _official("legal-entity-vLEI-credential", "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY")
ECR = _official("legal-entity-engagement-context-role-vLEI-credential", "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw")


def rules_for(schemer) -> dict:
    """The official schema fixes the rules text as a const: use it directly, do not write our own."""
    block = next(x for x in schemer.sed["properties"]["r"]["oneOf"] if x["type"] == "object")
    return {k: {"l": v["properties"]["l"]["const"]} for k, v in block["properties"].items() if k != "d"}


def block(**fields) -> dict:
    """The e/r blocks of an ACDC must be self-addressed too (d is the SAID of the block content)."""
    return coring.Saider.saidify(sad=dict(d="", **fields))[1]


# AMC: GLEIF "Agentic AI in Payments" Annex A p.44: action class, transaction cap, allowed counterparties, validity window.
# The discussion paper p.45 states that the formal ACDC schema for the AMC is not yet defined; this is this project's proposed version.
# paywordRoot / paywordLength / unitYocto bind the "limit" itself into the credential: w0 on chain must equal the value in the credential.
# settlementAsset (optional): NEP-141 token contract account; omitted = NEAR. unitYocto is then the token's smallest unit.
AMC = _schema(
    "Agent Mandate Credential",
    {
        "actionClass": {"type": "string"},
        "counterparties": {"type": "array", "items": {"type": "string"}, "maxItems": 16},
        "validUntil": {"type": "string", "format": "date-time"},
        "unitYocto": {"type": "string"},
        "paywordRoot": {"type": "string"},
        "paywordLength": {"type": "integer"},
        "dailyLinks": {"type": "integer"},
        "maxLinksPerPayment": {"type": "integer"},
        "maxStrikes": {"type": "integer"},
        "settlementRail": {"type": "string"},
        "settlementAsset": {"type": "string"},
        "creditLimitYocto": {"type": "string"},
        "bondBps": {"type": "integer"},
        "premiumBps": {"type": "integer"},
        "feePayer": {"type": "string"},
        "sellerCapBps": {"type": "integer"},
        "creditAsset": {"type": "string"},
        "minTenorSecs": {"type": "integer"},
        "maxTenorSecs": {"type": "integer"},
        "termsHash": {"type": "string"},
        "arbiter": {"type": "string"},
    },
    ["actionClass", "counterparties", "validUntil", "unitYocto", "paywordRoot", "paywordLength", "dailyLinks",
     "maxLinksPerPayment", "maxStrikes", "settlementRail"],
    {"d": {"type": "string"}, "ecr": {"type": "object"}},
)


# Cover terms are between the guarantor and the company, so they stay out of the AMC schema (its SAID does not change).
# The legal entity signs them for this contract and AMC; the verifier checks that signature, then signs them into the attestation.
COVER_FIELDS = ("limit", "deductible_bps", "premium_bps", "claim_window", "arbiter", "terms_hash")


def cover_line(c) -> str:
    """The value of the attestation's cover= line. Must match the contract's attestation_message."""
    return ",".join(str(c[k]) for k in COVER_FIELDS) if c else "none"


def cover_message(contract: str, amc_said: str, c) -> bytes:
    """What the legal entity signs."""
    return f"writ:cover:v1\ncontract={contract}\namc={amc_said}\ncover={cover_line(c)}".encode()


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1)


def read_json(path):
    with open(path) as f:
        return json.load(f)
