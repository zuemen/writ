"""
Writ 的 KERI 共用工具：schema、路徑、base58、CESR 串流拆解。

兩個角色各自一個 keystore，彼此不共享資料庫：
  - 發行端（issuer.py）：模擬「法人 LE → 職員 human（ECR）→ agent（AMC）」，keystore 在 keri/.keystore/
  - 驗證端（verify.py）：全新的暫存 Habery，只吃發行端匯出的 CESR 串流，從頭驗整條鏈
"""
import json, os
from keri.core import scheming, coring

HERE = os.path.dirname(os.path.abspath(__file__))
KEYSTORE = os.path.join(HERE, ".keystore")          # 發行端的私密資料（.gitignore）
BUNDLE = os.path.join(HERE, "bundle")                # 持有人出示的公開 CESR
REGISTRAR = os.path.join(HERE, "registrar")          # 發行方公布的 KEL／TEL（驗證端自己去查，不信任持有人給的狀態）
PRIVATE = os.path.join(KEYSTORE, "private.json")     # demo 用：agent 私鑰、PayWord 種子（.gitignore）


def b58(b: bytes) -> str:
    """NEAR 公鑰／私鑰字串用的 base58（Bitcoin 字母表，無 checksum）。"""
    A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = A[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + out


def _schema(title: str, attrs: dict, required: list, edges: dict | None, rules: bool = False):
    """建一份 ACDC JSON Schema，$id 由 keripy 以 Blake3-256 自我定址（SAID）。"""
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


# vLEI 的信任鏈用官方 schema（keri/schemas/，WebOfTrust/vLEI 的原檔）：GLEIF 根 → QVI → 法人 → ECR。
# 發行者是 mock，schema 是真的。ECR 走法人直接發給員工的 le edge（官方 schema 的兩條路之一）。
def _official(name: str, said: str):
    with open(os.path.join(HERE, "schemas", name + ".json"), "rb") as f:
        schemer = scheming.Schemer(raw=f.read())
    assert schemer.said == said, f"{name}: not the official schema ({schemer.said})"
    return schemer


QVI = _official("qualified-vLEI-issuer-vLEI-credential", "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao")
LEV = _official("legal-entity-vLEI-credential", "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY")
ECR = _official("legal-entity-engagement-context-role-vLEI-credential", "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw")


def rules_for(schemer) -> dict:
    """官方 schema 把 rules 條文定成 const：直接取用，不自己寫。"""
    block = next(x for x in schemer.sed["properties"]["r"]["oneOf"] if x["type"] == "object")
    return {k: {"l": v["properties"]["l"]["const"]} for k, v in block["properties"].items() if k != "d"}


def block(**fields) -> dict:
    """ACDC 的 e／r 區塊本身也要自我定址（d 是區塊內容的 SAID）。"""
    return coring.Saider.saidify(sad=dict(d="", **fields))[1]


# AMC：GLEIF《Agentic AI in Payments》Annex A p.44 —— 行動類別、交易上限、允許的交易對手、有效時間窗。
# 討論稿 p.45 明寫 AMC 的正式 ACDC schema 尚未定義；這是本專案的提案版本。
# paywordRoot / paywordLength / unitYocto 把「額度」本身綁進憑證：鏈上 w0 必須等於憑證裡的值。
# settlementAsset（選填）：NEP-141 代幣合約帳號；省略 = NEAR。unitYocto 此時為該代幣最小單位。
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


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1)


def read_json(path):
    with open(path) as f:
        return json.load(f)
