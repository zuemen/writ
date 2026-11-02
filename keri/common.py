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


def _schema(title: str, attrs: dict, required: list, edges: dict | None):
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
    sed = {"$id": "", "$schema": "http://json-schema.org/draft-07/schema#", "title": title,
           "type": "object", "credentialType": title.replace(" ", ""), "properties": props,
           "additionalProperties": False, "required": req}
    schemer = scheming.Schemer(sed=sed, typ=scheming.JSONSchema(), code=coring.MtrDex.Blake3_256)
    return schemer


# ECR：法人給「自然人」的情境角色憑證（欄位對齊 vLEI ECR 的 a 區塊，但 schema SAID 是本專案自建的 mock）
ECR = _schema(
    "Mock Engagement Context Role vLEI Credential",
    {"LEI": {"type": "string"}, "personLegalName": {"type": "string"}, "engagementContextRole": {"type": "string"}},
    ["LEI", "personLegalName", "engagementContextRole"],
    None,
)

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
