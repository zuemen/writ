#!/usr/bin/env python3
"""Compares a local wasm with the code hash an account has on testnet. Usage: code_hash.py <wasm> <account>"""
import hashlib, json, sys, urllib.request

wasm, account = sys.argv[1], sys.argv[2]
body = {"jsonrpc": "2.0", "id": "1", "method": "query", "params": {"request_type": "view_account", "finality": "final", "account_id": account}}
req = urllib.request.Request("https://test.rpc.fastnear.com", json.dumps(body).encode(), {"content-type": "application/json"})
chain = json.load(urllib.request.urlopen(req))["result"]["code_hash"]
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
digest = hashlib.sha256(open(wasm, "rb").read()).hexdigest()
n, local = int(digest, 16), ""
while n:
    n, r = divmod(n, 58)
    local = alphabet[r] + local
print("sha256", digest)
print("local ", local)
print("chain ", chain)
print("CODE_HASH|" + ("PASS" if local == chain else "DIFFERENT"))
sys.exit(0 if local == chain else 1)
