/** 呼叫 keri/ 底下的 keripy 腳本（發行端 issuer.py、驗證端 verify.py）。 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, readJson } from "./near.js";

const KERI = join(ROOT, "keri");
const PY = process.env.WRIT_PY ?? (existsSync(join(KERI, ".venv/bin/python")) ? join(KERI, ".venv/bin/python") : "python3");

export function py(script: "issuer.py" | "verify.py", ...args: string[]): string {
  return execFileSync(PY, [script, ...args], { cwd: KERI, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/** 同時拿 stdout 與 stderr（verify.py attest 把檢查清單寫在 stderr、args 寫在 stdout） */
export function pyBoth(script: string, ...args: string[]): { out: string; err: string; code: number } {
  const r = spawnSync(PY, [script, ...args], { cwd: KERI, encoding: "utf8" });
  return { out: r.stdout ?? "", err: r.stderr ?? "", code: r.status ?? 1 };
}

export const keriState = () => readJson(join(KERI, ".keystore", "state.json"));
export const keriPrivate = () => readJson(join(KERI, ".keystore", "private.json"));
export const releaseLink = (k: number) => py("issuer.py", "release", String(k)).trim();
