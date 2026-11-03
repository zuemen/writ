/** Calls the keripy scripts under keri/ (issuer side issuer.py, verifier side verify.py). */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { ROOT, readJson } from "./near.js";

const KERI = join(ROOT, "keri");
const PY = process.env.WRIT_PY ?? (existsSync(join(KERI, ".venv/bin/python")) ? join(KERI, ".venv/bin/python") : "python3");

export function py(script: "issuer.py" | "verify.py", ...args: string[]): string {
  return execFileSync(PY, [script, ...args], { cwd: KERI, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/** Capture both stdout and stderr (verify.py attest writes the checklist to stderr and args to stdout) */
export function pyBoth(script: string, ...args: string[]): { out: string; err: string; code: number } {
  const r = spawnSync(PY, [script, ...args], { cwd: KERI, encoding: "utf8" });
  return { out: r.stdout ?? "", err: r.stderr ?? "", code: r.status ?? 1 };
}

export const keriState = () => readJson(join(KERI, ".keystore", "state.json"));
export const keriPrivate = () => readJson(join(KERI, ".keystore", "private.json"));
export const releaseLink = (k: number) => py("issuer.py", "release", String(k)).trim();
