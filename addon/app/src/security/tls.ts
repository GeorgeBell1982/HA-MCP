import { X509Certificate, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { chmod, mkdir, readFile, rename } from "node:fs/promises";
import { createSecureContext } from "node:tls";
import { dirname } from "node:path";
import { promisify } from "node:util";
const execute = promisify(execFile);
export function certificateFingerprint(pem: string | Buffer) {
  const cert = new X509Certificate(pem);
  return createHash("sha256").update(cert.raw).digest("hex");
}
export async function generateOrRotateTlsIdentity(options: {
  certPath: string;
  keyPath: string;
  openssl?: string;
  days?: number;
  subjectAltName?: string;
}) {
  const cleanEnv = { ...process.env };
  delete cleanEnv.OPENSSL_CONF;
  delete cleanEnv.OPENSSL_MODULES;
  const commandOptions = { env: cleanEnv };
  await mkdir(dirname(options.certPath), { recursive: true, mode: 0o700 });
  const certTmp = `${options.certPath}.tmp`;
  const keyTmp = `${options.keyPath}.tmp`;
  await execute(
    options.openssl ?? "openssl",
    ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", keyTmp],
    commandOptions,
  );
  await execute(
    options.openssl ?? "openssl",
    [
      "req",
      "-new",
      "-x509",
      "-sha256",
      "-days",
      String(options.days ?? 365),
      "-key",
      keyTmp,
      "-out",
      certTmp,
      "-subj",
      "/CN=Home Assistant Engineering MCP",
      ...(options.subjectAltName
        ? ["-addext", `subjectAltName=${options.subjectAltName}`]
        : []),
    ],
    commandOptions,
  );
  await chmod(keyTmp, 0o600);
  await chmod(certTmp, 0o600);
  await rename(keyTmp, options.keyPath);
  await rename(certTmp, options.certPath);
  return certificateFingerprint(await readFile(options.certPath));
}
export async function ensureTlsIdentity(
  options: Parameters<typeof generateOrRotateTlsIdentity>[0],
) {
  try {
    const [cert, key] = await Promise.all([
      readFile(options.certPath),
      readFile(options.keyPath),
    ]);
    createSecureContext({ cert, key });
    const identity = new X509Certificate(cert);
    if (
      options.subjectAltName &&
      !subjectAltNamesMatch(identity.subjectAltName, options.subjectAltName)
    )
      throw new Error("SAN mismatch");
    if (Date.parse(identity.validTo) - Date.now() < 24 * 60 * 60_000)
      throw new Error("Certificate expires soon");
    return certificateFingerprint(cert);
  } catch {
    return generateOrRotateTlsIdentity(options);
  }
}
function subjectAltNamesMatch(actual: string | undefined, expected: string) {
  const normalized = expected
    .replaceAll("IP:", "IP Address:")
    .split(",")
    .map((x) => x.trim())
    .sort();
  return normalized.every((item) =>
    actual
      ?.split(",")
      .map((x) => x.trim())
      .includes(item),
  );
}
