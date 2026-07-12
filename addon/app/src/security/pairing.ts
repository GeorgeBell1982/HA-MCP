import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
const scrypt = promisify(scryptCallback);
export interface CredentialRecord {
  clientId: string;
  salt: string;
  hash: string;
  createdAt: string;
  revokedAt?: string;
}

export class PairingStore {
  private records = new Map<string, CredentialRecord>();
  private revokedListeners = new Set<(clientId: string) => void>();
  private sessionResetListeners = new Set<() => void>();
  constructor(private readonly maxClients = 16) {}
  async pair(): Promise<{ bearer: string; record: CredentialRecord }> {
    if (
      [...this.records.values()].filter((x) => !x.revokedAt).length >=
      this.maxClients
    )
      throw new Error("Maximum paired clients reached");
    if (this.records.size >= this.maxClients * 4) {
      for (const record of [...this.records.values()]
        .filter((x) => x.revokedAt)
        .sort((a, b) => (a.revokedAt ?? "").localeCompare(b.revokedAt ?? ""))) {
        this.records.delete(record.clientId);
        if (this.records.size < this.maxClients * 4) break;
      }
    }
    const value = await createCredential();
    this.records.set(value.record.clientId, value.record);
    return value;
  }
  async authenticate(bearer: string): Promise<string | undefined> {
    const id = bearer.split(".")[0];
    const record = id ? this.records.get(id) : undefined;
    return record &&
      !record.revokedAt &&
      (await verifyCredential(bearer, record))
      ? id
      : undefined;
  }
  revoke(clientId: string): boolean {
    const record = this.records.get(clientId);
    if (!record || record.revokedAt) return false;
    record.revokedAt = new Date().toISOString();
    for (const listener of this.revokedListeners) listener(clientId);
    return true;
  }
  async rotate(clientId: string) {
    if (!this.revoke(clientId)) throw new Error("Unknown client");
    return this.pair();
  }
  list() {
    return [...this.records.values()].map((record) => ({
      clientId: record.clientId,
      createdAt: record.createdAt,
      ...(record.revokedAt ? { revokedAt: record.revokedAt } : {}),
    }));
  }
  exportRecords() {
    return [...this.records.values()];
  }
  importRecords(records: CredentialRecord[]) {
    if (records.length > this.maxClients * 4)
      throw new Error("Pairing store exceeds retention limit");
    this.records = new Map(records.map((x) => [x.clientId, x]));
  }
  onRevoked(listener: (clientId: string) => void) {
    this.revokedListeners.add(listener);
    return () => this.revokedListeners.delete(listener);
  }
  resetSessions() {
    for (const listener of this.sessionResetListeners) listener();
  }
  onSessionsReset(listener: () => void) {
    this.sessionResetListeners.add(listener);
    return () => this.sessionResetListeners.delete(listener);
  }
}
export async function createCredential(): Promise<{
  bearer: string;
  record: CredentialRecord;
}> {
  const clientId = randomBytes(16).toString("base64url");
  const secret = randomBytes(32).toString("base64url");
  const salt = randomBytes(16);
  const hash = (await scrypt(secret, salt, 32)) as Buffer;
  return {
    bearer: `${clientId}.${secret}`,
    record: {
      clientId,
      salt: salt.toString("base64url"),
      hash: hash.toString("base64url"),
      createdAt: new Date().toISOString(),
    },
  };
}
export async function verifyCredential(
  bearer: string,
  record: CredentialRecord,
): Promise<boolean> {
  const [id, secret, extra] = bearer.split(".");
  if (!id || !secret || extra || id !== record.clientId) return false;
  const actual = (await scrypt(
    secret,
    Buffer.from(record.salt, "base64url"),
    32,
  )) as Buffer;
  return timingSafeEqual(actual, Buffer.from(record.hash, "base64url"));
}
