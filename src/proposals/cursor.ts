import {
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  repositoryCursorSchema,
  type Phase2OperationContext,
} from "../phase2Contracts.js";
import { assertOperationActive } from "../security/repositoryBoundary.js";
import { canonicalJson, type StoredProposal } from "./storage.js";

const PAYLOAD_BYTES = 70;
const CURSOR_BYTES = 102;

export class ProposalCursorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProposalCursorError";
  }
}

export class ProposalCursorCodec {
  private readonly key: Buffer;
  private readonly keyTag: Buffer;
  private closed = false;

  constructor(key: Uint8Array, sessionNonce: Uint8Array = randomBytes(32)) {
    if (key.byteLength < 32)
      throw new TypeError("Proposal cursor key must contain at least 32 bytes");
    if (sessionNonce.byteLength !== 32)
      throw new TypeError(
        "Proposal cursor session nonce must contain exactly 32 bytes",
      );
    const material = Buffer.from(key);
    const nonce = Buffer.from(sessionNonce);
    try {
      this.key = createHmac("sha256", material)
        .update("HA_PROPOSAL_CURSOR_SESSION_V1\0", "ascii")
        .update(nonce)
        .digest();
      this.keyTag = createHash("sha256")
        .update(this.key)
        .digest()
        .subarray(0, 28);
    } finally {
      material.fill(0);
      nonce.fill(0);
    }
  }

  encode(
    operation: number,
    generation: number,
    offset: number,
    snapshot: Buffer,
  ): string {
    if (this.closed)
      throw new ProposalCursorError("Proposal cursor session is closed");
    if (
      operation < 1 ||
      operation > 255 ||
      !Number.isSafeInteger(generation) ||
      generation < 0 ||
      generation > 0xffffffff ||
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      offset > 0xffffffff ||
      snapshot.byteLength !== 32
    )
      throw new ProposalCursorError("Proposal cursor fields are invalid");
    const payload = Buffer.alloc(PAYLOAD_BYTES);
    payload[0] = 1;
    payload[1] = operation;
    payload.writeUInt32BE(generation, 2);
    payload.writeUInt32BE(offset, 6);
    snapshot.copy(payload, 10);
    this.keyTag.copy(payload, 42);
    const mac = createHmac("sha256", this.key).update(payload).digest();
    return Buffer.concat([payload, mac]).toString("base64url");
  }

  decode(
    value: string,
    operation: number,
  ): Readonly<{ generation: number; offset: number; snapshot: Buffer }> {
    if (this.closed)
      throw new ProposalCursorError("Proposal cursor session is closed");
    if (!repositoryCursorSchema.safeParse(value).success)
      throw new ProposalCursorError("Proposal cursor is malformed");
    const bytes = Buffer.from(value, "base64url");
    if (bytes.byteLength !== CURSOR_BYTES)
      throw new ProposalCursorError("Proposal cursor is malformed");
    const payload = bytes.subarray(0, PAYLOAD_BYTES);
    const mac = bytes.subarray(PAYLOAD_BYTES);
    const expected = createHmac("sha256", this.key).update(payload).digest();
    if (
      !timingSafeEqual(mac, expected) ||
      payload[0] !== 1 ||
      payload[1] !== operation ||
      !timingSafeEqual(payload.subarray(42, 70), this.keyTag)
    )
      throw new ProposalCursorError(
        "Proposal cursor is invalid for this operation or key",
      );
    return Object.freeze({
      generation: payload.readUInt32BE(2),
      offset: payload.readUInt32BE(6),
      snapshot: Buffer.from(payload.subarray(10, 42)),
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.key.fill(0);
    this.keyTag.fill(0);
  }
}

export function proposalSnapshot(
  values: readonly StoredProposal[],
  context: Phase2OperationContext,
): Buffer {
  const hash = createHash("sha256");
  const length = Buffer.allocUnsafe(4);
  try {
    for (const value of values) {
      assertOperationActive(context);
      const bytes = Buffer.from(canonicalJson(value.public), "utf8");
      try {
        length.writeUInt32BE(bytes.byteLength);
        hash.update(length);
        for (let offset = 0; offset < bytes.byteLength; offset += 256) {
          assertOperationActive(context);
          hash.update(
            bytes.subarray(offset, Math.min(offset + 256, bytes.byteLength)),
          );
        }
      } finally {
        bytes.fill(0);
      }
    }
    return hash.digest();
  } finally {
    length.fill(0);
  }
}
