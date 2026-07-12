import { mkdir, open } from "node:fs/promises";
import { dirname } from "node:path";
import { redact } from "./redaction.js";
export interface AuditRecord {
  timestamp: string;
  tool: string;
  requestId: string;
  result: "success" | "failure";
  risk: "read-only";
  error?: string;
}
export class JsonlAudit {
  private queue = Promise.resolve();
  constructor(private readonly path: string) {}
  async health(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    const h = await open(this.path, "a", 0o600);
    await h.close();
  }
  async append(record: AuditRecord): Promise<void> {
    const line = JSON.stringify(redact(record)) + "\n";
    const operation = this.queue.then(async () => {
      const h = await open(this.path, "a", 0o600);
      try {
        await h.writeFile(line, "utf8");
        await h.sync();
      } finally {
        await h.close();
      }
    });
    this.queue = operation.catch(() => undefined);
    await operation;
  }
}
