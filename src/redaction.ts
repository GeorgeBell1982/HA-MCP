const patterns: RegExp[] = [
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\b(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  /([?&](?:token|key|password|secret|webhook_id)=)[^&#\s]+/gi,
  /\b(?:password|access[_-]?token|api[_-]?key|secret)\b\s*[:=]\s*[^\s,;]+/gi,
  /\/api\/webhook\/[^/?#\s]+/gi,
  /https?:\/\/[^/@\s]+:[^/@\s]+@/gi,
];

export interface RedactTextOptions {
  readonly maximumBytes?: number;
  readonly truncate?: boolean;
  readonly check?: () => void;
}

export function redactText(
  value: string,
  options: RedactTextOptions = {},
): string {
  const maximumBytes = options.maximumBytes ?? 16_384;
  const truncate = options.truncate ?? true;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1)
    throw new TypeError("maximumBytes must be a positive safe integer");
  let output = value;
  for (let index = 0; index < patterns.length; index += 1) {
    options.check?.();
    output = output.replace(
      patterns[index]!,
      index < 3 ? "$1[REDACTED]" : "[REDACTED]",
    );
  }
  options.check?.();
  if (truncate) return output.slice(0, maximumBytes);
  if (Buffer.byteLength(output, "utf8") > maximumBytes)
    throw new RangeError("Redacted text exceeds its byte boundary");
  return output;
}

export function redact(value: unknown): unknown {
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        /token|password|secret|authorization|webhook/i.test(key)
          ? "[REDACTED]"
          : redact(item),
      ]),
    );
  return value;
}
export function safeMessage(error: unknown): string {
  return String(
    redact(error instanceof Error ? error.message : "Unexpected failure"),
  );
}
