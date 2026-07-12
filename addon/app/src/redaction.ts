const patterns: RegExp[] = [
  /Bearer\s+[A-Za-z0-9._~+/-]+=*/gi,
  /\b(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  /([?&](?:token|key|password|secret|webhook_id)=)[^&#\s]+/gi,
  /\b(?:password|access[_-]?token|api[_-]?key|secret)\b\s*[:=]\s*[^\s,;]+/gi,
  /\/api\/webhook\/[^/?#\s]+/gi,
  /https?:\/\/[^/@\s]+:[^/@\s]+@/gi,
];
export function redact(value: unknown): unknown {
  if (typeof value === "string")
    return patterns
      .reduce(
        (text, pattern, index) =>
          text.replace(pattern, index < 3 ? "$1[REDACTED]" : "[REDACTED]"),
        value,
      )
      .slice(0, 16_384);
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        /token|password|secret|authorization|webhook/i.test(key) ? key : key,
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
