export type ErrorCode =
  | "invalid_input"
  | "auth_failed"
  | "upstream_error"
  | "timeout"
  | "capability_unavailable"
  | "audit_unavailable"
  | "not_found";
export interface Envelope<T> {
  ok: boolean;
  requestId: string;
  data?: T;
  error?: { code: ErrorCode; message: string };
  warnings: string[];
  evidence: string[];
  pagination?: { nextCursor?: string; truncated: boolean };
}
export class SafeError extends Error {
  constructor(
    public readonly code: ErrorCode,
    message: string,
  ) {
    super(message);
  }
}
export const success = <T>(
  requestId: string,
  data: T,
  evidence: string[] = [],
): Envelope<T> => ({ ok: true, requestId, data, warnings: [], evidence });
export const failure = (
  requestId: string,
  error: SafeError,
): Envelope<never> => ({
  ok: false,
  requestId,
  error: { code: error.code, message: error.message },
  warnings: [],
  evidence: [],
});
