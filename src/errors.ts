/**
 * Errors whose message is safe to show to MCP clients and CLI users.
 * Messages must never contain tokens, OAuth codes, or upstream response bodies.
 */
export class PerchError extends Error {
  constructor(
    message: string,
    readonly code: string = 'perch_error',
  ) {
    super(message);
    this.name = 'PerchError';
  }
}

/** Returns a message that is safe to surface; unknown errors are reduced to a generic text. */
export function safeMessage(err: unknown): string {
  if (err instanceof PerchError) return err.message;
  return 'Internal error (details withheld)';
}
