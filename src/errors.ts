export type ErrorCode =
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'INVALID'
  | 'CONFLICT'
  | 'LEASE_INVALID'
  | 'HOLD'
  | 'CREDITS_EXHAUSTED'
  | 'THROTTLED'
  | 'PAYLOAD_TOO_LARGE';

const STATUS: Record<ErrorCode, number> = {
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  INVALID: 400,
  CONFLICT: 409,
  LEASE_INVALID: 409,
  HOLD: 423,
  CREDITS_EXHAUSTED: 402,
  THROTTLED: 429,
  PAYLOAD_TOO_LARGE: 413,
};

export class CommanderError extends Error {
  readonly status: number;
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'CommanderError';
    this.status = STATUS[code];
  }
}
