export type RunqoraErrorCode =
  | "invalid_response"
  | "network_error"
  | "request_failed"
  | "timeout";

/**
 * The request did not get a usable answer: Runqora was unreachable or refused
 * it (for example an API key without the needed permission). For key
 * verification this says nothing about the key, so treat it as "not verified".
 */
export class RunqoraError extends Error {
  readonly code: RunqoraErrorCode;
  /** HTTP status, when Runqora answered. */
  readonly status: number | null;

  constructor(
    message: string,
    options: ErrorOptions & { code: RunqoraErrorCode; status?: number }
  ) {
    super(message, { cause: options.cause });
    this.name = "RunqoraError";
    this.code = options.code;
    this.status = options.status ?? null;
  }
}
