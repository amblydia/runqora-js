import {
  type BridgeMethod,
  buildRoute,
  SIGNATURE_HEADER,
  signRequest,
  TIMESTAMP_HEADER,
} from "../src/auth/protocol";

/**
 * Calls a bridge the way Runqora's servers do: a request signed with the
 * shared secret, sent straight to the handler, no network.
 */
export function createSignedClient(options: {
  baseUrl: string;
  handler: (request: Request) => Promise<Response>;
  secret: string;
}) {
  return async function call<T = Record<string, unknown>>(
    method: BridgeMethod,
    segments: string[],
    query: Record<string, string> = {}
  ): Promise<{ body: T; headers: Headers; status: number }> {
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await signRequest({
      method,
      query,
      secret: options.secret,
      segments,
      timestamp,
    });
    const search = new URLSearchParams(query).toString();
    // The bridge's own root has no trailing slash.
    const path = segments.length > 0 ? buildRoute(segments) : "";
    const response = await options.handler(
      new Request(`${options.baseUrl}${path}${search ? `?${search}` : ""}`, {
        headers: {
          [SIGNATURE_HEADER]: signature,
          [TIMESTAMP_HEADER]: String(timestamp),
        },
        method,
      })
    );
    return {
      body: (await response.json()) as T,
      headers: response.headers,
      status: response.status,
    };
  };
}
