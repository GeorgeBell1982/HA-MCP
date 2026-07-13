import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

export interface RemoteConnection<Client> {
  readonly client: Client;
  readonly transport: { readonly sessionId: string | undefined };
  connect(): Promise<void>;
  close(): Promise<void>;
}

export type RemoteConnectionFactory<Client> = () => RemoteConnection<Client>;

export async function closeStreamableHttpConnection(
  client: { close(): Promise<void> },
  transport: StreamableHTTPClientTransport,
  replacementTransport: (sessionId: string) => StreamableHTTPClientTransport,
): Promise<void> {
  try {
    if (transport.sessionId) {
      try {
        await transport.terminateSession();
      } catch (error) {
        // Client.connect closes its transport before surfacing an initialization
        // failure. Retry that DELETE on an equivalent, un-aborted transport.
        if (!(error instanceof Error) || error.name !== "AbortError")
          throw error;
        await replacementTransport(transport.sessionId).terminateSession();
      }
    }
  } finally {
    await client.close();
  }
}

export class RemoteSession<Client> {
  private tail: Promise<void> = Promise.resolve();

  private constructor(
    private current: RemoteConnection<Client>,
    private readonly factory: RemoteConnectionFactory<Client>,
  ) {}

  static async connect<Client>(
    factory: RemoteConnectionFactory<Client>,
  ): Promise<RemoteSession<Client>> {
    const connection = factory();
    try {
      await connection.connect();
    } catch (error) {
      await closeBestEffort(connection);
      throw error;
    }
    return new RemoteSession(connection, factory);
  }

  run<Result>(operation: (client: Client) => Promise<Result>): Promise<Result> {
    const result = this.tail.then(() => this.execute(operation));
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async execute<Result>(
    operation: (client: Client) => Promise<Result>,
  ): Promise<Result> {
    const attempted = this.current;
    try {
      return await operation(attempted.client);
    } catch (error) {
      if (!isExpiredSession(error, attempted.transport)) throw error;
    }

    const candidate = this.factory();
    try {
      await candidate.connect();
    } catch (error) {
      await closeBestEffort(candidate);
      throw error;
    }

    this.current = candidate;
    await closeBestEffort(attempted);
    return operation(candidate.client);
  }
}

function isExpiredSession(
  error: unknown,
  transport: { readonly sessionId: string | undefined },
): boolean {
  return (
    error instanceof StreamableHTTPError &&
    error.code === 404 &&
    typeof transport.sessionId === "string" &&
    transport.sessionId.length > 0
  );
}

async function closeBestEffort<Client>(
  connection: RemoteConnection<Client>,
): Promise<void> {
  try {
    await connection.close();
  } catch {
    // Closing a stale or only partially connected transport must not poison recovery.
  }
}
