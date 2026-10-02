import type { z } from "zod";

export interface ToolCallContext {
  readonly signal: AbortSignal;
  /** Originating transport only. Never populated from tool arguments. */
  readonly requestApproval?: (request: ToolApprovalRequest) => Promise<string>;
}

export interface ToolApprovalRequest {
  readonly message: string;
  readonly confirmation: string;
  readonly signal: AbortSignal;
  readonly deadlineAt: number;
}

export class ToolApprovalError extends Error {
  constructor(public readonly code: string) {
    super(`MCP approval failed: ${code}`);
    this.name = "ToolApprovalError";
  }
}

export interface ToolResult {
  readonly ok: boolean;
  readonly requestId: string;
}

export interface ToolDescriptor {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: z.ZodTypeAny;
  readonly outputSchema?: z.ZodTypeAny | undefined;
  readonly annotations?: Readonly<{
    readOnlyHint?: boolean;
    idempotentHint?: boolean;
    destructiveHint?: boolean;
    openWorldHint?: boolean;
  }>;
}

export interface ToolRegistry {
  names(): readonly string[];
  descriptors(): readonly ToolDescriptor[];
  descriptor(name: string): ToolDescriptor | undefined;
  call(
    name: string,
    rawInput: unknown,
    context?: ToolCallContext,
  ): Promise<ToolResult>;
}

export class CompositeToolRegistry implements ToolRegistry {
  private readonly byName = new Map<string, ToolRegistry>();
  private readonly orderedNames: readonly string[];

  constructor(registries: readonly ToolRegistry[]) {
    const names: string[] = [];
    for (const registry of registries) {
      for (const name of registry.names()) {
        if (this.byName.has(name)) throw new Error(`Duplicate tool: ${name}`);
        this.byName.set(name, registry);
        names.push(name);
      }
    }
    this.orderedNames = Object.freeze(names);
  }

  names(): readonly string[] {
    return this.orderedNames;
  }

  descriptors(): readonly ToolDescriptor[] {
    return Object.freeze(
      this.orderedNames.map((name) => this.descriptor(name)!),
    );
  }

  descriptor(name: string): ToolDescriptor | undefined {
    return this.byName.get(name)?.descriptor(name);
  }

  async call(
    name: string,
    rawInput: unknown,
    context?: ToolCallContext,
  ): Promise<ToolResult> {
    const registry = this.byName.get(name);
    if (!registry)
      return Object.freeze({
        ok: false,
        requestId: "00000000-0000-4000-8000-000000000000",
        error: { code: "invalid_input", message: "Unknown tool" },
        warnings: [],
        evidence: [],
      });
    return registry.call(name, rawInput, context);
  }
}
