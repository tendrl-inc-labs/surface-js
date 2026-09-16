import type { ActionContext, SurfaceClient } from "./client.js";
import type { DeferredScanResponse, ScanResult } from "./models.js";

/**
 * Tool-call screening for AI agents.
 *
 * Surface screens the tool call your agent proposes *before* you execute it and
 * returns Allow / Review / Block. It is not automatic: the host screens the
 * proposed call, the model never scans itself. `ToolGuard` packages that
 * propose -> scan -> branch pattern so you don't hand-wire the scan, the verdict
 * check, and the branch on every call.
 *
 * Framework wiring (LangChain tool wrapping, an OpenAI Agents tool guardrail) is
 * the same shape either way: call `screen()` / `wrap()` from the host.
 */

/** One flagged action from the screener. */
export interface ToolFinding {
  toolName?: string;
  category?: string;
  severity?: string;
  reason?: string;
  evidence?: string;
}

/** The verdict on one proposed tool call. */
export class Decision {
  constructor(
    readonly action: string, // "Allow" | "Review" | "Block"
    readonly reason: string,
    readonly findings: ToolFinding[],
    readonly result?: ScanResult,
  ) {}

  get allowed(): boolean {
    return this.action === "Allow";
  }
  get blocked(): boolean {
    return this.action === "Block";
  }
  get needsReview(): boolean {
    return this.action === "Review";
  }
}

/** Thrown by a wrapped tool when Surface's verdict stops it from running. */
export class ToolBlocked extends Error {
  constructor(readonly decision: Decision) {
    super(`Surface stopped a tool call (${decision.action}): ${decision.reason}`);
    this.name = "ToolBlocked";
  }
}

/** A fixed context, or a function that builds one per tool call from trusted state. */
export type ContextSource =
  | ActionContext
  | ((name: string, args: unknown) => ActionContext | undefined);

export interface ToolGuardOptions {
  /** Trusted context, or a per-call builder. Never derive it from the tool args. */
  context?: ContextSource;
  /** Treat Review as a hard stop (default false). */
  blockOnReview?: boolean;
}

/** Serialize a proposed tool call into the shape the scanner reads. */
export function toolCallJson(name: string, args: unknown): string {
  return JSON.stringify({ tool: name, args });
}

function decisionFrom(res: ScanResult | DeferredScanResponse): Decision {
  if (!("safetyScore" in res) || !res.safetyScore) {
    // A deferred scan carries no verdict; it cannot clear a live action.
    return new Decision("Review", "scan deferred; no verdict yet", []);
  }
  const ss = res.safetyScore;
  const findings: ToolFinding[] =
    ((res as { actionScreen?: { findings?: ToolFinding[] } }).actionScreen?.findings) ?? [];
  const reason = ss.primaryThreat || findings[0]?.reason || "";
  return new Decision(ss.recommendedAction, reason, findings, res);
}

/**
 * Screens proposed tool calls with Surface and decides allow / review / block.
 * Build once with a client, then `screen()` and branch, or `wrap()` a tool.
 */
export class ToolGuard {
  constructor(
    private readonly client: SurfaceClient,
    private readonly options: ToolGuardOptions = {},
  ) {}

  private ctx(name: string, args: unknown): ActionContext | undefined {
    const c = this.options.context;
    return typeof c === "function" ? c(name, args) : c;
  }

  private stop(d: Decision): boolean {
    return d.blocked || (!!this.options.blockOnReview && d.needsReview);
  }

  /** Scan a proposed tool call and return the {@link Decision}. */
  async screen(name: string, args: unknown): Promise<Decision> {
    const res = await this.client.scanPayload(toolCallJson(name, args), `${name}.toolcall.json`, {
      context: this.ctx(name, args),
    });
    return decisionFrom(res);
  }

  /**
   * Wrap a tool function so it screens its own call before executing. On a
   * stopping verdict it throws {@link ToolBlocked} instead of running the tool.
   */
  wrap<A extends unknown[], R>(
    fn: (...args: A) => R | Promise<R>,
    name?: string,
  ): (...args: A) => Promise<R> {
    const toolName = name ?? fn.name ?? "tool";
    return async (...args: A): Promise<R> => {
      const d = await this.screen(toolName, args.length === 1 ? args[0] : args);
      if (this.stop(d)) throw new ToolBlocked(d);
      return await fn(...args);
    };
  }
}
