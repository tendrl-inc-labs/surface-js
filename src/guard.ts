import { checkStrictness, type ActionContext, type StrictnessLevel, type SurfaceClient } from "./client.js";
import { ValidationError } from "./errors.js";
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
 * Review means "a person should confirm this": a wrapped tool is held on Review
 * by default (it throws {@link ToolNeedsReview}); `onReview` changes that.
 * `strictness` ("relaxed" | "balanced" | "strict", default balanced) sets how
 * readily a judgment call becomes a verdict.
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
    /** The strictness level the call was screened at. */
    readonly strictness: StrictnessLevel = "balanced",
  ) {}

  /**
   * Calibrated probability (0-1) that the call is harmful, from the result's
   * `actionRisk` when the scanner returned one. Informational: it does not
   * change `action`, which always follows the scan's recommendedAction.
   */
  get riskProbability(): number | undefined {
    return this.result?.actionRisk?.probability;
  }
  /** Plain-language reasons behind {@link riskProbability} (empty when absent). */
  get riskReasons(): string[] {
    return this.result?.actionRisk?.reasons ?? [];
  }

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

/**
 * Thrown by a wrapped tool on a Review verdict: a person should confirm it.
 * Extends {@link ToolBlocked}, so code that already catches that stays safe.
 * Catch this one first to ask the user and retry.
 */
export class ToolNeedsReview extends ToolBlocked {
  constructor(decision: Decision) {
    super(decision);
    this.name = "ToolNeedsReview";
  }
}

/**
 * What a wrapped tool does on Review: "hold" (throw {@link ToolNeedsReview}),
 * "allow" (run it), or a function that gets the {@link Decision} and returns
 * true to run it (ask the user there).
 */
export type ReviewPolicy = "hold" | "allow" | ((decision: Decision) => boolean | Promise<boolean>);

/** A fixed context, or a function that builds one per tool call from trusted state. */
export type ContextSource =
  | ActionContext
  | ((name: string, args: unknown) => ActionContext | undefined);

export interface ToolGuardOptions {
  /** Trusted context, or a per-call builder. Never derive it from the tool args. */
  context?: ContextSource;
  /** Strictness for every call unless the context sets its own. Omitted, the scanner uses "balanced". */
  strictness?: StrictnessLevel;
  /** What a wrapped tool does on Review (default "hold"). */
  onReview?: ReviewPolicy;
  /** Older spelling of `onReview`: true is "hold", false is "allow". Overrides `onReview` when set. */
  blockOnReview?: boolean;
}

/** Options for {@link ToolGuard.screen}. */
export interface ScreenOptions {
  /** Fills the context's `user_request` when it has none, e.g. the run's prompt. */
  userRequest?: string;
}

/** Serialize a proposed tool call into the shape the scanner reads. */
export function toolCallJson(name: string, args: unknown): string {
  return JSON.stringify({ tool: name, args });
}

function decisionFrom(res: ScanResult | DeferredScanResponse, ctx?: ActionContext): Decision {
  const level = ctx?.strictness ?? "balanced";
  if (!("safetyScore" in res) || !res.safetyScore) {
    // A deferred scan carries no verdict; it cannot clear a live action.
    return new Decision("Review", "scan deferred; no verdict yet", [], undefined, level);
  }
  const ss = res.safetyScore;
  const findings: ToolFinding[] =
    ((res as { actionScreen?: { findings?: ToolFinding[] } }).actionScreen?.findings) ?? [];
  const reason = ss.primaryThreat || findings[0]?.reason || "";
  return new Decision(ss.recommendedAction, reason, findings, res, level);
}

/**
 * Screens proposed tool calls with Surface and decides allow / review / block.
 * Build once with a client, then `screen()` and branch, or `wrap()` a tool.
 */
export class ToolGuard {
  private readonly strictness: StrictnessLevel | undefined;
  private readonly onReview: ReviewPolicy;

  constructor(
    private readonly client: SurfaceClient,
    private readonly options: ToolGuardOptions = {},
  ) {
    this.strictness = checkStrictness(options.strictness);
    let onReview = options.onReview ?? "hold";
    if (options.blockOnReview !== undefined) onReview = options.blockOnReview ? "hold" : "allow";
    if (typeof onReview !== "function" && onReview !== "hold" && onReview !== "allow") {
      throw new ValidationError('onReview must be "hold", "allow", or a function');
    }
    this.onReview = onReview;
  }

  private ctx(name: string, args: unknown, userRequest?: string): ActionContext | undefined {
    const c = this.options.context;
    let ctx = typeof c === "function" ? c(name, args) : c;
    // Guard-level defaults fill only what the context leaves empty.
    if (this.strictness && ctx?.strictness === undefined) {
      ctx = { ...ctx, strictness: this.strictness };
    }
    if (userRequest && !ctx?.user_request) {
      ctx = { ...ctx, user_request: String(userRequest) };
    }
    // Everything a guard screens is an action the agent is about to take.
    if (ctx?.source === undefined) {
      ctx = { ...ctx, source: "tool_call" };
    }
    return ctx;
  }

  /** Whether a Review verdict lets the wrapped tool run. */
  private async reviewRuns(d: Decision): Promise<boolean> {
    const p = this.onReview;
    return typeof p === "function" ? !!(await p(d)) : p === "allow";
  }

  /**
   * Scan a proposed tool call and return the {@link Decision}. `userRequest`
   * fills the context's request when it has none.
   */
  async screen(name: string, args: unknown, opts: ScreenOptions = {}): Promise<Decision> {
    const context = this.ctx(name, args, opts.userRequest);
    const res = await this.client.scanPayload(toolCallJson(name, args), `${name}.toolcall.json`, {
      context,
    });
    return decisionFrom(res, context);
  }

  /**
   * Wrap a tool function so it screens its own call before executing. On Block
   * it throws {@link ToolBlocked}; on Review it follows `onReview`, by default
   * throwing {@link ToolNeedsReview}. A Block never runs.
   */
  wrap<A extends unknown[], R>(
    fn: (...args: A) => R | Promise<R>,
    name?: string,
  ): (...args: A) => Promise<R> {
    const toolName = name ?? fn.name ?? "tool";
    return async (...args: A): Promise<R> => {
      const d = await this.screen(toolName, args.length === 1 ? args[0] : args);
      if (d.blocked) throw new ToolBlocked(d);
      if (d.needsReview && !(await this.reviewRuns(d))) throw new ToolNeedsReview(d);
      return await fn(...args);
    };
  }
}
