/**
 * Жорсткі обмеження на дії агента ПІСЛЯ виклику моделі.
 * Ці правила не залежать від того, що "вирішила" модель — вона може
 * попросити що завгодно, PolicyGuard вирішує сам.
 */

const PROTECTED_PATH_PATTERNS = [/^\.env/, /^\.git(\/|$)/, /^node_modules(\/|$)/, /secrets?\.json$/i];

const NETWORK_ALLOW_LIST: string[] = []; // порожньо = заборонено все за замовчуванням

export type ProposedAction =
  | { type: "read_file"; path: string }
  | { type: "write_file"; path: string; content: string }
  | { type: "network_request"; host: string }
  | { type: "git_merge"; branch: string };

export interface GuardDecision {
  allowed: boolean;
  reason: string;
  requiresHumanReview: boolean;
}

export class PolicyGuard {
  private pendingReview: ProposedAction[] = [];

  evaluate(action: ProposedAction): GuardDecision {
    switch (action.type) {
      case "read_file":
      case "write_file": {
        if (this.isProtectedPath(action.path)) {
          return { allowed: false, reason: `protected path: ${action.path}`, requiresHumanReview: false };
        }
        this.pendingReview.push(action);
        return { allowed: true, reason: "queued for human review", requiresHumanReview: true };
      }
      case "network_request": {
        if (!NETWORK_ALLOW_LIST.includes(action.host)) {
          return { allowed: false, reason: `host not in allow-list: ${action.host}`, requiresHumanReview: false };
        }
        return { allowed: true, reason: "allow-listed host", requiresHumanReview: false };
      }
      case "git_merge": {
        // Агент ніколи не мержить сам — результат завжди йде людині.
        this.pendingReview.push(action);
        return { allowed: false, reason: "merges always require a human", requiresHumanReview: true };
      }
    }
  }

  private isProtectedPath(path: string): boolean {
    return PROTECTED_PATH_PATTERNS.some((pattern) => pattern.test(path));
  }

  getPendingReview(): readonly ProposedAction[] {
    return this.pendingReview;
  }
}
