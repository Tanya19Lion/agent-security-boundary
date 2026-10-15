/**
 * Дешева перевірка недовіреного тексту ПЕРЕД тим, як він потрапить у промпт моделі.
 * Регулярки, без виклику LLM — тому дешево і детерміновано.
 */

export type PrefilterVerdict = "pass" | "block";

export interface PrefilterResult {
  verdict: PrefilterVerdict;
  reasons: string[];
}

interface Rule {
  name: string;
  pattern: RegExp;
}

const RULES: Rule[] = [
  // Prompt injection / jailbreak
  { name: "prompt-injection-ignore-instructions", pattern: /ignore (all )?(previous|prior|above) instructions/i },
  { name: "prompt-injection-developer-mode", pattern: /developer mode|jailbreak|you are now (in|an?) /i },
  { name: "prompt-injection-reveal-system-prompt", pattern: /reveal (your )?(system prompt|instructions)/i },
  { name: "prompt-injection-disregard", pattern: /disregard (all|any) (prior|previous|earlier)/i },

  // Secret-like material embedded in the untrusted text
  { name: "aws-access-key", pattern: /AKIA[0-9A-Z]{16}/ },
  { name: "private-key-block", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },

  // Shell / exfiltration patterns
  { name: "shell-rm-rf", pattern: /\brm\s+-rf\b/ },
  { name: "shell-pipe-to-sh", pattern: /curl[^\n]*\|\s*sh\b/i },
  { name: "shell-command-substitution", pattern: /\$\([^)]+\)|`[^`]+`/ },
  { name: "exfil-curl-post", pattern: /curl[^\n]*-d\s+@/i },

  // Explicit demand for a privileged action, in the text itself
  { name: "demand-merge-without-review", pattern: /merge[^\n]{0,40}main[^\n]{0,40}without (review|approval)/i },
  { name: "demand-disable-protection", pattern: /disable[^\n]{0,30}(firewall|branch protection|auth)/i },
];

export function prefilter(text: string): PrefilterResult {
  const reasons: string[] = [];

  for (const rule of RULES) {
    if (rule.pattern.test(text)) {
      reasons.push(rule.name);
    }
  }

  return {
    verdict: reasons.length > 0 ? "block" : "pass",
    reasons,
  };
}
