import type { Finding, Rule, RuleContext, Severity } from "../types.js";

/**
 * Create a per-rule {@link RuleContext}. The context stamps the rule id and a
 * default severity onto findings so individual rules stay terse.
 */
export function createRuleContext(rule: Rule): RuleContext {
  return {
    report(partial): Finding {
      const severity: Severity = partial.severity ?? rule.severity;
      return {
        ruleId: rule.id,
        severity,
        title: partial.title,
        message: partial.message,
        remediation: partial.remediation,
        location: partial.location,
      };
    },
  };
}
