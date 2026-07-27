import type { Rule } from "../types.js";
import { permissionRules } from "./permissions.js";
import { schemaRules } from "./schema.js";
import { injectionRules } from "./injection.js";
import { secretRules } from "./secrets.js";
import { transportRules } from "./transport.js";
import { metadataRules } from "./metadata.js";
import { hygieneRules } from "./hygiene.js";

/** The full, ordered set of built-in rules. */
export const ALL_RULES: Rule[] = [
  ...permissionRules,
  ...schemaRules,
  ...injectionRules,
  ...secretRules,
  ...transportRules,
  ...metadataRules,
  ...hygieneRules,
];

/** Look up a rule by id. */
export function getRule(id: string): Rule | undefined {
  return ALL_RULES.find((r) => r.id === id);
}

export {
  permissionRules,
  schemaRules,
  injectionRules,
  secretRules,
  transportRules,
  metadataRules,
  hygieneRules,
};
