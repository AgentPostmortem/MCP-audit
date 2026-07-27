import type { Finding, JsonSchema, Rule } from "../types.js";
import { walkSchema } from "./helpers.js";

function isObjectSchema(schema?: JsonSchema): boolean {
  if (!schema) return false;
  if (schema.type === "object") return true;
  if (Array.isArray(schema.type) && schema.type.includes("object")) return true;
  return schema.properties !== undefined;
}

/**
 * MCP010 - Tool has no input schema at all. The model can pass anything and the
 * server has no declared contract to validate against.
 */
export const missingInputSchema: Rule = {
  id: "MCP010",
  title: "Tool is missing an input schema",
  description:
    "Every tool should publish an input schema so arguments are validated and constrained.",
  severity: "medium",
  category: "schema",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const schema = tool.inputSchema;
      const empty =
        !schema ||
        (isObjectSchema(schema) &&
          Object.keys(schema.properties ?? {}).length === 0);
      if (empty) {
        findings.push(
          ctx.report({
            title: "Tool has no declared input schema",
            message: `Tool "${tool.name}" does not declare input properties, so arguments are unvalidated.`,
            remediation:
              "Publish a JSON Schema for inputSchema with typed properties and a required list.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

/**
 * MCP011 - Object schema permits unbounded additional properties. When
 * `additionalProperties` is not `false`, callers can smuggle arbitrary extra
 * fields past the declared contract.
 */
export const unboundedAdditionalProperties: Rule = {
  id: "MCP011",
  title: "Schema allows unbounded additional properties",
  description:
    "Object schemas should set additionalProperties:false to reject undeclared fields.",
  severity: "low",
  category: "schema",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      walkSchema(tool.inputSchema, (node, path) => {
        if (!isObjectSchema(node)) return;
        if (Object.keys(node.properties ?? {}).length === 0) return;
        if (node.additionalProperties !== false) {
          findings.push(
            ctx.report({
              title: "additionalProperties is not disabled",
              message: `Tool "${tool.name}" schema at ${path} allows undeclared properties (additionalProperties is not false).`,
              remediation:
                "Set additionalProperties:false on object schemas to reject unexpected fields.",
              location: `${tool.name} ${path}`,
            }),
          );
        }
      });
    }
    return findings;
  },
};

/**
 * MCP012 - Free-form string argument with no bounds. String args with no enum,
 * pattern, or maxLength are effectively unbounded injection surfaces.
 */
export const unconstrainedStringArg: Rule = {
  id: "MCP012",
  title: "Unconstrained string argument",
  description:
    "String arguments should constrain their values with enum, pattern, format, or maxLength.",
  severity: "low",
  category: "schema",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const props = tool.inputSchema?.properties ?? {};
      for (const [name, schema] of Object.entries(props)) {
        if (schema.type !== "string") continue;
        const bounded =
          schema.enum !== undefined ||
          schema["pattern"] !== undefined ||
          schema["format"] !== undefined ||
          schema["maxLength"] !== undefined;
        if (!bounded) {
          findings.push(
            ctx.report({
              title: "String argument has no value constraints",
              message: `Argument "${name}" of tool "${tool.name}" is a free-form string with no enum, pattern, format, or maxLength.`,
              remediation:
                "Constrain the argument with an enum, regex pattern, format, or maxLength appropriate to its purpose.",
              location: `${tool.name}.${name}`,
            }),
          );
        }
      }
    }
    return findings;
  },
};

/**
 * MCP013 - Object schema declares properties but no `required` list, so the
 * server cannot rely on any argument being present.
 */
export const missingRequiredList: Rule = {
  id: "MCP013",
  title: "Object schema has no required properties",
  description:
    "Tools with mandatory inputs should list them in `required` so calls without them are rejected.",
  severity: "info",
  category: "schema",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const schema = tool.inputSchema;
      if (!schema || !isObjectSchema(schema)) continue;
      const props = Object.keys(schema.properties ?? {});
      if (props.length > 0 && (schema.required ?? []).length === 0) {
        findings.push(
          ctx.report({
            title: "Schema declares no required properties",
            message: `Tool "${tool.name}" declares ${props.length} properties but no required list; every argument is optional.`,
            remediation:
              "Add the mandatory arguments to the `required` array so incomplete calls are rejected.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

export const schemaRules: Rule[] = [
  missingInputSchema,
  unboundedAdditionalProperties,
  unconstrainedStringArg,
  missingRequiredList,
];
