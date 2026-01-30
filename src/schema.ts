// Runtime validation schema derived from .pnpm-audit.schema.json
export const configSchema: any = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://example.org/pnpm-audit.schema.json",
  title: "pnpm-audit-hook configuration",
  type: "object",
  additionalProperties: false,
  properties: {
    version: {
      type: "integer",
      minimum: 1,
    },
    policies: {
      type: "object",
      additionalProperties: false,
      properties: {
        block: {
          type: "array",
          items: { $ref: "#/$defs/severity" },
        },
        warn: {
          type: "array",
          items: { $ref: "#/$defs/severity" },
        },
        gracePeriod: {
          type: "integer",
          minimum: 0,
        },
        unknownVulnData: {
          type: "string",
          enum: ["allow", "warn", "block"],
        },
        networkPolicy: {
          type: "string",
          enum: ["fail-open", "fail-closed"],
        },
        allowlist: {
          type: "array",
          items: {
            type: "object",
            additionalProperties: false,
            properties: {
              cve: {
                type: "string",
              },
              id: {
                type: "string",
              },
              package: {
                type: "string",
              },
              expires: {
                type: "string",
                format: "date",
              },
              reason: {
                type: "string",
              },
              approvedBy: {
                type: "string",
              },
            },
            required: ["package", "expires", "reason", "approvedBy"],
            anyOf: [
              {
                required: ["cve"],
              },
              {
                required: ["id"],
              },
            ],
          },
        },
        blocklist: {
          type: "array",
          items: {
            type: "string",
          },
        },
      },
      required: ["block", "warn", "gracePeriod", "allowlist", "blocklist"],
    },
    sources: {
      type: "object",
      additionalProperties: false,
      properties: {
        osv: {
          $ref: "#/$defs/sourceToggle",
        },
        github: {
          $ref: "#/$defs/sourceToggle",
        },
        npm: {
          $ref: "#/$defs/sourceToggle",
        },
        nvd: {
          $ref: "#/$defs/sourceToggle",
        },
        ossIndex: {
          $ref: "#/$defs/sourceToggle",
        },
      },
    },
    integrity: {
      type: "object",
      additionalProperties: false,
      properties: {
        requireSha512Integrity: {
          type: "boolean",
        },
      },
    },
    performance: {
      type: "object",
      additionalProperties: false,
      properties: {
        concurrency: {
          type: "integer",
          minimum: 1,
          maximum: 64,
        },
        timeoutMs: {
          type: "integer",
          minimum: 1000,
          maximum: 600000,
        },
        earlyExitOnBlock: {
          type: "boolean",
        },
      },
    },
    cache: {
      type: "object",
      additionalProperties: false,
      properties: {
        ttlSeconds: {
          type: "integer",
          minimum: 0,
        },
        dir: {
          type: "string",
        },
        allowStale: {
          type: "boolean",
        },
      },
    },
    reporting: {
      type: "object",
      additionalProperties: false,
      properties: {
        formats: {
          type: "array",
          items: {
            type: "string",
          },
        },
        outputDir: {
          type: "string",
        },
        basename: {
          type: "string",
        },
      },
    },
    azureDevOps: {
      type: "object",
      additionalProperties: false,
      properties: {
        prComment: { $ref: "#/$defs/enabledToggle" },
        logAnalytics: { $ref: "#/$defs/enabledToggle" },
      },
    },
  },
  required: ["version", "policies"],
  $defs: {
    severity: {
      type: "string",
      enum: ["critical", "high", "medium", "low", "unknown"],
    },
    enabledToggle: {
      type: "object",
      additionalProperties: false,
      properties: { enabled: { type: "boolean" } },
      required: ["enabled"],
    },
    sourceToggle: { $ref: "#/$defs/enabledToggle" },
  },
};
