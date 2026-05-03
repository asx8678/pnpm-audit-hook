/**
 * SBOM Schema Validation
 *
 * Provides validation for CycloneDX and SPDX SBOM output formats.
 * Uses JSON Schema definitions to validate generated SBOMs.
 *
 * @module sbom/schema-validator
 */

import type { SbomFormat, ValidationResult, ValidationError } from './types';

/**
 * CycloneDX 1.5 minimal schema definition.
 * This is a simplified schema for basic validation.
 */
const CYCLONEDX_SCHEMA = {
  required: ['bomFormat', 'specVersion', 'serialNumber', 'version', 'metadata', 'components'],
  properties: {
    bomFormat: { type: 'string', enum: ['CycloneDX'] },
    specVersion: { type: 'string', enum: ['1.2', '1.3', '1.4', '1.5', '1.6'] },
    serialNumber: { type: 'string', pattern: '^urn:uuid:' },
    version: { type: 'number', minimum: 1 },
    metadata: {
      type: 'object',
      required: ['timestamp', 'tools'],
      properties: {
        timestamp: { type: 'string', format: 'date-time' },
        tools: { type: 'array', minItems: 1 },
        component: { type: 'object' },
      },
    },
    components: { type: 'array' },
    dependencies: { type: 'array' },
    vulnerabilities: { type: 'array' },
  },
};

/**
 * SPDX 2.3 minimal schema definition.
 * This is a simplified schema for basic validation.
 */
const SPDX_SCHEMA = {
  required: ['spdxVersion', 'dataLicense', 'SPDXID', 'name', 'documentNamespace', 'creationInfo', 'packages', 'relationships'],
  properties: {
    spdxVersion: { type: 'string', enum: ['SPDX-2.1', 'SPDX-2.2', 'SPDX-2.3'] },
    dataLicense: { type: 'string' },
    SPDXID: { type: 'string', enum: ['SPDXRef-DOCUMENT'] },
    name: { type: 'string' },
    documentNamespace: { type: 'string', pattern: '^https?://' },
    creationInfo: {
      type: 'object',
      required: ['created', 'creators'],
      properties: {
        created: { type: 'string', format: 'date-time' },
        creators: { type: 'array', minItems: 1 },
      },
    },
    packages: { type: 'array', minItems: 1 },
    relationships: { type: 'array' },
    annotations: { type: 'array' },
  },
};

/**
 * Validate a string value against a simple schema property.
 */
function validateProperty(
  value: unknown,
  schema: Record<string, unknown>,
  path: string,
): ValidationError[] {
  const errors: ValidationError[] = [];

  if (schema.type && typeof value !== schema.type) {
    errors.push({
      path,
      message: `Expected type ${schema.type}, got ${typeof value}`,
      severity: 'error',
    });
    return errors;
  }

  if (schema.enum && Array.isArray(schema.enum)) {
    if (!schema.enum.includes(value)) {
      errors.push({
        path,
        message: `Value "${value}" not in allowed values: ${schema.enum.join(', ')}`,
        severity: 'error',
      });
    }
  }

  if (schema.pattern && typeof value === 'string') {
    const regex = new RegExp(schema.pattern as string);
    if (!regex.test(value)) {
      errors.push({
        path,
        message: `Value "${value}" does not match pattern: ${schema.pattern}`,
        severity: 'error',
      });
    }
  }

  if (schema.minimum != null && typeof value === 'number') {
    if (value < (schema.minimum as number)) {
      errors.push({
        path,
        message: `Value ${value} is less than minimum ${schema.minimum}`,
        severity: 'error',
      });
    }
  }

  return errors;
}

/**
 * Validate an object against a schema definition.
 */
function validateObject(
  obj: Record<string, unknown>,
  schema: Record<string, unknown>,
  basePath: string = '',
): ValidationError[] {
  const errors: ValidationError[] = [];

  // Check required fields
  if (schema.required && Array.isArray(schema.required)) {
    for (const field of schema.required) {
      if (!(field in obj)) {
        errors.push({
          path: basePath ? `${basePath}.${field}` : field,
          message: `Missing required field: ${field}`,
          severity: 'error',
        });
      }
    }
  }

  // Validate properties
  if (schema.properties) {
    for (const [key, propSchema] of Object.entries(schema.properties as Record<string, Record<string, unknown>>)) {
      if (key in obj) {
        const value = obj[key];
        const propPath = basePath ? `${basePath}.${key}` : key;

        // Validate primitive properties
        if (propSchema.type && !(propSchema.type as string).includes('object') && !(propSchema.type as string).includes('array')) {
          errors.push(...validateProperty(value, propSchema, propPath));
        }

        // Validate object properties
        if (propSchema.type === 'object' && typeof value === 'object' && value !== null) {
          errors.push(...validateObject(value as Record<string, unknown>, propSchema, propPath));
        }

        // Validate array properties
        if (propSchema.type === 'array' && Array.isArray(value)) {
          if (propSchema.minItems != null && value.length < (propSchema.minItems as number)) {
            errors.push({
              path: propPath,
              message: `Array has ${value.length} items, minimum required is ${propSchema.minItems}`,
              severity: 'error',
            });
          }
        }
      }
    }
  }

  return errors;
}

/**
 * Validate a CycloneDX BOM document.
 */
function validateCycloneDX(bom: Record<string, unknown>): ValidationResult {
  const errors = validateObject(bom, CYCLONEDX_SCHEMA);
  const warnings: ValidationError[] = [];

  // Additional CycloneDX-specific validations
  const components = bom.components;
  if (Array.isArray(components)) {
    for (let i = 0; i < components.length; i++) {
      const component = components[i];
      if (typeof component === 'object' && component !== null) {
        const comp = component as Record<string, unknown>;
        const path = `components[${i}]`;

        if (!comp.name) {
          errors.push({ path: `${path}.name`, message: 'Component missing name', severity: 'error' });
        }
        if (!comp.version) {
          errors.push({ path: `${path}.version`, message: 'Component missing version', severity: 'error' });
        }
        if (!comp.purl) {
          warnings.push({ path: `${path}.purl`, message: 'Component missing purl', severity: 'warning' });
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    format: 'cyclonedx',
  };
}

/**
 * Validate an SPDX document.
 */
function validateSPDX(doc: Record<string, unknown>): ValidationResult {
  const errors = validateObject(doc, SPDX_SCHEMA);
  const warnings: ValidationError[] = [];

  // Additional SPDX-specific validations
  const packages = doc.packages;
  if (Array.isArray(packages)) {
    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      if (typeof pkg === 'object' && pkg !== null) {
        const p = pkg as Record<string, unknown>;
        const path = `packages[${i}]`;

        if (!p.SPDXID) {
          errors.push({ path: `${path}.SPDXID`, message: 'Package missing SPDXID', severity: 'error' });
        }
        if (!p.name) {
          errors.push({ path: `${path}.name`, message: 'Package missing name', severity: 'error' });
        }
        if (!p.versionInfo) {
          warnings.push({ path: `${path}.versionInfo`, message: 'Package missing versionInfo', severity: 'warning' });
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    format: 'spdx',
  };
}

/**
 * Validate an SBOM document against the appropriate schema.
 *
 * @param sbomContent - SBOM content as JSON string or parsed object
 * @param format - Expected SBOM format
 * @returns Validation result with errors and warnings
 *
 * @example
 * ```typescript
 * const result = validateSbom(sbomJson, 'cyclonedx');
 * if (!result.valid) {
 *   console.error('SBOM validation failed:', result.errors);
 * }
 * ```
 */
export function validateSbom(
  sbomContent: string | Record<string, unknown>,
  format: SbomFormat,
): ValidationResult {
  let sbom: Record<string, unknown>;

  if (typeof sbomContent === 'string') {
    try {
      sbom = JSON.parse(sbomContent);
    } catch (err) {
      return {
        valid: false,
        errors: [{
          path: '',
          message: `Invalid JSON: ${(err as Error).message}`,
          severity: 'error',
        }],
        warnings: [],
        format,
      };
    }
  } else {
    sbom = sbomContent;
  }

  switch (format) {
    case 'cyclonedx':
      return validateCycloneDX(sbom);
    case 'spdx':
      return validateSPDX(sbom);
    default:
      return {
        valid: false,
        errors: [{
          path: '',
          message: `Unsupported format: ${format}`,
          severity: 'error',
        }],
        warnings: [],
        format,
      };
  }
}

/**
 * Quick check if SBOM content is valid.
 *
 * @param sbomContent - SBOM content as JSON string or parsed object
 * @param format - Expected SBOM format
 * @returns True if valid, false otherwise
 */
export function isValidSbom(
  sbomContent: string | Record<string, unknown>,
  format: SbomFormat,
): boolean {
  return validateSbom(sbomContent, format).valid;
}
