/**
 * Type definitions for structured logging and progress reporting.
 * 
 * @module logger-types
 */

// =============================================================================
// Structured Logging Types
// =============================================================================

/**
 * Severity levels for log messages
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Metadata for structured log entries
 */
export interface LogMetadata {
  /** Operation or component name */
  operation?: string;
  /** Correlation ID for request tracing */
  correlationId?: string;
  /** Source module/file */
  source?: string;
  /** Duration in milliseconds (for performance logging) */
  durationMs?: number;
  /** Additional key-value pairs */
  [key: string]: unknown;
}

/**
 * Structured log entry
 */
export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  metadata?: LogMetadata;
  source?: string;
}

// =============================================================================
// Progress Reporting Types
// =============================================================================

/**
 * Progress step information
 */
export interface ProgressStep {
  id: string;
  label: string;
  total: number;
  current: number;
  startTime: number;
  estimatedDurationMs?: number;
}

/**
 * Progress report
 */
export interface ProgressReport {
  /** Overall progress percentage (0-100) */
  percentage: number;
  /** Current step index */
  currentStep: number;
  /** Total steps */
  totalSteps: number;
  /** Steps */
  steps: ProgressStep[];
  /** Estimated time remaining in milliseconds */
  estimatedTimeRemainingMs?: number;
  /** Whether progress is complete */
  complete: boolean;
}

/**
 * Progress reporter options
 */
export interface ProgressReporterOptions {
  /** Show progress bar in terminal */
  showProgressBar?: boolean;
  /** Update interval in milliseconds */
  updateIntervalMs?: number;
  /** Whether to show ETA */
  showEta?: boolean;
  /** Custom format function */
  formatFn?: (report: ProgressReport) => string;
}

// =============================================================================
// CI/CD Integration Types
// =============================================================================

/**
 * CI/CD platform detection result
 */
export interface CIPlatform {
  name: string;
  isCI: boolean;
  /** Platform-specific environment variables */
  envVars: Record<string, string | undefined>;
}

/**
 * CI/CD annotation
 */
export interface CIAnnotation {
  type: 'warning' | 'error' | 'notice';
  message: string;
  file?: string;
  line?: number;
  column?: number;
}

/**
 * CI/CD integration interface
 */
export interface CIIntegration {
  /** Detect CI platform */
  detect(): CIPlatform;
  /** Emit annotation */
  emitAnnotation(annotation: CIAnnotation): void;
  /** Emit log message with platform-specific formatting */
  emitLog(message: string, level?: LogLevel): void;
  /** Set output variable */
  setOutput(name: string, value: string): void;
}