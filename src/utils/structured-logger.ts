/**
 * Structured logger with metadata support for pnpm-audit-hook.
 * 
 * Provides structured logging capabilities while maintaining backward
 * compatibility with the existing logger interface.
 * 
 * @module structured-logger
 */

import { getEnvironmentVariables, isVerboseMode } from './env-manager';
import type { LogLevel, LogEntry, LogMetadata } from './logger-types';

// =============================================================================
// Configuration
// =============================================================================

const PREFIX = '[pnpm-audit]';

// All env vars are cached at module load for hot-path performance
const { PNPM_AUDIT_QUIET: QUIET, PNPM_AUDIT_DEBUG: DEBUG, PNPM_AUDIT_JSON: JSON_MODE } = getEnvironmentVariables();
const VERBOSE = isVerboseMode();

// =============================================================================
// Core Structured Logger
// =============================================================================

/**
 * Structured logger with metadata support
 */
export class StructuredLogger {
  private correlationId: string | undefined;
  private defaultSource: string | undefined;

  /**
   * Create a new structured logger
   * @param defaultSource - Default source module name
   * @param correlationId - Correlation ID for request tracing
   */
  constructor(defaultSource?: string, correlationId?: string) {
    this.defaultSource = defaultSource;
    this.correlationId = correlationId;
  }

  /**
   * Set correlation ID for all subsequent log entries
   */
  setCorrelationId(id: string): void {
    this.correlationId = id;
  }

  /**
   * Set default source module name
   */
  setSource(source: string): void {
    this.defaultSource = source;
  }

  /**
   * Create a child logger with specific context
   */
  child(source: string, correlationId?: string): StructuredLogger {
    return new StructuredLogger(
      source || this.defaultSource,
      correlationId || this.correlationId,
    );
  }

  /**
   * Log a structured message
   */
  private log(
    level: LogLevel,
    message: string,
    metadata?: LogMetadata,
  ): void {
    if (JSON_MODE) return;
    if (level !== 'error' && QUIET) return;

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      metadata: {
        ...metadata,
        correlationId: metadata?.correlationId || this.correlationId,
        source: metadata?.source || this.defaultSource,
      },
    };

    // Format output based on level
    const formattedMessage = this.formatEntry(entry);

    switch (level) {
      case 'debug':
        if (DEBUG) {
          console.log(formattedMessage);
        }
        break;
      case 'info':
        if (!QUIET) {
          console.log(formattedMessage);
        }
        break;
      case 'warn':
        if (!QUIET) {
          console.warn(formattedMessage);
        }
        break;
      case 'error':
        console.error(formattedMessage);
        break;
    }
  }

  /**
   * Format log entry for console output
   */
  private formatEntry(entry: LogEntry): string {
    const parts: string[] = [PREFIX];

    // Add level
    parts.push(`[${entry.level}]`);

    // Add source if present
    if (entry.metadata?.source) {
      parts.push(`[${entry.metadata.source}]`);
    }

    // Add message
    parts.push(entry.message);

    // Add duration if present
    if (entry.metadata?.durationMs !== undefined) {
      parts.push(`(${entry.metadata.durationMs}ms)`);
    }

    // Add correlation ID if present
    if (entry.metadata?.correlationId) {
      parts.push(`[${entry.metadata.correlationId}]`);
    }

    return parts.join(' ');
  }

  /**
   * Log debug message
   */
  debug(message: string, metadata?: LogMetadata): void {
    this.log('debug', message, metadata);
  }

  /**
   * Log info message
   */
  info(message: string, metadata?: LogMetadata): void {
    this.log('info', message, metadata);
  }

  /**
   * Log warning message
   */
  warn(message: string, metadata?: LogMetadata): void {
    this.log('warn', message, metadata);
  }

  /**
   * Log error message
   */
  error(message: string, metadata?: LogMetadata): void {
    this.log('error', message, metadata);
  }

  /**
   * Log performance timing
   */
  timing(label: string, durationMs: number, metadata?: LogMetadata): void {
    this.debug(`${label}: ${durationMs}ms`, {
      ...metadata,
      durationMs,
    });
  }

  /**
   * Start a timer for performance measurement
   */
  startTimer(label: string): () => number {
    const start = performance.now();
    return () => {
      const duration = Math.round(performance.now() - start);
      this.timing(label, duration);
      return duration;
    };
  }

  /**
   * Get logger for verbose output
   */
  verbose(message: string, metadata?: LogMetadata): void {
    if (VERBOSE && !QUIET) {
      this.log('info', message, metadata);
    }
  }
}

// =============================================================================
// Export default logger instance
// =============================================================================

/**
 * Default logger instance for backward compatibility
 */
export const structuredLogger = new StructuredLogger();

/**
 * Create a new structured logger instance
 */
export function createLogger(source?: string, correlationId?: string): StructuredLogger {
  return new StructuredLogger(source, correlationId);
}

/**
 * Get a child logger with specific context
 */
export function getChildLogger(source: string, correlationId?: string): StructuredLogger {
  return structuredLogger.child(source, correlationId);
}
