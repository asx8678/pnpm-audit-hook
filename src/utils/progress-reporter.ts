/**
 * Progress reporter utilities for pnpm-audit-hook.
 * 
 * Provides progress tracking with ETA calculations and step-based progress.
 * 
 * @module progress-reporter
 */

import { getEnvironmentVariables, isVerboseMode } from './env-manager';
import type { ProgressStep, ProgressReport, ProgressReporterOptions } from './logger-types';

// =============================================================================
// Configuration
// =============================================================================

const PREFIX = '[pnpm-audit]';
const { PNPM_AUDIT_QUIET: QUIET, PNPM_AUDIT_JSON: JSON_MODE } = getEnvironmentVariables();
const VERBOSE = isVerboseMode();

// =============================================================================
// Progress Reporter
// =============================================================================

/**
 * Progress reporter with ETA calculations and step tracking
 */
export class ProgressReporter {
  private steps: ProgressStep[] = [];
  private currentStepIndex: number = -1;
  private options: Required<ProgressReporterOptions>;
  private updateTimer: NodeJS.Timeout | null = null;
  private startTime: number = 0;

  constructor(options: ProgressReporterOptions = {}) {
    this.options = {
      showProgressBar: options.showProgressBar ?? true,
      updateIntervalMs: options.updateIntervalMs ?? 100,
      showEta: options.showEta ?? true,
      formatFn: options.formatFn ?? this.defaultFormatFn.bind(this),
    };
  }

  /**
   * Start progress tracking
   */
  start(): void {
    this.startTime = performance.now();
    this.steps = [];
    this.currentStepIndex = -1;
    
    if (this.shouldOutput()) {
      this.startUpdateTimer();
    }
  }

  /**
   * Add a progress step
   */
  addStep(id: string, label: string, total: number, estimatedDurationMs?: number): void {
    const step: ProgressStep = {
      id,
      label,
      total,
      current: 0,
      startTime: performance.now(),
      estimatedDurationMs,
    };
    this.steps.push(step);
    
    if (this.currentStepIndex === -1) {
      this.currentStepIndex = 0;
    }
  }

  /**
   * Update progress for a step
   */
  update(stepId: string, current: number): void {
    const step = this.steps.find(s => s.id === stepId);
    if (step) {
      step.current = Math.min(current, step.total);
      
      // Auto-advance to next step if current step is complete
      if (step.current >= step.total) {
        this.advanceToNextStep();
      }
    }
  }

  /**
   * Increment progress for a step
   */
  increment(stepId: string, amount: number = 1): void {
    const step = this.steps.find(s => s.id === stepId);
    if (step) {
      this.update(stepId, step.current + amount);
    }
  }

  /**
   * Advance to next step
   */
  advanceToNextStep(): void {
    if (this.currentStepIndex < this.steps.length - 1) {
      this.currentStepIndex++;
    }
  }

  /**
   * Complete current step
   */
  completeStep(stepId: string): void {
    const step = this.steps.find(s => s.id === stepId);
    if (step) {
      step.current = step.total;
      this.advanceToNextStep();
    }
  }

  /**
   * Get current progress report
   */
  getReport(): ProgressReport {
    const totalProgress = this.steps.reduce((sum, step) => sum + step.current, 0);
    const totalItems = this.steps.reduce((sum, step) => sum + step.total, 0);
    const percentage = totalItems > 0 ? Math.round((totalProgress / totalItems) * 100) : 0;
    
    const estimatedTimeRemainingMs = this.calculateETA();
    
    return {
      percentage,
      currentStep: this.currentStepIndex,
      totalSteps: this.steps.length,
      steps: [...this.steps],
      estimatedTimeRemainingMs,
      complete: percentage >= 100,
    };
  }

  /**
   * Calculate estimated time remaining
   */
  private calculateETA(): number | undefined {
    if (this.steps.length === 0 || this.currentStepIndex < 0) {
      return undefined;
    }

    const elapsed = performance.now() - this.startTime;
    
    // Calculate percentage inline to avoid infinite recursion
    const totalProgress = this.steps.reduce((sum, step) => sum + step.current, 0);
    const totalItems = this.steps.reduce((sum, step) => sum + step.total, 0);
    const percentage = totalItems > 0 ? Math.round((totalProgress / totalItems) * 100) : 0;
    
    if (percentage <= 0) {
      return undefined;
    }
    
    // Calculate based on overall progress
    const totalEstimated = (elapsed / percentage) * 100;
    const remaining = totalEstimated - elapsed;
    
    return Math.max(0, Math.round(remaining));
  }

  /**
   * Format ETA for display
   */
  private formatETA(ms: number): string {
    if (ms < 1000) return '<1s';
    
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  }

  /**
   * Default format function
   */
  private defaultFormatFn(report: ProgressReport): string {
    const parts: string[] = [];
    
    // Progress bar
    if (this.options.showProgressBar) {
      const barLength = 20;
      const filled = Math.floor((report.percentage / 100) * barLength);
      const bar = '='.repeat(filled).padEnd(barLength, ' ');
      parts.push(`[${bar}] ${report.percentage}%`);
    }
    
    // Current step info
    if (report.currentStep >= 0 && report.currentStep < report.steps.length) {
      const step = report.steps[report.currentStep]!;
      parts.push(`${step.label} (${step.current}/${step.total})`);
    }
    
    // ETA
    if (this.options.showEta && report.estimatedTimeRemainingMs !== undefined) {
      parts.push(`ETA: ${this.formatETA(report.estimatedTimeRemainingMs)}`);
    }
    
    return parts.join(' ');
  }

  /**
   * Should output progress to console
   */
  private shouldOutput(): boolean {
    return !JSON_MODE && !QUIET && VERBOSE;
  }

  /**
   * Start update timer for periodic progress updates
   */
  private startUpdateTimer(): void {
    if (this.updateTimer) {
      clearInterval(this.updateTimer);
    }
    
    this.updateTimer = setInterval(() => {
      this.render();
    }, this.options.updateIntervalMs);
  }

  /**
   * Render progress to console
   */
  render(): void {
    if (!this.shouldOutput()) return;
    
    const report = this.getReport();
    const formatted = this.options.formatFn(report);
    process.stdout.write(`\r${PREFIX} ${formatted}`);
  }

  /**
   * Stop progress tracking and render final state
   */
  stop(): void {
    if (this.updateTimer) {
      clearInterval(this.updateTimer);
      this.updateTimer = null;
    }
    
    if (this.shouldOutput()) {
      this.render();
      process.stdout.write('\n');
    }
  }

  /**
   * Create a sub-progress reporter for a specific step
   */
  createSubProgress(stepId: string): SubProgressReporter {
    const step = this.steps.find(s => s.id === stepId);
    if (!step) {
      throw new Error(`Step ${stepId} not found`);
    }
    
    return new SubProgressReporter(this, step);
  }
}

// =============================================================================
// Sub-Progress Reporter
// =============================================================================

/**
 * Progress reporter for a specific step within the main progress
 */
export class SubProgressReporter {
  private parent: ProgressReporter;
  private step: ProgressStep;

  constructor(parent: ProgressReporter, step: ProgressStep) {
    this.parent = parent;
    this.step = step;
  }

  /**
   * Update progress for this step
   */
  update(current: number): void {
    this.parent.update(this.step.id, current);
  }

  /**
   * Increment progress
   */
  increment(amount: number = 1): void {
    this.parent.increment(this.step.id, amount);
  }

  /**
   * Complete this step
   */
  complete(): void {
    this.parent.completeStep(this.step.id);
  }
}

// =============================================================================
// Simple Progress Bar (for backward compatibility)
// =============================================================================

/**
 * Simple progress bar for terminal output
 */
export function formatProgressBar(current: number, total: number, label: string): string {
  if (JSON_MODE || QUIET || !VERBOSE) return '';
  
  const percent = total > 0 ? Math.round((current / total) * 100) : 0;
  const bar = '='.repeat(Math.floor(percent / 5)).padEnd(20, ' ');
  return `${PREFIX} [${bar}] ${percent}% ${label}`;
}

/**
 * Render progress bar to stdout
 */
export function renderProgressBar(current: number, total: number, label: string): void {
  if (JSON_MODE || QUIET || !VERBOSE) return;
  
  const formatted = formatProgressBar(current, total, label);
  process.stdout.write(`\r${formatted}`);
  
  if (current >= total) {
    process.stdout.write('\n');
  }
}