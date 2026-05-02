/**
 * Static Database Optimizer
 *
 * Provides compression and optimization utilities for the static vulnerability database.
 * Includes field deduplication, date compression, and optional gzip compression.
 *
 * This file is now a re-export hub for backward compatibility.
 * The actual implementation has been moved to the optimizer/ directory.
 */

// Re-export everything from the optimizer module
export * from "./optimizer/index";
