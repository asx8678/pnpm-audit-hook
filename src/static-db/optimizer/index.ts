/**
 * Static Database Optimizer Module
 *
 * Provides compression and optimization utilities for the static vulnerability database.
 * Includes field deduplication, date compression, and optional gzip compression.
 */

// Re-export all types
export * from "./types";

// Re-export all constants
export * from "./constants";

// Re-export utility functions
export * from "./date-utils";
export * from "./version-utils";
export * from "./hash";
export * from "./search";

// Re-export optimization functions
export * from "./vulnerability-optimizer";
export * from "./package-optimizer";
export * from "./index-optimizer";

// Re-export compression utilities
export * from "./compression";