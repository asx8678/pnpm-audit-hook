import type { Severity } from "../../types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export const RESET = "\x1b[0m";
export const BOLD = "\x1b[1m";
export const RED = "\x1b[31m";
export const GREEN = "\x1b[32m";
export const YELLOW = "\x1b[33m";
export const CYAN = "\x1b[36m";
export const DIM = "\x1b[2m";

export function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return RED;
    case "high":
      return RED;
    case "medium":
      return YELLOW;
    case "low":
      return CYAN;
    default:
      return DIM;
  }
}
