import type { Severity } from "../../types";
import {
  supportsColor,
  severityColor as coreSeverityColor,
  SEVERITY_ORDER as coreSeverityOrder,
  RESET as coreReset,
  BOLD as coreBold,
  RED as coreRed,
  GREEN as coreGreen,
  YELLOW as coreYellow,
  CYAN as coreCyan,
  DIM as coreDim,
  BRIGHT_RED as coreBrightRed,
  BRIGHT_GREEN as coreBrightGreen,
  BRIGHT_YELLOW as coreBrightYellow,
  BRIGHT_CYAN as coreBrightCyan,
  horizontalLine,
  sectionHeader,
  subsectionHeader,
  indent,
  listItem,
  formatError,
  formatWarning,
  formatSuccess,
  progressBar,
  spinnerChar,
  truncate,
  pad,
  center,
  box,
  statusColor,
  statusIcon,
  statusText,
  severityLabel,
  severityBgColor,
} from "../color-utils";

// Re-export from color-utils for backward compatibility
export const SEVERITY_ORDER: Severity[] = coreSeverityOrder;
export const RESET = coreReset;
export const BOLD = coreBold;
export const RED = coreRed;
export const GREEN = coreGreen;
export const YELLOW = coreYellow;
export const CYAN = coreCyan;
export const DIM = coreDim;
export const BRIGHT_RED = coreBrightRed;
export const BRIGHT_GREEN = coreBrightGreen;
export const BRIGHT_YELLOW = coreBrightYellow;
export const BRIGHT_CYAN = coreBrightCyan;

// Export new utilities
export { supportsColor, horizontalLine, sectionHeader, subsectionHeader, indent, listItem, formatError, formatWarning, formatSuccess, progressBar, spinnerChar, truncate, pad, center, box, statusColor, statusIcon, statusText, severityLabel, severityBgColor };

export function severityColor(severity: Severity): string {
  return coreSeverityColor(severity);
}
