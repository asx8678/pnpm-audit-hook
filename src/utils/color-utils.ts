/**
 * Color utility module for pnpm-audit-hook.
 *
 * Provides color support detection, consistent color scheme,
 * and accessibility-focused color functions.
 *
 * @module color-utils
 */

import type { Severity } from '../types';

// =============================================================================
// Severity Constants
// =============================================================================

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'unknown'];

// =============================================================================
// Color Support Detection
// =============================================================================

/**
 * Detect if the terminal supports color output.
 *
 * Checks standard environment variables:
 * - FORCE_COLOR: If set, force color output (0 = disable, 1+ = enable)
 * - NO_COLOR: If set, disable color output (http://no-color.org/)
 * - COLORTERM: If set to 'truecolor' or '24bit', enable advanced colors
 * - TERM: If set, check for color support in terminal type
 */
export function supportsColor(): boolean {
  // Check for explicit disable
  if (process.env.NO_COLOR !== undefined) {
    return false;
  }

  // Check for explicit enable
  if (process.env.FORCE_COLOR !== undefined) {
    return parseInt(process.env.FORCE_COLOR, 10) > 0;
  }

  // Check for terminal color support
  if (process.env.COLORTERM === 'truecolor' || process.env.COLORTERM === '24bit') {
    return true;
  }

  // Check terminal type
  const term = process.env.TERM || '';
  if (term.includes('color') || term.includes('256color')) {
    return true;
  }

  // Windows Terminal and ConEmu support color
  if (process.env.WT_SESSION || process.env.ConEmuANSI === 'ON') {
    return true;
  }

  // Check if we're in a CI environment (most CIs support color)
  if (process.env.CI) {
    return true;
  }

  // Default: assume color support if not explicitly disabled
  // This is more permissive but works better for most modern terminals
  return process.stdout?.isTTY === true;
}

// =============================================================================
// ANSI Color Codes
// =============================================================================

const colorEnabled = supportsColor();

export const RESET = colorEnabled ? '\x1b[0m' : '';
export const BOLD = colorEnabled ? '\x1b[1m' : '';
export const DIM = colorEnabled ? '\x1b[2m' : '';
export const ITALIC = colorEnabled ? '\x1b[3m' : '';
export const UNDERLINE = colorEnabled ? '\x1b[4m' : '';

// Foreground colors
export const RED = colorEnabled ? '\x1b[31m' : '';
export const GREEN = colorEnabled ? '\x1b[32m' : '';
export const YELLOW = colorEnabled ? '\x1b[33m' : '';
export const BLUE = colorEnabled ? '\x1b[34m' : '';
export const MAGENTA = colorEnabled ? '\x1b[35m' : '';
export const CYAN = colorEnabled ? '\x1b[36m' : '';
export const WHITE = colorEnabled ? '\x1b[37m' : '';

// Bright foreground colors (better contrast)
export const BRIGHT_RED = colorEnabled ? '\x1b[91m' : '';
export const BRIGHT_GREEN = colorEnabled ? '\x1b[92m' : '';
export const BRIGHT_YELLOW = colorEnabled ? '\x1b[93m' : '';
export const BRIGHT_BLUE = colorEnabled ? '\x1b[94m' : '';
export const BRIGHT_MAGENTA = colorEnabled ? '\x1b[95m' : '';
export const BRIGHT_CYAN = colorEnabled ? '\x1b[96m' : '';

// Background colors
export const BG_RED = colorEnabled ? '\x1b[41m' : '';
export const BG_GREEN = colorEnabled ? '\x1b[42m' : '';
export const BG_YELLOW = colorEnabled ? '\x1b[43m' : '';
export const BG_BLUE = colorEnabled ? '\x1b[44m' : '';

// =============================================================================
// Severity Colors (Consistent scheme)
// =============================================================================

/**
 * Get color for severity level with improved contrast.
 *
 * Color scheme:
 * - Critical: Bright red with bold (high visibility)
 * - High: Red (clear warning)
 * - Medium: Yellow (attention needed)
 * - Low: Cyan (informational)
 * - Unknown: Dim (neutral)
 */
export function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return BOLD + BRIGHT_RED;
    case 'high':
      return RED;
    case 'medium':
      return YELLOW;
    case 'low':
      return CYAN;
    default:
      return DIM;
  }
}

/**
 * Get background color for severity level (for highlights).
 */
export function severityBgColor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return BG_RED;
    case 'high':
      return BG_RED;
    case 'medium':
      return BG_YELLOW;
    case 'low':
      return BG_BLUE;
    default:
      return '';
  }
}

/**
 * Get severity display label with color.
 */
export function severityLabel(severity: Severity): string {
  const color = severityColor(severity);
  const label = severity.toUpperCase();
  return `${color}${label}${RESET}`;
}

// =============================================================================
// Status Colors
// =============================================================================

/**
 * Get color for status indicators.
 */
export function statusColor(ok: boolean): string {
  return ok ? GREEN : RED;
}

/**
 * Get icon for status.
 */
export function statusIcon(ok: boolean): string {
  return ok ? '✓' : '✗';
}

/**
 * Get colored status string.
 */
export function statusText(ok: boolean, text: string): string {
  const color = statusColor(ok);
  const icon = statusIcon(ok);
  return `${color}${icon} ${text}${RESET}`;
}

// =============================================================================
// Box Drawing & Formatting
// =============================================================================

/**
 * Create a horizontal line.
 */
export function horizontalLine(char: string = '─', length: number = 50): string {
  return char.repeat(length);
}

/**
 * Create a box around text.
 */
export function box(text: string, style: 'single' | 'double' | 'bold' = 'single'): string {
  const chars = {
    single: { tl: '┌', tr: '┐', bl: '└', br: '┘', h: '─', v: '│' },
    double: { tl: '╔', tr: '╗', bl: '╚', br: '╝', h: '═', v: '║' },
    bold: { tl: '┏', tr: '┓', bl: '┗', br: '┛', h: '━', v: '┃' },
  }[style];

  const lines = text.split('\n');
  const maxWidth = Math.max(...lines.map(l => l.length));
  
  const top = `${chars.tl}${chars.h.repeat(maxWidth + 2)}${chars.tr}`;
  const bottom = `${chars.bl}${chars.h.repeat(maxWidth + 2)}${chars.br}`;
  const middle = lines.map(l => `${chars.v} ${l.padEnd(maxWidth)} ${chars.v}`).join('\n');
  
  return `${top}\n${middle}\n${bottom}`;
}

/**
 * Create a section header.
 */
export function sectionHeader(title: string): string {
  return `\n${BOLD}${horizontalLine('═')}${RESET}\n${BOLD}  ${title}${RESET}\n${BOLD}${horizontalLine('═')}${RESET}`;
}

/**
 * Create a subsection header.
 */
export function subsectionHeader(title: string): string {
  return `\n${BOLD}${title}${RESET}\n${horizontalLine('─', Math.min(title.length + 4, 40))}`;
}

// =============================================================================
// Indentation Helpers
// =============================================================================

/**
 * Indent text by specified number of spaces.
 */
export function indent(text: string, spaces: number = 2): string {
  const prefix = ' '.repeat(spaces);
  return text.split('\n').map(line => prefix + line).join('\n');
}

/**
 * Create a nested list item.
 */
export function listItem(text: string, level: number = 0): string {
  const prefix = '  '.repeat(level);
  const bullet = level === 0 ? '•' : level === 1 ? '├─' : '└─';
  return `${prefix}${bullet} ${text}`;
}

// =============================================================================
// Progress Indicators
// =============================================================================

/**
 * Create a spinner character for animations.
 */
export function spinnerChar(frame: number): string {
  const chars = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  return chars[frame % chars.length] || '⠋'; // fallback to first character if somehow undefined
}

/**
 * Create a progress bar.
 */
export function progressBar(
  current: number,
  total: number,
  width: number = 20,
  filledChar: string = '█',
  emptyChar: string = '░'
): string {
  const percent = total > 0 ? Math.round((current / total) * 100) : 0;
  const filled = Math.round((current / total) * width);
  const empty = width - filled;
  
  const bar = filledChar.repeat(filled) + emptyChar.repeat(empty);
  return `[${bar}] ${percent}%`;
}

// =============================================================================
// Error Formatting
// =============================================================================

/**
 * Format an error message with clear boundaries.
 */
export function formatError(title: string, details: string[]): string {
  const lines: string[] = [];
  
  lines.push(`${BOLD}${RED}╔══════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${RED}║  ERROR: ${title.padEnd(38)}║${RESET}`);
  lines.push(`${BOLD}${RED}╚══════════════════════════════════════════════╝${RESET}`);
  
  for (const detail of details) {
    lines.push(`${RED}  • ${detail}${RESET}`);
  }
  
  return lines.join('\n');
}

/**
 * Format a warning message.
 */
export function formatWarning(title: string, details: string[]): string {
  const lines: string[] = [];
  
  lines.push(`${BOLD}${YELLOW}╔══════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${YELLOW}║  WARNING: ${title.padEnd(37)}║${RESET}`);
  lines.push(`${BOLD}${YELLOW}╚══════════════════════════════════════════════╝${RESET}`);
  
  for (const detail of details) {
    lines.push(`${YELLOW}  • ${detail}${RESET}`);
  }
  
  return lines.join('\n');
}

/**
 * Format a success message.
 */
export function formatSuccess(title: string, details: string[] = []): string {
  const lines: string[] = [];
  
  lines.push(`${BOLD}${GREEN}╔══════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}${GREEN}║  ✓ ${title.padEnd(43)}║${RESET}`);
  lines.push(`${BOLD}${GREEN}╚══════════════════════════════════════════════╝${RESET}`);
  
  for (const detail of details) {
    lines.push(`${GREEN}  • ${detail}${RESET}`);
  }
  
  return lines.join('\n');
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Truncate text to specified length with ellipsis.
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength - 3) + '...';
}

/**
 * Pad text to specified length.
 */
export function pad(text: string, length: number, char: string = ' '): string {
  return text.padEnd(length, char);
}

/**
 * Center text in specified width.
 */
export function center(text: string, width: number): string {
  const padding = Math.max(0, width - text.length);
  const leftPad = Math.floor(padding / 2);
  const rightPad = padding - leftPad;
  return ' '.repeat(leftPad) + text + ' '.repeat(rightPad);
}