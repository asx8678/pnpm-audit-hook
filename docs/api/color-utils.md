# Color Utilities

> Terminal color and formatting utilities for building rich CLI output.

## Overview

The color utilities module provides consistent, accessible terminal formatting for pnpm-audit-hook's CLI output. It includes color detection, severity formatting, and layout helpers.

## Import

```typescript
import {
  // Color detection
  supportsColor,

  // Severity formatting
  severityColor,
  severityBgColor,
  severityLabel,

  // Status formatting
  statusColor,
  statusIcon,
  statusText,

  // Layout helpers
  horizontalLine,
  box,
  sectionHeader,
  subsectionHeader,
  indent,
  listItem,

  // Progress indicators
  spinnerChar,
  progressBar,

  // Message formatting
  formatError,
  formatWarning,
  formatSuccess,

  // Text utilities
  truncate,
  pad,
  center,

  // ANSI constants
  RESET, BOLD, DIM, ITALIC, UNDERLINE,
  RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE,
  BRIGHT_RED, BRIGHT_GREEN, BRIGHT_YELLOW, BRIGHT_BLUE,
  BRIGHT_MAGENTA, BRIGHT_CYAN,
  BG_RED, BG_GREEN, BG_YELLOW, BG_BLUE,

  // Constants
  SEVERITY_ORDER,
} from 'pnpm-audit-hook';
```

---

## Color Detection

### `supportsColor()`

Detects if the terminal supports color output.

```typescript
function supportsColor(): boolean
```

**Checks:**
- `NO_COLOR` — Disables color ([no-color.org](https://no-color.org))
- `FORCE_COLOR` — Enables/disables color (0 = off, 1+ = on)
- `COLORTERM` — `truecolor` or `24bit` enables advanced colors
- `TERM` — Checked for `color` or `256color`

---

## Severity Formatting

### `severityColor(severity)`

Returns the ANSI color code for a severity level.

```typescript
function severityColor(severity: Severity): string
```

| Severity | Color |
|----------|-------|
| `critical` | Bright Red |
| `high` | Red |
| `medium` | Yellow |
| `low` | Green |
| `unknown` | White |

**Example:**
```typescript
const text = `${severityColor('critical')}CRITICAL${RESET}`;
// → "\x1b[91mCRITICAL\x1b[0m"
```

---

### `severityBgColor(severity)`

Returns the ANSI background color code for a severity level.

```typescript
function severityBgColor(severity: Severity): string
```

| Severity | Background Color |
|----------|------------------|
| `critical` | Bright Red |
| `high` | Red |
| `medium` | Yellow |
| `low` | Green |
| `unknown` | Default |

---

### `severityLabel(severity)`

Returns an uppercase label for a severity level.

```typescript
function severityLabel(severity: Severity): string
```

**Example:**
```typescript
severityLabel('critical');  // 'CRITICAL'
severityLabel('high');      // 'HIGH'
severityLabel('medium');    // 'MEDIUM'
```

---

## Status Formatting

### `statusColor(ok)`

Returns green for success, red for failure.

```typescript
function statusColor(ok: boolean): string
```

---

### `statusIcon(ok)`

Returns a checkmark or cross icon.

```typescript
function statusIcon(ok: boolean): string
```

| Input | Output |
|-------|--------|
| `true` | `✓` |
| `false` | `✗` |

---

### `statusText(ok, text)`

Wraps text with the appropriate status color.

```typescript
function statusText(ok: boolean, text: string): string
```

---

## Layout Helpers

### `horizontalLine(char, length)`

Creates a horizontal line.

```typescript
function horizontalLine(char: string = '─', length: number = 50): string
```

**Example:**
```typescript
horizontalLine();         // '──────────────────────────────────────────────────'
horizontalLine('=', 30);  // '=============================='
```

---

### `box(text, style)`

Wraps text in a box.

```typescript
function box(text: string, style: 'single' | 'double' | 'bold' = 'single'): string
```

**Example:**
```typescript
box('Hello', 'single');
// ┌───────┐
// │ Hello │
// └───────┘

box('Title', 'double');
// ╔═════════╗
// ║  Title  ║
// ╚═════════╝
```

---

### `sectionHeader(title)`

Creates a section header with line.

```typescript
function sectionHeader(title: string): string
```

**Example:**
```typescript
sectionHeader('Summary');
// Summary
// ─────────────────────────────
```

---

### `subsectionHeader(title)`

Creates a subsection header.

```typescript
function subsectionHeader(title: string): string
```

---

### `indent(text, spaces)`

Indents text by the specified number of spaces.

```typescript
function indent(text: string, spaces: number = 2): string
```

---

### `listItem(text, level)`

Creates a formatted list item with bullet.

```typescript
function listItem(text: string, level: number = 0): string
```

**Example:**
```typescript
listItem('First item');     // '  • First item'
listItem('Nested', 1);      // '    • Nested'
```

---

## Progress Indicators

### `spinnerChar(frame)`

Returns a spinner character for the given animation frame.

```typescript
function spinnerChar(frame: number): string
```

**Characters:** `⠋`, `⠙`, `⠹`, `⠸`, `⠼`, `⠴`, `⠦`, `⠧`, `⠇`, `⠏`

---

### `progressBar(progress, width, filled, empty)`

Creates a progress bar.

```typescript
function progressBar(
  progress: number,
  width?: number,
  filled?: string,
  empty?: string
): string
```

**Example:**
```typescript
progressBar(0.5, 20, '█', '░');
// '██████████░░░░░░░░░░'
```

---

## Message Formatting

### `formatError(title, details)`

Formats an error message box.

```typescript
function formatError(title: string, details: string[]): string
```

**Example:**
```typescript
formatError('Blocked', ['CVE-2021-44228 found']);
// ┌─ ✗ Blocked ─────────────────────┐
// │ CVE-2021-44228 found             │
// └──────────────────────────────────┘
```

---

### `formatWarning(title, details)`

Formats a warning message box.

```typescript
function formatWarning(title: string, details: string[]): string
```

---

### `formatSuccess(title, details)`

Formats a success message box.

```typescript
function formatSuccess(title: string, details: string[] = []): string
```

---

## Text Utilities

### `truncate(text, maxLength)`

Truncates text with ellipsis if too long.

```typescript
function truncate(text: string, maxLength: number): string
```

---

### `pad(text, length, char)`

Pads text to the specified length.

```typescript
function pad(text: string, length: number, char: string = ' '): string
```

---

### `center(text, width)`

Centers text within the specified width.

```typescript
function center(text: string, width: number): string
```

---

## ANSI Constants

### Style Constants

| Constant | Code | Description |
|----------|------|-------------|
| `RESET` | `\x1b[0m` | Reset all styles |
| `BOLD` | `\x1b[1m` | Bold text |
| `DIM` | `\x1b[2m` | Dim text |
| `ITALIC` | `\x1b[3m` | Italic text |
| `UNDERLINE` | `\x1b[4m` | Underlined text |

### Foreground Colors

| Constant | Code |
|----------|------|
| `RED` | `\x1b[31m` |
| `GREEN` | `\x1b[32m` |
| `YELLOW` | `\x1b[33m` |
| `BLUE` | `\x1b[34m` |
| `MAGENTA` | `\x1b[35m` |
| `CYAN` | `\x1b[36m` |
| `WHITE` | `\x1b[37m` |

### Bright Foreground Colors

| Constant | Code |
|----------|------|
| `BRIGHT_RED` | `\x1b[91m` |
| `BRIGHT_GREEN` | `\x1b[92m` |
| `BRIGHT_YELLOW` | `\x1b[93m` |
| `BRIGHT_BLUE` | `\x1b[94m` |
| `BRIGHT_MAGENTA` | `\x1b[95m` |
| `BRIGHT_CYAN` | `\x1b[96m` |

### Background Colors

| Constant | Code |
|----------|------|
| `BG_RED` | `\x1b[41m` |
| `BG_GREEN` | `\x1b[42m` |
| `BG_YELLOW` | `\x1b[43m` |
| `BG_BLUE` | `\x1b[44m` |

### Constants

| Constant | Type | Description |
|----------|------|-------------|
| `SEVERITY_ORDER` | `Severity[]` | `['critical', 'high', 'medium', 'low', 'unknown']` |

---

## Usage Examples

### Custom Severity Report

```typescript
import {
  severityColor,
  severityLabel,
  sectionHeader,
  indent,
  horizontalLine,
  BOLD,
  RESET,
} from 'pnpm-audit-hook';

function printSeverityReport(findings: VulnerabilityFinding[]) {
  const bySeverity = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    medium: findings.filter(f => f.severity === 'medium'),
    low: findings.filter(f => f.severity === 'low'),
  };

  console.log(sectionHeader('Vulnerability Report'));

  for (const [severity, items] of Object.entries(bySeverity)) {
    if (items.length === 0) continue;

    const color = severityColor(severity as Severity);
    const label = severityLabel(severity as Severity);

    console.log(`\n${color}${BOLD}${label}${RESET} (${items.length})`);
    console.log(horizontalLine('─', 40));

    for (const item of items) {
      console.log(indent(`• ${item.packageName}@${item.packageVersion}`));
    }
  }
}
```

### Dashboard Layout

```typescript
import {
  box,
  sectionHeader,
  horizontalLine,
  indent,
  listItem,
  pad,
  center,
  BOLD,
  RESET,
  CYAN,
} from 'pnpm-audit-hook';

function renderDashboard(data: DashboardData) {
  const width = 60;
  const lines: string[] = [];

  // Title
  lines.push(box(center('Security Dashboard', width - 4), 'double'));
  lines.push('');

  // Summary
  lines.push(sectionHeader('Summary'));
  lines.push(listItem(`Packages: ${data.totalPackages}`));
  lines.push(listItem(`Findings: ${data.totalFindings}`));
  lines.push(listItem(`Blocked: ${data.blocked ? 'Yes' : 'No'}`));
  lines.push('');

  // Source Status
  lines.push(sectionHeader('Sources'));
  for (const [name, status] of Object.entries(data.sources)) {
    const icon = status.ok ? '✓' : '✗';
    const color = status.ok ? '\x1b[32m' : '\x1b[31m';
    lines.push(listItem(`${color}${icon}${RESET} ${name}`));
  }

  return lines.join('\n');
}
```
