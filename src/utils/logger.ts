const PREFIX = "[pnpm-audit]";

export const logger = {
  info: (msg: string) => console.log(`${PREFIX} ${msg}`),
  warn: (msg: string) => console.warn(`${PREFIX}[warn] ${msg}`),
  error: (msg: string) => console.error(`${PREFIX}[error] ${msg}`),
};
