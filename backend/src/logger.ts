export interface Logger {
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

const levels = { debug: 10, info: 20, warn: 30, error: 40 } as const;

export function createLogger(minimum: keyof typeof levels): Logger {
  const write = (level: keyof typeof levels, event: string, fields: Record<string, unknown> = {}) => {
    if (levels[level] < levels[minimum]) return;
    // Callers pass identifiers such as request IDs only; request bodies, query strings,
    // auth headers, email addresses, license keys, and Stripe objects are never logged.
    const line = JSON.stringify({
      level,
      event,
      timestamp: new Date().toISOString(),
      ...fields,
    });
    if (level === 'error') console.error(line);
    else if (level === 'warn') console.warn(line);
    else console.log(line);
  };
  return {
    debug: (event, fields) => write('debug', event, fields),
    info: (event, fields) => write('info', event, fields),
    warn: (event, fields) => write('warn', event, fields),
    error: (event, fields) => write('error', event, fields),
  };
}

export const silentLogger: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};
