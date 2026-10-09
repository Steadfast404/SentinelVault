/**
 * Redacts sensitive information from logs.
 */
function redact(data: unknown): unknown {
  if (typeof data !== "object" || data === null) return data;

  if (Array.isArray(data)) {
    return data.map((item) => redact(item));
  }

  const redacted = { ...data } as Record<string, unknown>;
  for (const key in redacted) {
    if (Object.prototype.hasOwnProperty.call(redacted, key)) {
      const value = redacted[key];
      if (typeof value === "object" && value !== null) {
        redacted[key] = redact(value);
      } else if (
        typeof key === "string" &&
        /password|token|secret|key/i.test(key)
      ) {
        redacted[key] = "[REDACTED]";
      }
    }
  }
  return redacted;
}

export const logger = {
  info: (message: string, data?: unknown) => {
    // eslint-disable-next-line no-console
    console.info(message, data ? redact(data) : "");
  },
  warn: (message: string, data?: unknown) => {
    // eslint-disable-next-line no-console
    console.warn(message, data ? redact(data) : "");
  },
  error: (message: string, error?: unknown) => {
    // eslint-disable-next-line no-console
    console.error(message, error ? redact(error) : "");
  },
};
