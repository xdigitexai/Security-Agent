const SENSITIVE_KEYS = /^(authorization|cookie|set-cookie|x-api-key|api-key|password|passwd|token|access_token|refresh_token|secret)$/i;
const SECRET_PATTERNS = [
  /(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
  /((?:api[_-]?key|secret|token|password)\s*[:=]\s*["']?)[^\s"']{6,}/gi,
  /(postgres(?:ql)?:\/\/[^:\s]+:)[^@\s]+(@)/gi,
  /(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)[\s\S]*?(-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)/g
];

export function maskSecret(value: string): string {
  if (value.length <= 8) return '[REDACTED]';
  return `${value.slice(0,4)}…${value.slice(-4)} [REDACTED]`;
}

export function redactText(input?: string | null): string | undefined {
  if (!input) return input ?? undefined;
  let out = input;
  for (const re of SECRET_PATTERNS) out = out.replace(re, (_m, a, b) => `${a ?? ''}[REDACTED]${b ?? ''}`);
  return out.length > 4096 ? `${out.slice(0,4096)}…[TRUNCATED]` : out;
}

export function redactHeaders(headers: Record<string,string>): Record<string,string> {
  return Object.fromEntries(Object.entries(headers).map(([k,v]) => [k, SENSITIVE_KEYS.test(k) ? '[REDACTED]' : redactText(v) ?? '']));
}
