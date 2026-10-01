import { NextResponse } from 'next/server';
import type { z } from 'zod';

type Parsed<T> = { ok: true; data: T } | { ok: false; response: NextResponse };

/**
 * Validate user input without turning bad input into a 500.
 *
 * `schema.parse(...)` throws a ZodError, and an unhandled throw inside a route
 * handler becomes an opaque HTTP 500 with no explanation. Invalid form data is
 * normal user input — a too-short password, a malformed email, a missing field —
 * so it should come back as a 400 that names the offending field.
 */
export function parseOrBadRequest<T>(schema: z.ZodType<T>, input: unknown): Parsed<T> {
  const result = schema.safeParse(input);

  if (result.success) return { ok: true, data: result.data };

  const issue = result.error.issues[0];
  const field = issue?.path?.length ? issue.path.join('.') : 'input';
  const message = issue ? `${field}: ${issue.message}` : 'Invalid input';

  return { ok: false, response: new NextResponse(message, { status: 400 }) };
}

/** Read a JSON body without throwing a 500 on malformed input. */
export async function readJson(req: Request): Promise<{ ok: true; data: unknown } | { ok: false; response: NextResponse }> {
  try {
    return { ok: true, data: await req.json() };
  } catch {
    return { ok: false, response: new NextResponse('Request body must be valid JSON.', { status: 400 }) };
  }
}
