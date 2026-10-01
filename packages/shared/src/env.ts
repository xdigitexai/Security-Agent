import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  SESSION_SECRET: z.string().min(32).default('development-only-change-me-32-bytes!!'),
  APP_URL: z.string().url().default('http://localhost:3000'),
  WORKER_CONCURRENCY: z.coerce.number().int().min(1).max(10).default(2),
  MAX_SCAN_DURATION_MS: z.coerce.number().int().max(30*60*1000).default(30*60*1000),
  MAX_PAGES: z.coerce.number().int().max(500).default(500),
  MAX_REQUESTS: z.coerce.number().int().max(5000).default(5000),
  MAX_RESPONSE_SIZE: z.coerce.number().int().max(5*1024*1024).default(5*1024*1024),
  MAX_CONCURRENT_REQUESTS: z.coerce.number().int().max(5).default(5),
  MAX_REQUESTS_PER_SECOND: z.coerce.number().int().max(5).default(5),
  SCAN_USER_AGENT: z.string().default('Xdigitex-Security-Agent/0.2 (+authorized-security-testing)')
});
export const env = () => schema.parse(process.env);
