import { redis } from './queue';

export async function enforceRateLimit(bucket: string, limit: number, windowSeconds: number) {
  const key = `rl:${bucket}`;
  const count = await redis.incr(key);
  if (count === 1) await redis.expire(key, windowSeconds);
  if (count > limit) throw new Error('RATE_LIMITED');
}
