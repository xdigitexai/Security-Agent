import { createHash } from 'node:crypto';
export function findingFingerprint(input: {checkId:string; affectedUrl:string; method?:string; parameter?:string}) {
  const normalized = [input.checkId, input.method?.toUpperCase() ?? 'GET', input.affectedUrl.replace(/#.*$/,''), input.parameter ?? ''].join('|');
  return createHash('sha256').update(normalized).digest('hex');
}
