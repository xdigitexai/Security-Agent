import { describe,it,expect } from 'vitest';
import { redactHeaders, redactText } from './redaction';
describe('redaction',()=>{
  it('redacts auth and cookie headers',()=>expect(redactHeaders({Authorization:'Bearer abcdefghijk',Cookie:'sid=secret',Accept:'text/html'})).toEqual({Authorization:'[REDACTED]',Cookie:'[REDACTED]',Accept:'text/html'}));
  it('redacts secret values in text',()=>expect(redactText('api_key=supersecretvalue')).not.toContain('supersecretvalue'));
});
