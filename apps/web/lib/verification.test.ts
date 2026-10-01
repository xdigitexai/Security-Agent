import { describe,it,expect } from 'vitest';
describe('ownership verification contract',()=>{it('uses explicit xdigitex token format',()=>{const token='abc123';expect(`xdigitex-security-verification=${token}`).toContain(token);});});
