import { describe,it,expect } from 'vitest';
const rank={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFORMATIONAL:1};
describe('severity semantics',()=>it('keeps informational below low',()=>expect(rank.INFORMATIONAL).toBeLessThan(rank.LOW)));
