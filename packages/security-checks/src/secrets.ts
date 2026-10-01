import type { SecurityCheck } from '@xdigitex/scanner-core';
import { maskSecret } from '@xdigitex/shared';
const patterns=[
 ['Private key',/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
 ['Database URL',/(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"']+/i],
 ['JWT-like token',/eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}/],
 ['Likely API key',/(?:api[_-]?key|secret|token)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']/i]
] as const;
export const secretCheck:SecurityCheck={id:'secrets.public',name:'Public secret exposure',category:'Secret Exposure',async run(ctx){
 const assetHost=(()=>{try{return new URL(ctx.assetUrl).hostname;}catch{return '';}})(); const sameHost=(s:string)=>{try{return new URL(s).hostname===assetHost;}catch{return false;}}; const urls=[...new Set([ctx.assetUrl,...ctx.pages.filter(sameHost),...ctx.scripts.filter(sameHost)])].slice(0,100); const out=[];
 for(const url of urls){ const r=await ctx.http.request(url).catch(()=>null); if(!r)continue; for(const [name,re] of patterns){ const m=r.body.match(re); if(!m)continue; const sample=maskSecret((m[1]||m[0]).slice(0,128)); out.push({checkId:this.id,title:`Public ${name} pattern detected`,description:`A response contains a pattern consistent with ${name.toLowerCase()}. Stored evidence is redacted.`,category:this.category,severity:name==='Private key'||name==='Database URL'?'HIGH':'MEDIUM',confidence:'NEEDS_REVIEW',affectedUrl:r.url,method:'GET',impact:'If the value is a real active secret, unauthorized parties may gain access to associated systems or data.',remediation:'Remove secrets from public responses, rotate any exposed credential, and move configuration to server-side secret storage.',evidence:[{...r.evidence,responseExcerpt:`Detected redacted sample: ${sample}`} ]}); } }
 return out;
}};
