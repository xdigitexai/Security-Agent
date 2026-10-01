import type { SecurityCheck } from '@xdigitex/scanner-core';
import { maskSecret } from '@xdigitex/shared';

type Pattern={name:string;re:RegExp;severity:'HIGH'|'MEDIUM';confidence:'CONFIRMED'|'HIGH'|'NEEDS_REVIEW';capture?:number};
const patterns:Pattern[]=[
  {name:'Private key',re:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,severity:'HIGH',confidence:'CONFIRMED'},
  {name:'Database connection URL',re:/(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>]{8,}/i,severity:'HIGH',confidence:'HIGH'},
  {name:'AWS access key identifier',re:/\b(AKIA[0-9A-Z]{16})\b/,severity:'HIGH',confidence:'HIGH',capture:1},
  {name:'GitHub personal access token',re:/\b(gh[pousr]_[A-Za-z0-9]{30,255})\b/,severity:'HIGH',confidence:'HIGH',capture:1},
  {name:'Stripe secret key',re:/\b(sk_(?:live|test)_[A-Za-z0-9]{16,})\b/,severity:'HIGH',confidence:'HIGH',capture:1},
  {name:'Paystack secret key',re:/\b(sk_(?:live|test)_[A-Za-z0-9]{20,})\b/,severity:'HIGH',confidence:'HIGH',capture:1},
  {name:'Flutterwave secret key',re:/\b(FLWSECK-[A-Za-z0-9_-]{16,})\b/i,severity:'HIGH',confidence:'HIGH',capture:1},
  {name:'Slack token',re:/\b(xox[baprs]-[A-Za-z0-9-]{20,})\b/,severity:'HIGH',confidence:'HIGH',capture:1},
  {name:'JWT-like token',re:/\b(eyJ[a-zA-Z0-9_-]{8,}\.eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,})\b/,severity:'MEDIUM',confidence:'NEEDS_REVIEW',capture:1},
  {name:'Bearer token literal',re:/\bBearer\s+([A-Za-z0-9._~+\/-]{20,})/i,severity:'HIGH',confidence:'NEEDS_REVIEW',capture:1},
  {name:'Generic secret assignment',re:/(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|secret[_-]?key|password)\s*[:=]\s*["']([^"']{16,})["']/i,severity:'MEDIUM',confidence:'NEEDS_REVIEW',capture:1}
];

export const secretCheck:SecurityCheck={id:'secrets.public',name:'Public secret and credential exposure',category:'Secret Exposure',async run(ctx){
  const assetHost=(()=>{try{return new URL(ctx.assetUrl).hostname;}catch{return '';}})();
  const sameHost=(s:string)=>{try{return new URL(s).hostname===assetHost;}catch{return false;}};
  const urls=[...new Set([
    ctx.assetUrl,
    ...ctx.pages.filter(sameHost),
    ...ctx.scripts.filter(sameHost),
    ...ctx.endpoints.filter(e=>['GET','HEAD'].includes(e.method)).map(e=>e.url).filter(sameHost)
  ])].slice(0,180);
  const out=[];const emitted=new Set<string>();
  for(const url of urls){
    if(await ctx.isCanceled())break;let r;try{r=await ctx.http.request(url);}catch{continue;}
    for(const p of patterns){
      const m=r.body.match(p.re);if(!m)continue;const raw=m[p.capture||0]||m[0];const key=`${p.name}:${r.url}`;if(emitted.has(key))continue;emitted.add(key);
      const sample=maskSecret(raw.slice(0,160));
      out.push({checkId:this.id,title:`Public ${p.name} pattern detected`,description:`A public first-party response contains a pattern consistent with ${p.name.toLowerCase()}. The suspected value is redacted and must be validated before rotation decisions are made.`,category:this.category,severity:p.severity,confidence:p.confidence,affectedUrl:r.url,method:'GET',impact:'If the detected value is a live credential, unauthorized parties may gain access to associated services, data or infrastructure.',remediation:'Remove secrets from public responses and bundles, validate whether the value is active, rotate exposed credentials, review access logs, and move secrets to server-side secret storage.',evidence:[{...r.evidence,responseExcerpt:`Detected redacted ${p.name}: ${sample}`} ]});
    }
  }
  return out;
}};
