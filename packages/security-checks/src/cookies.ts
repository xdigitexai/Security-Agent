import type { SecurityCheck } from '@xdigitex/scanner-core';
export const cookieCheck:SecurityCheck={id:'cookies.flags',name:'Cookie security',category:'Session Security',async run(ctx){
 const r=await ctx.http.request(ctx.assetUrl); const raw=r.headers['set-cookie']; if(!raw)return[]; const c=raw.toLowerCase(); const out=[];
 if(!c.includes('secure')) out.push({checkId:this.id,title:'Cookie without Secure flag',description:'A cookie was set without the Secure attribute.',category:this.category,severity:'MEDIUM',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:'The cookie may be exposed if transmitted over a non-TLS connection.',remediation:'Mark authentication/session cookies Secure and enforce HTTPS.',evidence:[r.evidence]});
 if(!c.includes('httponly')) out.push({checkId:this.id,title:'Cookie without HttpOnly flag',description:'A cookie was set without HttpOnly.',category:this.category,severity:'LOW',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:'Client-side script can read the cookie, which can increase impact if an XSS flaw exists.',remediation:'Mark session cookies HttpOnly unless JavaScript access is explicitly required.',evidence:[r.evidence]});
 return out;
}};
