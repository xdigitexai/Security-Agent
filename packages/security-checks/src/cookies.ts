import type { SecurityCheck } from '@xdigitex/scanner-core';

function splitSetCookie(raw:string){return raw.split(/,(?=\s*[^;=,\s]+=)/).map(v=>v.trim()).filter(Boolean);}
function cookieName(raw:string){return raw.match(/^\s*([^=;\s]+)=/)?.[1]||'unnamed-cookie';}
function sessionLike(name:string){return /(?:session|sess|sid|auth|token|jwt|login|php(?:sessid)?)/i.test(name);}

export const cookieCheck:SecurityCheck={id:'cookies.flags',name:'Cookie and session flag security',category:'Session Security',async run(ctx){
  const out=[];const urls=[...new Set([
    ctx.assetUrl,
    ...ctx.applicationMap.authUrls,
    ...ctx.applicationMap.surfaces.filter(s=>s.kind==='ACCOUNT'&&['GET','HEAD'].includes(s.method)).map(s=>s.url)
  ])].slice(0,25);const emitted=new Set<string>();
  for(const url of urls){
    if(await ctx.isCanceled())break;let r;try{r=await ctx.http.request(url);}catch{continue;}
    const raw=r.headers['set-cookie'];if(!raw)continue;
    for(const cookie of splitSetCookie(raw)){
      const name=cookieName(cookie);const lower=cookie.toLowerCase();const sensitive=sessionLike(name);const keyBase=`${name}:${r.url}`;
      if(r.url.startsWith('https://')&&!lower.includes('; secure')&&!emitted.has(`secure:${keyBase}`)){
        emitted.add(`secure:${keyBase}`);out.push({checkId:this.id,title:`Cookie ${name} missing Secure flag`,description:`The response sets cookie ${name} over HTTPS without the Secure attribute.`,category:this.category,severity:sensitive?'MEDIUM':'LOW',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:sensitive?'A session/authentication cookie could be exposed if a browser is induced to send it over a non-TLS connection.':'The cookie may be transmitted over an insecure connection in downgrade or mixed-scheme scenarios.',remediation:'Mark cookies Secure and enforce HTTPS site-wide.',evidence:[{...r.evidence,responseExcerpt:`Set-Cookie observed for ${name}; cookie value omitted.`}]});
      }
      if(!lower.includes('; httponly')&&!emitted.has(`http:${keyBase}`)){
        emitted.add(`http:${keyBase}`);out.push({checkId:this.id,title:`Cookie ${name} missing HttpOnly flag`,description:`The response sets cookie ${name} without HttpOnly.`,category:this.category,severity:sensitive?'MEDIUM':'LOW',confidence:sensitive?'HIGH':'NEEDS_REVIEW',affectedUrl:r.url,method:'GET',impact:sensitive?'If client-side script execution is compromised, a readable session/authentication cookie may increase account takeover impact.':'JavaScript can read this cookie; impact depends on whether the application intentionally requires client-side access.',remediation:'Mark session and other server-only cookies HttpOnly. Keep JavaScript-readable cookies only where explicitly required.',evidence:[{...r.evidence,responseExcerpt:`Set-Cookie observed for ${name}; cookie value omitted.`}]});
      }
      const sameSite=lower.match(/;\s*samesite\s*=\s*(lax|strict|none)/)?.[1];
      if(sensitive&&!sameSite&&!emitted.has(`same:${keyBase}`)){
        emitted.add(`same:${keyBase}`);out.push({checkId:this.id,title:`Session-like cookie ${name} has no explicit SameSite policy`,description:`A session/authentication-like cookie was set without an explicit SameSite attribute.`,category:this.category,severity:'LOW',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:'Cross-site request behavior depends on browser defaults instead of an application-defined policy, which can weaken CSRF defense consistency.',remediation:'Set an intentional SameSite=Lax or SameSite=Strict policy where compatible; use SameSite=None only when cross-site delivery is required and Secure is enabled.',evidence:[{...r.evidence,responseExcerpt:`Set-Cookie observed for ${name}; cookie value omitted.`}]});
      }
      if(sameSite==='none'&&!lower.includes('; secure')&&!emitted.has(`none:${keyBase}`)){
        emitted.add(`none:${keyBase}`);out.push({checkId:this.id,title:`Cookie ${name} uses SameSite=None without Secure`,description:'The cookie requests cross-site delivery using SameSite=None but is not marked Secure.',category:this.category,severity:'MEDIUM',confidence:'CONFIRMED',affectedUrl:r.url,method:'GET',impact:'Modern browsers may reject the cookie, while inconsistent clients may handle it insecurely.',remediation:'Pair SameSite=None with Secure or choose a stricter SameSite policy.',evidence:[{...r.evidence,responseExcerpt:`Set-Cookie observed for ${name}; cookie value omitted.`}]});
      }
    }
  }
  return out;
}};
