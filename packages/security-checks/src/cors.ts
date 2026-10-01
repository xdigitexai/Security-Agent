import type { SecurityCheck } from '@xdigitex/scanner-core';

export const corsCheck:SecurityCheck={id:'cors.origin',name:'CORS behavior across application surfaces',category:'CORS',async run(ctx){
  const out=[];const arbitrary='https://xdigitex-invalid.example';
  const urls=[...new Set([
    ctx.assetUrl,
    ...ctx.applicationMap.apiUrls,
    ...ctx.applicationMap.authUrls,
    ...ctx.applicationMap.graphqlUrls,
    ...ctx.applicationMap.paymentUrls,
    ...ctx.applicationMap.surfaces.filter(s=>s.kind==='ACCOUNT'&&['GET','HEAD'].includes(s.method)).map(s=>s.url)
  ])].slice(0,30);
  for(const url of urls){
    if(await ctx.isCanceled())break;let r;
    try{r=await ctx.http.request(url,{headers:{Origin:arbitrary}});}catch{continue;}
    const aco=(r.headers['access-control-allow-origin']||'').trim();const acc=(r.headers['access-control-allow-credentials']||'').toLowerCase();
    if(aco===arbitrary&&acc==='true')out.push({checkId:this.id,title:'Credentialed arbitrary CORS origin accepted',description:'A first-party endpoint reflected an untrusted Origin while allowing credentials.',category:this.category,severity:'HIGH',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:'If authenticated responses contain sensitive data, a malicious site may be able to read them using the victim browser.',remediation:'Use a strict server-side origin allowlist and never reflect arbitrary Origin values when credentials are enabled.',evidence:[r.evidence]});
    else if(aco===arbitrary)out.push({checkId:this.id,title:'Arbitrary CORS origin reflected',description:'The endpoint reflects an untrusted Origin. Credentials were not observed on this response, so impact depends on endpoint sensitivity and authentication design.',category:this.category,severity:'MEDIUM',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:'Public or token-bearing API responses may become readable cross-origin if other controls permit the request.',remediation:'Replace dynamic Origin reflection with an explicit allowlist and review all API authentication assumptions.',evidence:[r.evidence]});
    else if(aco==='*'&&acc==='true')out.push({checkId:this.id,title:'Inconsistent credentialed wildcard CORS',description:'The response combines wildcard ACAO with credentials.',category:this.category,severity:'LOW',confidence:'CONFIRMED',affectedUrl:r.url,method:'GET',impact:'Browsers reject this combination, but it indicates an unsafe or confused CORS policy.',remediation:'Use vetted explicit origins and align credential settings.',evidence:[r.evidence]});
    try{
      const nul=await ctx.http.request(url,{headers:{Origin:'null'}});const naco=(nul.headers['access-control-allow-origin']||'').trim();const ncred=(nul.headers['access-control-allow-credentials']||'').toLowerCase();
      if(naco==='null'&&ncred==='true')out.push({checkId:this.id,title:'Credentialed null Origin trusted',description:'The endpoint allows the special null Origin together with credentials.',category:this.category,severity:'MEDIUM',confidence:'HIGH',affectedUrl:nul.url,method:'GET',impact:'Sandboxed documents and some local/file contexts can emit Origin: null, which may bypass assumptions in weak origin allowlists.',remediation:'Do not trust null Origin for credentialed sensitive endpoints unless there is a narrowly justified requirement.',evidence:[nul.evidence]});
    }catch{}
  }
  return out;
}};
