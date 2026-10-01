import type { SecurityCheck } from '@xdigitex/scanner-core';
const names=/^(next|url|redirect|redirect_uri|return|return_to|continue)$/i;
export const redirectCheck:SecurityCheck={id:'redirect.safe-marker',name:'Open redirect',category:'Open Redirect',async run(ctx){
 const out=[]; const external='https://example.invalid/xdigitex-marker';
 for(const ep of ctx.endpoints.filter(e=>e.method==='GET').slice(0,30)){ const u=new URL(ep.url); const p=[...(ep.parameters||[]),...u.searchParams.keys()].find(x=>names.test(x)); if(!p)continue; u.searchParams.set(p,external);
   try{ await ctx.http.request(u.toString()); }catch(e){ if(String(e).includes('SCOPE_HOST_BLOCKED')) out.push({checkId:this.id,title:'Potential external open redirect',description:`Parameter ${p} caused a redirect toward an external host during a benign marker test. The scanner blocked following it by scope policy.`,category:this.category,severity:'MEDIUM',confidence:'HIGH',affectedUrl:ep.url,method:'GET',parameter:p,impact:'Open redirects can support phishing and token leakage in some authentication flows.',remediation:'Only allow relative redirects or validate destinations against an explicit same-origin allowlist.',evidence:[]}); }
 } return out;
}};
