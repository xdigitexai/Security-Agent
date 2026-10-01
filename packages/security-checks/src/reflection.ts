import type { SecurityCheck } from '@xdigitex/scanner-core';
export const reflectionCheck:SecurityCheck={id:'xss.reflection-marker',name:'Benign reflection test',category:'XSS',async run(ctx){
 const marker='XDIGITEX_REFLECT_7f31'; const out=[];
 for(const ep of ctx.endpoints.filter(e=>e.method==='GET').slice(0,30)){
   const u=new URL(ep.url); const candidate=(ep.parameters||[])[0] || [...u.searchParams.keys()][0]; if(!candidate)continue; u.searchParams.set(candidate,marker);
   const r=await ctx.http.request(u.toString()); if(r.body.includes(marker)) out.push({checkId:this.id,title:'Reflected input detected',description:`A benign marker supplied in parameter ${candidate} was reflected in the response. No executable payload was used.`,category:'XSS',severity:'LOW',confidence:'NEEDS_REVIEW',affectedUrl:ep.url,method:'GET',parameter:candidate,impact:'Reflection can become XSS if output encoding is missing in an executable context; this check does not claim exploitability.',remediation:'Apply context-appropriate output encoding and validate/sanitize untrusted input.',evidence:[r.evidence]});
 } return out;
}};
