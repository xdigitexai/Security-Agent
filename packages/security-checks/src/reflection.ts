import type { SecurityCheck } from '@xdigitex/scanner-core';

function reflectionContext(body:string,marker:string,contentType:string){
  if(/json/i.test(contentType))return {label:'JSON response',severity:'INFORMATIONAL' as const};
  const i=body.indexOf(marker);if(i<0)return {label:'response body',severity:'LOW' as const};
  const before=body.slice(0,i).toLowerCase();const scriptOpen=before.lastIndexOf('<script');const scriptClose=before.lastIndexOf('</script>');
  if(scriptOpen>scriptClose)return {label:'script block',severity:'MEDIUM' as const};
  const around=body.slice(Math.max(0,i-180),Math.min(body.length,i+180));
  if(/(?:href|src|value|content|data-[\w-]+|on\w+)\s*=\s*["'][^"']*$/i.test(around.slice(0,around.indexOf(marker))))return {label:'HTML attribute',severity:'LOW' as const};
  return {label:'HTML/text response',severity:'LOW' as const};
}

export const reflectionCheck:SecurityCheck={id:'xss.reflection-marker',name:'Benign reflected-input mapping',category:'XSS',async run(ctx){
  const out=[];let probes=0;const emitted=new Set<string>();
  for(const ep of ctx.endpoints.filter(e=>e.method==='GET').slice(0,60)){
    if(await ctx.isCanceled()||probes>=80)break;let u:URL;try{u=new URL(ep.url);}catch{continue;}
    const params=[...new Set([...(ep.parameters||[]),...u.searchParams.keys()])].filter(Boolean).slice(0,5);
    for(const parameter of params){
      if(await ctx.isCanceled()||probes++>=80)break;const marker=`XDIGITEX_REFLECT_${probes.toString(36)}_7f31`;const candidate=new URL(u);candidate.searchParams.set(parameter,marker);
      let r;try{r=await ctx.http.request(candidate.toString());}catch{continue;}if(!r.body.includes(marker))continue;
      const key=`${ep.url}:${parameter}`;if(emitted.has(key))continue;emitted.add(key);const where=reflectionContext(r.body,marker,r.headers['content-type']||'');
      out.push({checkId:this.id,title:where.label==='script block'?'Input reflected inside script context':'Reflected input detected',description:`A benign non-executable marker supplied in parameter ${parameter} was reflected into a ${where.label}. This maps an output path but does not claim executable XSS.`,category:'XSS',severity:where.severity,confidence:'NEEDS_REVIEW',affectedUrl:ep.url,method:'GET',parameter,impact:where.label==='script block'?'Reflection into script context can become exploitable if attacker-controlled characters are not correctly encoded for JavaScript. Manual context-aware validation is warranted.':'Reflected input can become XSS when dangerous characters reach an executable HTML/JavaScript context without correct output encoding.',remediation:'Apply context-specific output encoding at the final output sink, prefer safe DOM/text APIs, and manually verify the exact reflection context before classifying exploitability.',evidence:[{...r.evidence,responseExcerpt:`Benign marker reflected in ${where.label}; surrounding application content omitted.`}]});
    }
  }
  return out;
}};
