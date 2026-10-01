import type { SecurityCheck } from '@xdigitex/scanner-core';

function mapReference(body:string){return body.match(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/)?.[1]?.trim();}
function privateReference(body:string){return body.match(/(?:https?:\/\/)?(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?[^\s"']*/i)?.[0];}

export const clientCheck:SecurityCheck={id:'client.passive',name:'Client-side bundle and source-map inspection',category:'Client-Side Analysis',async run(ctx){
  const out=[];
  for(const url of ctx.scripts.slice(0,80)){
    if(await ctx.isCanceled())break;let r;try{r=await ctx.http.request(url);}catch{continue;}
    if(/\b(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=|document\.write\s*\(/.test(r.body))out.push({checkId:this.id,title:'Potentially unsafe DOM sink present',description:'A public JavaScript resource contains a DOM sink that may become security-sensitive when fed untrusted input. This is a code indicator, not confirmed XSS.',category:'XSS',severity:'INFORMATIONAL',confidence:'NEEDS_REVIEW',affectedUrl:r.url,method:'GET',impact:'If attacker-controlled data reaches this sink without contextual encoding, DOM XSS may become possible.',remediation:'Trace data flow to the sink and use safe DOM APIs or contextual sanitization.',evidence:[r.evidence]});
    const internal=privateReference(r.body);if(internal)out.push({checkId:this.id,title:'Internal network reference exposed in JavaScript',description:'A public JavaScript bundle contains a localhost or private-network reference. The value is reported only as an indicator and not contacted.',category:'Information Disclosure',severity:'LOW',confidence:'HIGH',affectedUrl:r.url,method:'GET',impact:'Internal hostnames or addresses can reveal architecture and environment assumptions useful during reconnaissance.',remediation:'Remove development/internal endpoints from production bundles and inject environment-specific public configuration at build or runtime.',evidence:[{...r.evidence,responseExcerpt:`Private/internal endpoint reference detected and redacted: ${internal.slice(0,60)}…`} ]});
    const ref=mapReference(r.body);if(!ref)continue;
    let mapUrl;try{mapUrl=new URL(ref,r.url);if(mapUrl.hostname!==new URL(ctx.assetUrl).hostname)continue;}catch{continue;}
    try{
      const sm=await ctx.http.request(mapUrl.toString());
      const valid=sm.status===200&&(/"sources"\s*:\s*\[/.test(sm.body)||/"sourcesContent"\s*:\s*\[/.test(sm.body));
      if(valid)out.push({checkId:this.id,title:'Production source map publicly accessible',description:'A JavaScript bundle references a source map and the referenced map is publicly downloadable.',category:'Information Disclosure',severity:'LOW',confidence:'CONFIRMED',affectedUrl:sm.url,method:'GET',impact:'Source maps may reveal original source structure, comments, endpoint names and implementation details that materially improve reconnaissance.',remediation:'Disable public production source maps or publish them only to a private error-monitoring service when source disclosure is not intended.',evidence:[{...sm.evidence,responseExcerpt:'Valid source-map structure confirmed; source content intentionally omitted from stored evidence.'}]});
      else out.push({checkId:this.id,title:'Source map reference present but map not confirmed',description:'A JavaScript bundle contains a sourceMappingURL reference, but the referenced map was not confirmed as a valid public source map.',category:'Information Disclosure',severity:'INFORMATIONAL',confidence:'NEEDS_REVIEW',affectedUrl:r.url,method:'GET',impact:'The reference discloses build metadata but no source disclosure was confirmed.',remediation:'Remove stale sourceMappingURL comments from production bundles if source maps are intentionally private.',evidence:[r.evidence]});
    }catch{out.push({checkId:this.id,title:'Source map reference present but map not confirmed',description:'A JavaScript bundle contains a sourceMappingURL reference, but the referenced map could not be fetched safely.',category:'Information Disclosure',severity:'INFORMATIONAL',confidence:'NEEDS_REVIEW',affectedUrl:r.url,method:'GET',impact:'The reference exposes build information; source disclosure was not confirmed.',remediation:'Remove unnecessary production source-map references.',evidence:[r.evidence]});}
  }
  return out;
}};
