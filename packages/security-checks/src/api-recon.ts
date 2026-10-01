import type { SecurityCheck } from '@xdigitex/scanner-core';
import { finding } from './helpers';

const docsPaths=['/openapi.json','/swagger.json','/api/openapi.json','/api/swagger.json','/swagger/v1/swagger.json','/api-docs','/swagger','/docs'];
const graphqlPaths=['/graphql','/api/graphql','/graphiql'];

function docsSignature(body:string){return /"openapi"\s*:\s*"3\.|"swagger"\s*:\s*"2\.|Swagger UI|OpenAPI Specification/i.test(body);}
function graphqlSignature(body:string){return /GraphQL|graphiql|Must provide query string|Cannot query field|"errors"\s*:\s*\[/i.test(body);}
function normalized(body:string){return body.slice(0,1800).replace(/[a-f0-9]{16,}/gi,'#').replace(/\s+/g,' ').trim();}

export const apiReconCheck:SecurityCheck={id:'api.recon-bounded',name:'Bounded API documentation and GraphQL reconnaissance',category:'API Security',async run(ctx){
  const out=[];const base=new URL(ctx.assetUrl);
  const baseline=await ctx.http.request(new URL(`/xdigitex-api-miss-${Date.now().toString(36)}`,base).toString()).catch(()=>null);
  const baselineBody=baseline?normalized(baseline.body):'';

  for(const path of docsPaths){
    if(await ctx.isCanceled())break;let r;try{r=await ctx.http.request(new URL(path,base).toString());}catch{continue;}
    if(r.status<200||r.status>=400)continue;const body=normalized(r.body);
    if(baseline&&r.status===baseline.status&&baselineBody&&body===baselineBody)continue;
    if(!docsSignature(r.body))continue;
    out.push(finding({checkId:this.id,title:'Public API documentation discovered',description:'A common first-party API documentation/OpenAPI endpoint is publicly reachable and contains a concrete Swagger/OpenAPI signature.',category:this.category,severity:'INFORMATIONAL',confidence:'CONFIRMED',affectedUrl:r.url,method:'GET',impact:'Public API schemas can materially improve endpoint and parameter enumeration. Exposure is not inherently vulnerable, but it should be intentional and all documented operations must enforce server-side authorization.',remediation:'Keep documentation public only when intended; otherwise restrict production documentation and independently verify authorization on every operation.',evidence:[{...r.evidence,responseExcerpt:'Swagger/OpenAPI signature confirmed; schema body omitted from stored evidence.'}]}));
  }

  for(const path of graphqlPaths){
    if(await ctx.isCanceled())break;const endpoint=new URL(path,base);let r;try{r=await ctx.http.request(endpoint.toString());}catch{continue;}
    if(!graphqlSignature(r.body)&&![400,405].includes(r.status))continue;
    const q=new URL(endpoint);q.searchParams.set('query','{__schema{queryType{name}}}');let introspection=null;
    try{introspection=await ctx.http.request(q.toString());}catch{}
    if(introspection&&introspection.status===200&&/"__schema"\s*:/.test(introspection.body))out.push(finding({checkId:this.id,title:'Public GraphQL introspection enabled',description:'A first-party GraphQL endpoint accepted a read-only schema introspection query without authentication.',category:this.category,severity:'LOW',confidence:'CONFIRMED',affectedUrl:endpoint.toString(),method:'GET',impact:'Unauthenticated schema introspection can expose object, field and operation names, making API reconnaissance substantially easier. It does not by itself prove unauthorized data access.',remediation:'If public introspection is unnecessary in production, restrict it and ensure every resolver independently enforces authentication and object-level authorization.',evidence:[{...introspection.evidence,responseExcerpt:'GraphQL __schema response confirmed; schema details intentionally omitted.'}]}));
    else out.push(finding({checkId:this.id,title:'GraphQL endpoint discovered',description:'A first-party endpoint behaves like GraphQL, but public schema introspection was not confirmed.',category:this.category,severity:'INFORMATIONAL',confidence:'HIGH',affectedUrl:endpoint.toString(),method:'GET',impact:'The endpoint expands the API attack surface and should be included in authenticated authorization testing.',remediation:'Verify authentication, resolver-level authorization, query complexity controls and production introspection policy.',evidence:[r.evidence]}));
  }
  return out;
}};
