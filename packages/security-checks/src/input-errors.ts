import type { SecurityCheck } from '@xdigitex/scanner-core';
import { finding } from './helpers';

const dbErrors=[
  /You have an error in your SQL syntax/i,
  /mysqli?_sql_exception/i,
  /SQLSTATE\[[A-Z0-9]+\]/i,
  /PG::(?:SyntaxError|Error)/i,
  /unterminated quoted string/i,
  /SQLite(?:3)?::(?:SQLException|Exception)/i,
  /near ["'][^"']+["']:\s*syntax error/i,
  /ORA-\d{5}/i,
  /Microsoft OLE DB Provider for SQL Server/i,
  /Unclosed quotation mark after the character string/i
];
const frameworkErrors=[/Traceback \(most recent call last\)/i,/Unhandled(?:Promise)?Rejection/i,/\b(?:TypeError|ReferenceError|ValueError|ArgumentError|PDOException):[^<]{3,180}/i,/\bat [\w.$<>]+ \([^\n()]+:\d+:\d+\)/];
function hasAny(body:string,patterns:RegExp[]){return patterns.some(p=>p.test(body));}

export const inputErrorCheck:SecurityCheck={id:'input.error-differential',name:'Safe malformed-input error differential',category:'Input Validation',async run(ctx){
  const out=[];let probes=0;
  const endpoints=ctx.endpoints.filter(e=>e.method==='GET').slice(0,50);
  for(const ep of endpoints){
    if(await ctx.isCanceled()||probes>=60)break;
    let original:URL;try{original=new URL(ep.url);}catch{continue;}
    const params=[...new Set([...(ep.parameters||[]),...original.searchParams.keys()])].filter(Boolean).slice(0,4);
    if(!params.length)continue;
    let baseline;try{baseline=await ctx.http.request(original.toString());}catch{continue;}
    for(const parameter of params){
      if(await ctx.isCanceled()||probes++>=60)break;
      const candidate=new URL(original);const prior=candidate.searchParams.get(parameter)||'1';candidate.searchParams.set(parameter,`${prior}XDIGITEX_'`);
      let r;try{r=await ctx.http.request(candidate.toString());}catch{continue;}
      const baselineDb=hasAny(baseline.body,dbErrors);const mutatedDb=hasAny(r.body,dbErrors);
      if(mutatedDb&&!baselineDb){
        out.push(finding({checkId:this.id,title:'Database error triggered by malformed parameter input',description:`A benign malformed marker added to parameter ${parameter} caused a database-specific error signature that was absent from the baseline response. No data-extraction or destructive SQL payload was used.`,category:'Injection / Error Handling',severity:'MEDIUM',confidence:'HIGH',affectedUrl:ep.url,method:'GET',parameter,impact:'Database errors caused by attacker-controlled input can reveal query construction details and may indicate unsafe query handling that requires manual injection testing.',remediation:'Use parameterized queries/prepared statements, validate input types server-side, and suppress database diagnostics from client responses.',evidence:[{...r.evidence,responseExcerpt:'Database-specific error signature observed after benign malformed-input probe; detailed response omitted.'}] }));
        continue;
      }
      const baselineFramework=hasAny(baseline.body,frameworkErrors);const mutatedFramework=hasAny(r.body,frameworkErrors);
      if(mutatedFramework&&!baselineFramework)out.push(finding({checkId:this.id,title:'Detailed server exception triggered by malformed input',description:`A benign malformed value for parameter ${parameter} caused a detailed framework/runtime exception that was absent from the baseline response.`,category:'Error Handling',severity:'LOW',confidence:'HIGH',affectedUrl:ep.url,method:'GET',parameter,impact:'Triggered exceptions can reveal internal paths, framework behavior and code structure, and may identify poorly handled input paths.',remediation:'Validate parameter formats before processing and return generic production errors while retaining detailed diagnostics only in server-side logs.',evidence:[{...r.evidence,responseExcerpt:'Framework/runtime exception signature observed after benign malformed-input probe; detailed response omitted.'}] }));
    }
  }
  return out;
}};
