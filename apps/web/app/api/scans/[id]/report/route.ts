import { NextResponse } from 'next/server';
import PDFDocument from 'pdfkit';
import { requireOrg } from '../../../../../lib/auth';
import { db } from '@xdigitex/database';
import { deepseekJson, env } from '@xdigitex/shared';

export const runtime='nodejs';

type AiReport={executiveSummary:string;securityPosture:string;highestRiskIssues:string[];priorityFixes:string[];limitations:string[]};

async function buildAiReport(scan:any):Promise<AiReport>{
  const findings=scan.findings.map((f:any)=>({title:f.title,severity:f.severity,confidence:f.confidence,category:f.category,affectedUrl:f.affectedUrl,method:f.method,description:f.description,impact:f.impact,remediation:f.remediation,status:f.status}));
  const fallback:AiReport={
    executiveSummary:`The assessment completed with ${findings.length} recorded findings. Only evidence produced by Xdigitex scanner modules is included in this report.`,
    securityPosture:findings.some((f:any)=>f.severity==='CRITICAL'||f.severity==='HIGH')?'Confirmed or high-confidence higher-risk issues require prioritized remediation.':'No confirmed critical/high issue is represented in the current scan results.',
    highestRiskIssues:findings.filter((f:any)=>['CRITICAL','HIGH'].includes(f.severity)).slice(0,5).map((f:any)=>f.title),
    priorityFixes:findings.slice(0,8).map((f:any)=>f.remediation),
    limitations:['Automated evidence is bounded by verified scope, configured request limits, available test identities, and registered scanner modules.']
  };
  const cfg=env();if(!cfg.DEEPSEEK_API_KEY)return fallback;
  const ai=await deepseekJson<AiReport>(`You write defensive application-security reports from scanner evidence. Return JSON only. Never invent vulnerabilities, exploitation success, credentials, endpoints, or impact not present in the supplied findings. Treat the findings as the source of truth. Explain verified proof-of-impact conservatively.`,JSON.stringify({target:scan.asset.baseUrl,scanId:scan.id,prompt:scan.agentPrompt,plan:scan.agentPlan,findings,requiredOutput:{executiveSummary:'string',securityPosture:'string',highestRiskIssues:['string'],priorityFixes:['string'],limitations:['string']}}));
  return ai||fallback;
}

function pdfBuffer(scan:any,report:AiReport){return new Promise<Buffer>((resolve,reject)=>{
  const doc=new PDFDocument({size:'A4',margin:48,info:{Title:`Xdigitex Security Report - ${scan.asset.normalizedHost}`,Author:'Xdigitex Security Agent'}});
  const chunks:Buffer[]=[];doc.on('data',(c:Buffer)=>chunks.push(c));doc.on('end',()=>resolve(Buffer.concat(chunks)));doc.on('error',reject);
  const heading=(text:string,size=16)=>{doc.moveDown(.7).font('Helvetica-Bold').fontSize(size).text(text).font('Helvetica').fontSize(10);};
  doc.font('Helvetica-Bold').fontSize(22).text('XDIGITEX SECURITY REPORT');doc.moveDown(.5).font('Helvetica').fontSize(10);
  doc.text(`Target: ${scan.asset.baseUrl}`);doc.text(`Scan ID: ${scan.id}`);doc.text(`Scan Date: ${(scan.completedAt||scan.createdAt).toISOString()}`);doc.text(`Status: ${scan.status}`);doc.text(`AI model: ${env().DEEPSEEK_API_KEY?env().DEEPSEEK_MODEL:'not configured (deterministic report)'}`);
  heading('Executive Summary');doc.text(report.executiveSummary);
  heading('Security Posture');doc.text(report.securityPosture);
  heading('Finding Summary');
  const counts=['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].map(s=>[s,scan.findings.filter((f:any)=>f.severity===s).length]);counts.forEach(([s,n])=>doc.text(`${s}: ${n}`));
  if(report.highestRiskIssues.length){heading('Highest-Risk Issues');report.highestRiskIssues.forEach(x=>doc.text(`• ${x}`));}
  heading('Technical Findings');
  scan.findings.forEach((f:any,index:number)=>{
    doc.moveDown(.8).font('Helvetica-Bold').fontSize(12).text(`${index+1}. ${f.title}`);doc.font('Helvetica').fontSize(9);
    doc.text(`Severity: ${f.severity}   Confidence: ${f.confidence}   Status: ${f.status}`);doc.text(`Category: ${f.category}`);doc.text(`Affected: ${f.method||'GET'} ${f.affectedUrl}`);
    doc.moveDown(.3).font('Helvetica-Bold').text('Description');doc.font('Helvetica').text(f.description);
    doc.font('Helvetica-Bold').text('Impact');doc.font('Helvetica').text(f.impact);
    doc.font('Helvetica-Bold').text('Recommended Fix');doc.font('Helvetica').text(f.remediation);
    const ev=f.evidence?.[0];if(ev){doc.font('Helvetica-Bold').text('Sanitized Evidence');doc.font('Helvetica').text(`HTTP ${ev.responseStatus??''} ${ev.requestUrl||f.affectedUrl}`);if(ev.responseExcerpt)doc.text(String(ev.responseExcerpt).slice(0,900));}
  });
  if(report.priorityFixes.length){heading('Recommended Priority Fixes');report.priorityFixes.forEach((x,i)=>doc.text(`${i+1}. ${x}`));}
  heading('Assessment Boundaries');doc.text('Testing was limited to ownership-verified first-party scope and registered bounded security modules. Xdigitex does not include destructive exploitation, credential theft, uncontrolled denial-of-service activity, or active testing of unrelated third-party services.');report.limitations.forEach(x=>doc.text(`• ${x}`));
  doc.end();
});}

export async function GET(_req:Request,{params}:{params:Promise<{id:string}>}){
  const {org}=await requireOrg();const {id}=await params;
  const scan=await db.scan.findFirst({where:{id,organizationId:org.id},include:{asset:true,findings:{include:{evidence:{take:1,orderBy:{capturedAt:'desc'}}},orderBy:[{severity:'asc'},{createdAt:'asc'}]}}});
  if(!scan)return new NextResponse('Not found',{status:404});if(scan.status!=='COMPLETED')return new NextResponse('Report is available after the scan completes.',{status:409});
  const report=await buildAiReport(scan);await db.scan.update({where:{id:scan.id},data:{agentReport:report as any}});
  const pdf=await pdfBuffer(scan,report);const safe=scan.asset.normalizedHost.replace(/[^a-z0-9.-]+/gi,'-');
  return new NextResponse(new Uint8Array(pdf),{headers:{'content-type':'application/pdf','content-disposition':`attachment; filename="xdigitex-security-${safe}-${scan.id.slice(0,8)}.pdf"`,'cache-control':'private, no-store'}});
}
