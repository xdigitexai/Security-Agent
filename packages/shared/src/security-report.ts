import { deepseekJson } from './deepseek';
import { env } from './env';

export type ReportSeverity='CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFORMATIONAL';
export type ReportCheckResult={id:string;status:'completed'|'skipped';error?:string};

export interface SecurityReportFinding {
  title:string;
  severity:ReportSeverity|string;
  confidence:string;
  category:string;
  affectedUrl:string;
  method?:string|null;
  description:string;
  impact:string;
  remediation:string;
  status?:string;
}

export interface SecurityReportInput {
  target:string;
  scanId:string;
  prompt?:string|null;
  plan?:unknown;
  findings:SecurityReportFinding[];
  endpointCount:number;
  pageCount?:number;
  requestCount?:number;
  technologies?:unknown[];
  selectedChecks?:string[];
  checkResults?:ReportCheckResult[];
  scope?:unknown;
}

export interface FullSecurityReport {
  generatedBy:'deepseek-flash'|'deterministic-fallback';
  generatedAt:string;
  executiveSummary:string;
  securityPosture:string;
  riskOverview:{total:number;critical:number;high:number;medium:number;low:number;informational:number;confirmed:number;};
  assessmentCoverage:string;
  attackSurfaceSummary:string;
  keyFindings:Array<{title:string;severity:string;confidence:string;affectedUrl:string;impact:string;whyItMatters:string;remediationPriority:string;}>;
  prioritizedRemediation:Array<{priority:'P0'|'P1'|'P2'|'P3';title:string;reason:string;action:string;validation:string;}>;
  technicalSummary:string;
  positiveObservations:string[];
  limitations:string[];
  nextActions:string[];
}

const rank:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFORMATIONAL:4};
function counts(findings:SecurityReportFinding[]){const count=(severity:string)=>findings.filter(f=>f.severity===severity).length;return {total:findings.length,critical:count('CRITICAL'),high:count('HIGH'),medium:count('MEDIUM'),low:count('LOW'),informational:count('INFORMATIONAL'),confirmed:findings.filter(f=>f.confidence==='CONFIRMED'||f.confidence==='HIGH').length};}
function priorityFor(severity:string):'P0'|'P1'|'P2'|'P3'{if(severity==='CRITICAL')return'P0';if(severity==='HIGH')return'P1';if(severity==='MEDIUM')return'P2';return'P3';}

function fallbackReport(input:SecurityReportInput):FullSecurityReport{
  const risk=counts(input.findings);const sorted=[...input.findings].sort((a,b)=>(rank[a.severity]??9)-(rank[b.severity]??9));const highRisk=risk.critical+risk.high;
  const completed=(input.checkResults||[]).filter(c=>c.status==='completed');const skipped=(input.checkResults||[]).filter(c=>c.status==='skipped');
  const checkText=input.checkResults?.length?`${completed.length} scanner modules completed${skipped.length?` and ${skipped.length} were skipped due to safe execution errors`:''}`:`${input.selectedChecks?.length||0} scanner modules were selected`;
  const limitations=['Automated coverage is limited by verified scope, crawl visibility, request caps, registered scanner modules, and any owner-provided test identities.','Absence of a finding does not prove absence of a vulnerability.','Unrelated third-party systems and destructive exploitation were excluded from testing.'];
  if(skipped.length)limitations.unshift(`The following scanner modules did not complete and must not be treated as negative assurance: ${skipped.map(c=>c.id).join(', ')}.`);
  return {
    generatedBy:'deterministic-fallback',generatedAt:new Date().toISOString(),
    executiveSummary:`The authorized assessment of ${input.target} completed with ${risk.total} recorded finding${risk.total===1?'':'s'} across ${input.endpointCount} discovered URL/API surface${input.endpointCount===1?'':'s'}. ${highRisk?`${highRisk} critical/high finding${highRisk===1?' requires':'s require'} prioritized remediation.`:'No critical or high-severity finding was recorded by the scanner modules that completed successfully.'}`,
    securityPosture:highRisk?'Higher-risk weaknesses were recorded and should be addressed before expanding exposure or releasing sensitive changes.':'Completed checks did not record a critical/high issue; lower-severity findings, skipped checks and assessment limitations must still be reviewed.',
    riskOverview:risk,
    assessmentCoverage:`The assessment mapped ${input.endpointCount} URL/API surfaces${input.pageCount!=null?`, crawled ${input.pageCount} pages`:''}${input.requestCount!=null?`, issued ${input.requestCount} bounded requests`:''}, and ${checkText}. Execution remained inside the ownership-verified scope.`,
    attackSurfaceSummary:'Observed application coverage was derived from the verified first-party target, robots/sitemaps where reachable, discovered pages, forms, scripts, API traffic and registered checks. Third-party dependencies were not actively tested.',
    keyFindings:sorted.slice(0,15).map(f=>({title:f.title,severity:String(f.severity),confidence:f.confidence,affectedUrl:f.affectedUrl,impact:f.impact,whyItMatters:f.description,remediationPriority:priorityFor(String(f.severity))})),
    prioritizedRemediation:sorted.slice(0,15).map(f=>({priority:priorityFor(String(f.severity)),title:f.title,reason:f.impact,action:f.remediation,validation:`Retest the affected ${f.method||'GET'} ${f.affectedUrl} after remediation and confirm the original evidence is no longer reproducible.`})),
    technicalSummary:`Findings were produced only by registered Xdigitex checks through the centralized bounded HTTP/browser layer. ${checkText}. Evidence is sanitized before storage and reporting.`,
    positiveObservations:[],limitations,
    nextActions:sorted.length?['Remediate P0/P1 issues first.','Review NEEDS_REVIEW observations manually before promoting their severity.','Apply recommended fixes and run focused retests.','Run another comprehensive assessment after material remediation or deployment changes.']:['Review mapped attack surface and coverage limitations.','Resolve/re-run any skipped scanner modules before drawing negative conclusions.','Add authorized test identities/resources when deeper authorization testing is required.']
  };
}

function safeText(value:unknown,fallback:string,max=6000){return typeof value==='string'&&value.trim()?value.trim().slice(0,max):fallback;}
function safeList(value:unknown,fallback:string[]){if(!Array.isArray(value))return fallback;const items=value.filter((x):x is string=>typeof x==='string'&&x.trim().length>0).slice(0,20).map(x=>x.trim().slice(0,1200));return items.length?items:fallback;}
function normalizeReport(ai:Partial<FullSecurityReport>,fallback:FullSecurityReport):FullSecurityReport{return {generatedBy:'deepseek-flash',generatedAt:new Date().toISOString(),executiveSummary:safeText(ai.executiveSummary,fallback.executiveSummary),securityPosture:safeText(ai.securityPosture,fallback.securityPosture),riskOverview:fallback.riskOverview,assessmentCoverage:safeText(ai.assessmentCoverage,fallback.assessmentCoverage),attackSurfaceSummary:safeText(ai.attackSurfaceSummary,fallback.attackSurfaceSummary),keyFindings:fallback.keyFindings,prioritizedRemediation:fallback.prioritizedRemediation,technicalSummary:safeText(ai.technicalSummary,fallback.technicalSummary),positiveObservations:safeList(ai.positiveObservations,fallback.positiveObservations),limitations:safeList(ai.limitations,fallback.limitations),nextActions:safeList(ai.nextActions,fallback.nextActions)};}

export async function generateSecurityReport(input:SecurityReportInput):Promise<FullSecurityReport>{
  const fallback=fallbackReport(input);if(!env().DEEPSEEK_API_KEY)return fallback;
  const findingEvidence=input.findings.map(f=>({title:f.title,severity:f.severity,confidence:f.confidence,category:f.category,affectedUrl:f.affectedUrl,method:f.method,description:f.description,impact:f.impact,remediation:f.remediation,status:f.status}));
  const system=`You are DeepSeek Flash acting as the reporting brain for an authorized defensive application-security assessment. Return valid JSON only. Scanner findings and check completion states are the source of truth. Never invent a vulnerability, endpoint, credential, exploit result, financial impact, affected user, or successful attack that is not present in the input. Never say that a weakness, secret, API, admin/debug endpoint, CORS issue, injection flaw, authentication issue, or other class was absent unless the relevant scanner module is explicitly marked completed and the supplied evidence supports that statement. A selected-but-skipped module provides no negative assurance. Do not claim a test was performed unless reflected in coverage. Write an executive-ready but technically useful report. Prioritize confirmed evidence, distinguish indicators from confirmed vulnerabilities, and explain uncertainty. Xdigitex independently derives canonical findings and remediation records from scanner evidence; your job is narrative sections only.`;
  const user=JSON.stringify({target:input.target,scanId:input.scanId,originalMission:input.prompt,agentPlan:input.plan,coverage:{endpointCount:input.endpointCount,pageCount:input.pageCount,requestCount:input.requestCount,technologies:input.technologies,selectedChecks:input.selectedChecks,checkResults:input.checkResults,scope:input.scope},findings:findingEvidence,exactJsonShape:{executiveSummary:'string',securityPosture:'string',assessmentCoverage:'string',attackSurfaceSummary:'string',technicalSummary:'string',positiveObservations:['string'],limitations:['string'],nextActions:['string']}});
  const ai=await deepseekJson<Partial<FullSecurityReport>>(system,user,{maxTokens:8000});return ai?normalizeReport(ai,fallback):fallback;
}
