import { deepseekJson } from './deepseek';
import { env } from './env';

export type ReportSeverity='CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFORMATIONAL';

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
  scope?:unknown;
}

export interface FullSecurityReport {
  generatedBy:'deepseek-flash'|'deterministic-fallback';
  generatedAt:string;
  executiveSummary:string;
  securityPosture:string;
  riskOverview:{
    total:number;
    critical:number;
    high:number;
    medium:number;
    low:number;
    informational:number;
    confirmed:number;
  };
  assessmentCoverage:string;
  attackSurfaceSummary:string;
  keyFindings:Array<{
    title:string;
    severity:string;
    confidence:string;
    affectedUrl:string;
    impact:string;
    whyItMatters:string;
    remediationPriority:string;
  }>;
  prioritizedRemediation:Array<{
    priority:'P0'|'P1'|'P2'|'P3';
    title:string;
    reason:string;
    action:string;
    validation:string;
  }>;
  technicalSummary:string;
  positiveObservations:string[];
  limitations:string[];
  nextActions:string[];
}

const rank:Record<string,number>={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFORMATIONAL:4};

function counts(findings:SecurityReportFinding[]){
  const count=(severity:string)=>findings.filter(f=>f.severity===severity).length;
  return {
    total:findings.length,
    critical:count('CRITICAL'),
    high:count('HIGH'),
    medium:count('MEDIUM'),
    low:count('LOW'),
    informational:count('INFORMATIONAL'),
    confirmed:findings.filter(f=>f.confidence==='CONFIRMED'||f.confidence==='HIGH').length
  };
}

function priorityFor(severity:string):'P0'|'P1'|'P2'|'P3'{
  if(severity==='CRITICAL')return 'P0';
  if(severity==='HIGH')return 'P1';
  if(severity==='MEDIUM')return 'P2';
  return 'P3';
}

function fallbackReport(input:SecurityReportInput):FullSecurityReport{
  const risk=counts(input.findings);
  const sorted=[...input.findings].sort((a,b)=>(rank[a.severity]??9)-(rank[b.severity]??9));
  const highRisk=risk.critical+risk.high;
  return {
    generatedBy:'deterministic-fallback',
    generatedAt:new Date().toISOString(),
    executiveSummary:`The authorized assessment of ${input.target} completed with ${risk.total} recorded finding${risk.total===1?'':'s'} across ${input.endpointCount} discovered URL/API surface${input.endpointCount===1?'':'s'}. ${highRisk?`${highRisk} critical/high finding${highRisk===1?' requires':'s require'} prioritized remediation.`:'No critical or high-severity finding was recorded by the executed scanner modules.'}`,
    securityPosture:highRisk?'Higher-risk weaknesses were recorded and should be addressed before expanding exposure or releasing sensitive changes.':'The executed checks did not record a critical/high issue; lower-severity findings and assessment limitations should still be reviewed.',
    riskOverview:risk,
    assessmentCoverage:`The assessment mapped ${input.endpointCount} URL/API surfaces${input.pageCount!=null?`, crawled ${input.pageCount} pages`:''}${input.requestCount!=null?`, and issued ${input.requestCount} bounded requests`:''}. Execution remained inside the ownership-verified scope and registered scanner modules.`,
    attackSurfaceSummary:`Observed application coverage was derived from the verified first-party target, discovered pages, forms, scripts, API traffic, and registered checks. Third-party dependencies were not actively tested.`,
    keyFindings:sorted.slice(0,10).map(f=>({title:f.title,severity:String(f.severity),confidence:f.confidence,affectedUrl:f.affectedUrl,impact:f.impact,whyItMatters:f.description,remediationPriority:priorityFor(String(f.severity))})),
    prioritizedRemediation:sorted.slice(0,10).map(f=>({priority:priorityFor(String(f.severity)),title:f.title,reason:f.impact,action:f.remediation,validation:`Retest the affected ${f.method||'GET'} ${f.affectedUrl} after remediation and confirm the original evidence is no longer reproducible.`})),
    technicalSummary:`Findings were produced only by registered Xdigitex checks through the centralized bounded HTTP/browser layer. Evidence is sanitized before storage and reporting.`,
    positiveObservations:risk.total===0?['No finding was produced by the executed registered checks.']:[],
    limitations:['Automated coverage is limited by verified scope, crawl visibility, request caps, registered scanner modules, and any owner-provided test identities.','Absence of a finding does not prove absence of a vulnerability.','Unrelated third-party systems and destructive exploitation were excluded from testing.'],
    nextActions:sorted.length?['Remediate P0/P1 issues first.','Apply the recommended fixes and run focused retests.','Run another comprehensive assessment after major remediation or deployment changes.']:['Review the mapped attack surface and coverage limitations.','Add authorized test identities/resources when deeper authorization testing is required.','Repeat the assessment after material application changes.']
  };
}

function normalizeReport(ai:Partial<FullSecurityReport>,fallback:FullSecurityReport):FullSecurityReport{
  const arr=(value:unknown,backup:string[])=>Array.isArray(value)?value.slice(0,20).map(String):backup;
  const objects=<T>(value:unknown,backup:T[])=>Array.isArray(value)?value.slice(0,20) as T[]:backup;
  return {
    generatedBy:'deepseek-flash',
    generatedAt:new Date().toISOString(),
    executiveSummary:String(ai.executiveSummary||fallback.executiveSummary),
    securityPosture:String(ai.securityPosture||fallback.securityPosture),
    riskOverview:fallback.riskOverview,
    assessmentCoverage:String(ai.assessmentCoverage||fallback.assessmentCoverage),
    attackSurfaceSummary:String(ai.attackSurfaceSummary||fallback.attackSurfaceSummary),
    keyFindings:objects(ai.keyFindings,fallback.keyFindings),
    prioritizedRemediation:objects(ai.prioritizedRemediation,fallback.prioritizedRemediation),
    technicalSummary:String(ai.technicalSummary||fallback.technicalSummary),
    positiveObservations:arr(ai.positiveObservations,fallback.positiveObservations),
    limitations:arr(ai.limitations,fallback.limitations),
    nextActions:arr(ai.nextActions,fallback.nextActions)
  };
}

export async function generateSecurityReport(input:SecurityReportInput):Promise<FullSecurityReport>{
  const fallback=fallbackReport(input);
  if(!env().DEEPSEEK_API_KEY)return fallback;

  const findingEvidence=input.findings.map(f=>({
    title:f.title,severity:f.severity,confidence:f.confidence,category:f.category,
    affectedUrl:f.affectedUrl,method:f.method,description:f.description,impact:f.impact,
    remediation:f.remediation,status:f.status
  }));

  const system=`You are DeepSeek Flash acting as the reporting brain for an authorized defensive application-security assessment. Return valid JSON only. The supplied scanner findings are the source of truth. Never invent a vulnerability, endpoint, credential, exploit result, financial impact, affected user, or successful attack that is not present in the input. Do not claim a test was performed unless reflected in the supplied coverage. Write an executive-ready but technically useful report. Prioritize confirmed evidence and explain uncertainty. Keep remediation concrete and validation steps non-destructive.`;
  const user=JSON.stringify({
    target:input.target,
    scanId:input.scanId,
    originalMission:input.prompt,
    agentPlan:input.plan,
    coverage:{endpointCount:input.endpointCount,pageCount:input.pageCount,requestCount:input.requestCount,technologies:input.technologies,selectedChecks:input.selectedChecks,scope:input.scope},
    findings:findingEvidence,
    exactJsonShape:{
      executiveSummary:'string',
      securityPosture:'string',
      assessmentCoverage:'string',
      attackSurfaceSummary:'string',
      keyFindings:[{title:'string',severity:'string',confidence:'string',affectedUrl:'string',impact:'string',whyItMatters:'string',remediationPriority:'P0|P1|P2|P3'}],
      prioritizedRemediation:[{priority:'P0|P1|P2|P3',title:'string',reason:'string',action:'string',validation:'string'}],
      technicalSummary:'string',
      positiveObservations:['string'],
      limitations:['string'],
      nextActions:['string']
    }
  });

  const ai=await deepseekJson<Partial<FullSecurityReport>>(system,user,{maxTokens:8000});
  return ai?normalizeReport(ai,fallback):fallback;
}
