import { Worker } from 'bullmq';
import IORedis from 'ioredis';
import { db, ScanStatus, JobStatus, FindingStatus } from '@xdigitex/database';
import { env, findingFingerprint, generateSecurityReport } from '@xdigitex/shared';
import { ScanHttpClient, crawl, runChecks, buildApplicationMap, type ScanContext } from '@xdigitex/scanner-core';
import { checks } from '@xdigitex/security-checks';
import type { ScanScope, SecurityFinding, AuthorizedTestIdentity, AuthorizedTestResource } from '@xdigitex/types';
import { resolveRequestProfile } from './profile-broker';
import { buildAgentPlan } from './deepseek-plan';

const cfg=env();
const redis=new IORedis(cfg.REDIS_URL,{maxRetriesPerRequest:null});
async function log(scanId:string,stage:string,message:string,metadata?:unknown){await db.scanLog.create({data:{scanId,level:'INFO',stage,message,metadata:metadata as object|undefined}});}
async function saveFinding(scan:any,f:SecurityFinding){
 const fp=findingFingerprint({checkId:f.checkId,affectedUrl:f.affectedUrl,method:f.method,parameter:f.parameter});
 const existing=await db.finding.findFirst({where:{assetId:scan.assetId,fingerprint:fp},orderBy:{lastSeenAt:'desc'}});let row;
 if(existing){row=await db.finding.update({where:{id:existing.id},data:{scanId:scan.id,lastSeenAt:new Date(),status:FindingStatus.OPEN,severity:f.severity,confidence:f.confidence,description:f.description,impact:f.impact,remediation:f.remediation}});}
 else{row=await db.finding.create({data:{organizationId:scan.organizationId,assetId:scan.assetId,scanId:scan.id,checkId:f.checkId,title:f.title,description:f.description,category:f.category,severity:f.severity,confidence:f.confidence,affectedUrl:f.affectedUrl,method:f.method,parameter:f.parameter,impact:f.impact,remediation:f.remediation,fingerprint:fp}});}
 for(const ev of f.evidence||[])await db.findingEvidence.create({data:{findingId:row.id,requestMethod:ev.requestMethod,requestUrl:ev.requestUrl,requestHeaders:ev.requestHeaders as object|undefined,requestBody:ev.requestBody,responseStatus:ev.responseStatus,responseHeaders:ev.responseHeaders as object|undefined,responseExcerpt:ev.responseExcerpt,capturedAt:ev.timestamp}});
 await db.findingEvent.create({data:{findingId:row.id,type:'DETECTED',message:'Detected during scan'}});
 return {row,fingerprint:fp};
}
async function canceled(scanId:string){return !!(await db.scan.findUnique({where:{id:scanId},select:{cancelRequestedAt:true}}))?.cancelRequestedAt;}

const worker=new Worker('security-scans',async job=>{
 const scan=await db.scan.findUniqueOrThrow({where:{id:job.data.scanId},include:{asset:true}});
 if(!scan.asset.verifiedAt||!scan.asset.scanningEnabled)throw new Error('ASSET_NOT_VERIFIED_OR_DISABLED');
 const retestFindingId=typeof job.data?.retestFindingId==='string'?job.data.retestFindingId:undefined;
 const retestFinding=retestFindingId?await db.finding.findFirst({where:{id:retestFindingId,assetId:scan.assetId,organizationId:scan.organizationId}}):null;
 if(retestFindingId&&!retestFinding)throw new Error('RETEST_FINDING_NOT_FOUND');
 const retestChecks=retestFinding?checks.filter(c=>c.id===retestFinding.checkId):[];
 if(retestFinding&&retestChecks.length===0)throw new Error(`RETEST_CHECK_UNAVAILABLE:${retestFinding.checkId}`);
 const scope=scan.scope as unknown as ScanScope;const http=new ScanHttpClient(scope);const started=new Date();
 await db.scan.update({where:{id:scan.id},data:{status:ScanStatus.RUNNING,stage:'Validation',progress:2,startedAt:started}});
 await db.scanJob.updateMany({where:{scanId:scan.id},data:{status:JobStatus.RUNNING,startedAt:started,attempt:{increment:1}}});
 const deadline=Date.now()+cfg.MAX_SCAN_DURATION_MS;const isCanceled=async()=>Date.now()>deadline||await canceled(scan.id);
 try{
   await log(scan.id,'Validation',retestFinding?`Focused retest authorized for ${retestFinding.checkId}`:'Verified ownership and scope loaded',retestFinding?{findingId:retestFinding.id,affectedUrl:retestFinding.affectedUrl}:undefined);
   const identityRows=await db.testIdentity.findMany({where:{assetId:scan.assetId,enabled:true,OR:[{expiresAt:null},{expiresAt:{gt:new Date()}}]}});
   const resourceRows=await db.testResource.findMany({where:{assetId:scan.assetId,safeReadOnly:true}});
   const testIdentities:AuthorizedTestIdentity[]=identityRows.map(i=>({id:i.id,label:i.label,roleLabel:i.roleLabel,tenantLabel:i.tenantLabel,authType:i.authType,credentialRef:i.credentialRef,expectedSessionState:i.expectedSessionState}));
   const testResources:AuthorizedTestResource[]=resourceRows.filter(r=>r.method==='GET'||r.method==='HEAD').map(r=>({id:r.id,label:r.label,url:r.url,method:r.method as 'GET'|'HEAD',ownerIdentityId:r.ownerIdentityId,comparatorIdentityIds:Array.isArray(r.comparatorIdentityIds)?r.comparatorIdentityIds.filter((x):x is string=>typeof x==='string'):[],expectation:r.expectation,proofMarker:r.proofMarker}));
   const resolvedIdentityHeaders:Record<string,Record<string,string>>={};
   if(cfg.IDENTITY_PROFILE_BROKER_URL){for(const identity of testIdentities){try{const profile=await resolveRequestProfile(cfg.IDENTITY_PROFILE_BROKER_URL,identity.credentialRef);if(profile)resolvedIdentityHeaders[identity.id]=profile;}catch(error){await log(scan.id,'Authorization Planning','Identity profile could not be resolved',{identityId:identity.id,credentialRef:identity.credentialRef,error:String(error).slice(0,160)});}}}
   await log(scan.id,'Authorization Planning','Loaded owner-authorized identity test plan',{identities:testIdentities.map(i=>({id:i.id,label:i.label,role:i.roleLabel,tenant:i.tenantLabel,sessionState:i.expectedSessionState,credentialRef:i.credentialRef,resolved:!!resolvedIdentityHeaders[i.id]})),resources:testResources.map(r=>({id:r.id,label:r.label,url:r.url,method:r.method,expectation:r.expectation,comparators:r.comparatorIdentityIds.length})),activeProfileBroker:!!cfg.IDENTITY_PROFILE_BROKER_URL,resolvedProfiles:Object.keys(resolvedIdentityHeaders).length});
   await db.scan.update({where:{id:scan.id},data:{stage:'Reconnaissance',progress:8}});
   const recon=await http.request(scan.asset.baseUrl);await log(scan.id,'Reconnaissance',`Root responded ${recon.status}`);
   await db.scan.update({where:{id:scan.id},data:{stage:'Crawling',progress:15}});
   const crawlStart=retestFinding&&retestFinding.method==='GET'?retestFinding.affectedUrl:scan.asset.baseUrl;
   let cr;try{cr=await crawl(crawlStart,scope,isCanceled);}catch(e){if(crawlStart!==scan.asset.baseUrl){await log(scan.id,'Crawling','Affected URL could not be crawled directly; falling back to verified asset root',{reason:String(e)});cr=await crawl(scan.asset.baseUrl,scope,isCanceled);}else throw e;}
   await db.discoveredEndpoint.createMany({data:[...cr.endpoints.map(e=>({scanId:scan.id,url:e.url,method:e.method,parameters:e.parameters??[],responseCode:e.responseCode,contentType:e.contentType,external:false})),...cr.externalDependencies.map(url=>({scanId:scan.id,url,method:'EXTERNAL_DEPENDENCY',external:true}))],skipDuplicates:true});
   const applicationMap=buildApplicationMap({pages:cr.pages,endpoints:cr.endpoints,scripts:cr.scripts,externalDependencies:cr.externalDependencies,rootHeaders:recon.headers,rootBody:recon.body});
   await log(scan.id,'Endpoint Discovery','Application map built',{surfaces:applicationMap.surfaces.length,auth:applicationMap.authUrls.length,api:applicationMap.apiUrls.length,admin:applicationMap.adminUrls.length,uploads:applicationMap.uploadUrls.length,payments:applicationMap.paymentUrls.length,graphql:applicationMap.graphqlUrls.length,apiDocs:applicationMap.apiDocsUrls.length,websockets:applicationMap.websocketUrls.length,technologies:applicationMap.technologies,externalDependencies:applicationMap.externalDependencies});
   let selectedChecks=retestFinding?retestChecks:checks;
   let agentPlan:any=scan.agentPlan||null;
   if(!retestFinding){
     await db.scan.update({where:{id:scan.id},data:{stage:'AI Planning',progress:30}});
     const plan=await buildAgentPlan(scan.agentPrompt||undefined,applicationMap,checks);
     if(plan){
       agentPlan=plan;
       const wanted=new Set(plan.focusCheckIds);selectedChecks=checks.filter(c=>wanted.has(c.id));
       await db.scan.update({where:{id:scan.id},data:{agentPlan:plan as any}});
       await log(scan.id,'AI Planning','DeepSeek Flash prioritized registered scanner modules',{model:'deepseek-flash',checks:selectedChecks.map(c=>c.id),rationale:plan.rationale,priorities:plan.priorities});
     }else await log(scan.id,'AI Planning','DeepSeek Flash unavailable; using complete registered safe check set',{checks:checks.map(c=>c.id)});
   }
   const ctx:ScanContext={assetUrl:scan.asset.baseUrl,scope,http,pages:cr.pages,endpoints:cr.endpoints,scripts:cr.scripts,applicationMap,testIdentities,testResources,resolvedIdentityHeaders,isCanceled};
   const stages=['Header Analysis','API Analysis','Authentication Analysis','Client-Side Analysis','Safe Vulnerability Checks'];
   const findings=await runChecks(ctx,selectedChecks,async(check,i)=>{const stage=retestFinding?'Focused Retest':stages[Math.min(i,stages.length-1)]!;await db.scan.update({where:{id:scan.id},data:{stage,progress:35+Math.floor((i/Math.max(selectedChecks.length,1))*50)}});await log(scan.id,stage,`Running ${check.name}`,retestFinding?{checkId:check.id,findingId:retestFinding.id}:undefined);},async(check,error,i)=>{const stage=retestFinding?'Focused Retest':stages[Math.min(i,stages.length-1)]!;const detail=error instanceof Error?error.message:String(error);await log(scan.id,stage,`${check.name} could not complete and was skipped: ${detail}`,{checkId:check.id,skipped:true,error:detail});});
   const saved=[];for(const f of findings)saved.push(await saveFinding(scan,f));
   const current=new Set(saved.map(x=>x.fingerprint));
   if(retestFinding){const reproduced=current.has(retestFinding.fingerprint);if(reproduced){await db.finding.update({where:{id:retestFinding.id},data:{status:FindingStatus.OPEN,lastSeenAt:new Date()}});await db.findingEvent.create({data:{findingId:retestFinding.id,type:'RETEST_STILL_VULNERABLE',message:`Focused retest ${scan.id} reproduced the original finding.`}});}else{await db.finding.update({where:{id:retestFinding.id},data:{status:FindingStatus.FIXED}});await db.findingEvent.create({data:{findingId:retestFinding.id,type:findings.length?'RETEST_CHANGED_BEHAVIOR':'RETEST_FIXED',message:findings.length?`Original fingerprint was not reproduced by focused retest ${scan.id}; related changed behavior was recorded separately.`:`Focused retest ${scan.id} did not reproduce the original behavior.`}});}}
   else{const prior=await db.finding.findMany({where:{assetId:scan.assetId,status:FindingStatus.OPEN,NOT:{scanId:scan.id}}});for(const f of prior)if(!current.has(f.fingerprint)){await db.finding.update({where:{id:f.id},data:{status:FindingStatus.FIXED}});await db.findingEvent.create({data:{findingId:f.id,type:'NOT_REPRODUCED',message:`Not reproduced by scan ${scan.id}; historical evidence retained.`}});}}

   await db.scan.update({where:{id:scan.id},data:{stage:'DeepSeek Report',progress:92}});
   await log(scan.id,'DeepSeek Report','Generating complete executive and technical assessment report with DeepSeek Flash',{model:'deepseek-flash',findings:findings.length});
   const report=await generateSecurityReport({
     target:scan.asset.baseUrl,
     scanId:scan.id,
     prompt:scan.agentPrompt,
     plan:agentPlan,
     findings:findings.map(f=>({title:f.title,severity:f.severity,confidence:f.confidence,category:f.category,affectedUrl:f.affectedUrl,method:f.method,description:f.description,impact:f.impact,remediation:f.remediation,status:'OPEN'})),
     endpointCount:cr.endpoints.length,
     pageCount:cr.pages.length,
     requestCount:http.count,
     technologies:applicationMap.technologies,
     selectedChecks:selectedChecks.map(c=>c.id),
     scope
   });

   const completedAt=new Date();
   await db.scan.update({where:{id:scan.id},data:{status:ScanStatus.COMPLETED,stage:'Report Ready',progress:100,agentReport:report as any,completedAt}});
   await db.scanJob.updateMany({where:{scanId:scan.id},data:{status:JobStatus.COMPLETED,completedAt}});
   await log(scan.id,'Report Ready',retestFinding?`Focused retest completed with ${findings.length} matching/related observations`:`Completed with ${findings.length} findings and a full ${report.generatedBy==='deepseek-flash'?'DeepSeek Flash':'fallback'} report`,{requests:http.count,pages:cr.pages.length,surfaces:applicationMap.surfaces.length,retestFindingId,authorizedIdentityPlans:testResources.length,resolvedIdentityProfiles:Object.keys(resolvedIdentityHeaders).length,selectedChecks:selectedChecks.map(c=>c.id),reportProvider:report.generatedBy});return {findings:findings.length,retestFindingId,reportProvider:report.generatedBy};
 }catch(e){const cancel=String(e).includes('SCAN_CANCELED')||await canceled(scan.id)||Date.now()>deadline;await db.scan.update({where:{id:scan.id},data:{status:cancel?ScanStatus.CANCELED:ScanStatus.FAILED,stage:cancel?'Canceled':'Failed',completedAt:new Date()}});await db.scanJob.updateMany({where:{scanId:scan.id},data:{status:cancel?JobStatus.CANCELED:JobStatus.FAILED,errorMessage:cancel?undefined:String(e),completedAt:new Date()}});if(retestFinding)await db.findingEvent.create({data:{findingId:retestFinding.id,type:'RETEST_FAILED',message:`Focused retest failed safely: ${String(e).slice(0,300)}`}});throw e;}
 finally{await http.close();}
},{connection:redis,concurrency:cfg.WORKER_CONCURRENCY});
worker.on('failed',(job,err)=>console.error('scan failed',job?.id,err));console.log('Xdigitex security worker online');
