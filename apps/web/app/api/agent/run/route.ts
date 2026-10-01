import { NextResponse } from 'next/server';
import { z } from 'zod';
import { requireOrg } from '../../../../lib/auth';
import { db } from '@xdigitex/database';
import { scanQueue } from '../../../../lib/queue';
import { audit } from '../../../../lib/audit';
import { env } from '@xdigitex/shared';
import { enforceRateLimit } from '../../../../lib/rate-limit';

const input=z.object({prompt:z.string().trim().min(8).max(3000)});
function extractUrl(prompt:string){const m=prompt.match(/https?:\/\/[^\s<>"']+/i);if(!m)return null;try{const u=new URL(m[0]);u.hash='';return u;}catch{return null;}}

export async function POST(req:Request){
  const {user,org}=await requireOrg();
  await enforceRateLimit(`agent-run:${user.id}`,6,60);
  const form=Object.fromEntries(await req.formData());
  const {prompt}=input.parse(form);
  const target=extractUrl(prompt);
  if(!target)return new NextResponse('Include a full site URL such as https://example.com in the prompt.',{status:400});
  const asset=await db.asset.findFirst({where:{organizationId:org.id,normalizedHost:target.hostname.toLowerCase(),verifiedAt:{not:null},scanningEnabled:true}});
  if(!asset)return new NextResponse('This site must first be added and ownership-verified as an enabled asset.',{status:403});
  const assetOrigin=new URL(asset.baseUrl);
  if(assetOrigin.protocol!==target.protocol)return new NextResponse('Prompt URL must use the verified asset protocol.',{status:400});
  const c=env();
  const scope={allowedHosts:[asset.normalizedHost],allowedProtocols:[assetOrigin.protocol.slice(0,-1)],maxDepth:5,maxPages:c.MAX_PAGES,maxRequests:c.MAX_REQUESTS,maxRequestsPerSecond:c.MAX_REQUESTS_PER_SECOND,allowSubdomains:false};
  const scan=await db.scan.create({data:{organizationId:org.id,assetId:asset.id,scope,agentPrompt:prompt,jobs:{create:{}}},include:{jobs:true}});
  const job=await scanQueue.add('scan',{scanId:scan.id},{removeOnComplete:100,removeOnFail:500,attempts:1});
  await db.scanJob.update({where:{id:scan.jobs[0]!.id},data:{queueJobId:String(job.id)}});
  await audit(org.id,user.id,'agent.scan.started','Scan',scan.id,{assetId:asset.id,target:target.origin,deepseekModel:c.DEEPSEEK_MODEL});
  return NextResponse.redirect(new URL(`/scans/${scan.id}`,req.url),303);
}
