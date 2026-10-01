import { NextResponse } from 'next/server';
import { z } from 'zod';
import { requireOrg } from '../../../../lib/auth';
import { db } from '@xdigitex/database';
import { scanQueue } from '../../../../lib/queue';
import { audit } from '../../../../lib/audit';
import { env } from '@xdigitex/shared';
import { enforceRateLimit } from '../../../../lib/rate-limit';
import { parseOrBadRequest } from '../../../../lib/validate';

const input=z.object({prompt:z.string().trim().min(8).max(6000)});

function extractUrl(prompt:string){
  const match=prompt.match(/https?:\/\/[^\s<>"']+/i);
  if(!match)return null;
  try{
    const url=new URL(match[0].replace(/[),.;!?]+$/,''));
    url.hash='';
    return url;
  }catch{return null;}
}

function promptMentionsHost(prompt:string,host:string){
  const escaped=host.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  return new RegExp(`(^|[^a-z0-9.-])${escaped}([^a-z0-9.-]|$)`,'i').test(prompt);
}

export async function POST(req:Request){
  const {user,org}=await requireOrg();
  await enforceRateLimit(`agent-run:${user.id}`,6,60);
  const parsed=parseOrBadRequest(input,Object.fromEntries(await req.formData()));
  if(!parsed.ok)return parsed.response;
  const {prompt}=parsed.data;

  const assets=await db.asset.findMany({
    where:{organizationId:org.id,verifiedAt:{not:null},scanningEnabled:true},
    orderBy:{createdAt:'desc'}
  });
  if(!assets.length)return new NextResponse('Add and ownership-verify at least one enabled asset before running the security agent.',{status:403});

  const explicitUrl=extractUrl(prompt);
  let asset=(explicitUrl
    ? assets.find(a=>a.normalizedHost===explicitUrl.hostname.toLowerCase())
    : undefined);

  if(explicitUrl&&!asset){
    return new NextResponse('The URL in this prompt is not one of your ownership-verified enabled assets.',{status:403});
  }

  if(!asset){
    const mentioned=assets.filter(a=>promptMentionsHost(prompt,a.normalizedHost));
    if(mentioned.length===1)asset=mentioned[0];
    else if(mentioned.length>1)return new NextResponse('Your prompt names more than one verified asset. Run one target per assessment.',{status:400});
    else if(assets.length===1)asset=assets[0];
    else return new NextResponse(`Name one verified target in the prompt. Available targets: ${assets.map(a=>a.normalizedHost).join(', ')}`,{status:400});
  }

  const assetOrigin=new URL(asset.baseUrl);
  if(explicitUrl&&assetOrigin.protocol!==explicitUrl.protocol){
    return new NextResponse('Prompt URL must use the verified asset protocol.',{status:400});
  }

  const c=env();
  const scope={
    allowedHosts:[asset.normalizedHost],
    allowedProtocols:[assetOrigin.protocol.slice(0,-1)],
    maxDepth:5,
    maxPages:c.MAX_PAGES,
    maxRequests:c.MAX_REQUESTS,
    maxRequestsPerSecond:c.MAX_REQUESTS_PER_SECOND,
    allowSubdomains:false
  };

  const scan=await db.scan.create({
    data:{organizationId:org.id,assetId:asset.id,scope,agentPrompt:prompt,jobs:{create:{}}},
    include:{jobs:true}
  });
  const job=await scanQueue.add('scan',{scanId:scan.id},{removeOnComplete:100,removeOnFail:500,attempts:1});
  await db.scanJob.update({where:{id:scan.jobs[0]!.id},data:{queueJobId:String(job.id)}});
  await audit(org.id,user.id,'agent.scan.started','Scan',scan.id,{
    assetId:asset.id,
    target:assetOrigin.origin,
    targetResolution:explicitUrl?'explicit-url':assets.length===1?'single-verified-asset':'prompt-host',
    deepseekModel:'deepseek-flash'
  });
  return NextResponse.redirect(new URL(`/scans/${scan.id}`,req.url),303);
}
