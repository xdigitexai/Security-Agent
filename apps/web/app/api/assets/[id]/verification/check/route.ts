import { NextResponse } from 'next/server';
import { requireOrg } from '../../../../../../lib/auth';
import { db } from '@xdigitex/database';
import { verifyOwnership, type OwnershipVerificationResult } from '../../../../../../lib/verification';
import { audit } from '../../../../../../lib/audit';

export async function POST(req:Request,{params}:{params:Promise<{id:string}>}){
  const {user,org}=await requireOrg();
  const {id}=await params;
  const a=await db.asset.findFirst({
    where:{id,organizationId:org.id},
    include:{verifications:{where:{status:'PENDING'},orderBy:{createdAt:'desc'},take:1}}
  });
  if(!a||!a.verifications[0])return new NextResponse('No pending verification. Create a new verification proof first.',{status:404});
  const v=a.verifications[0];
  if(v.expiresAt<new Date()){
    await db.assetVerification.update({where:{id:v.id},data:{status:'EXPIRED',failureReason:'Verification token expired. Create a new proof and try again.'}});
    return NextResponse.redirect(new URL(`/assets/${a.id}?verification=expired`,req.url),303);
  }

  let result:OwnershipVerificationResult;
  try{
    result=await verifyOwnership(a.baseUrl,v.method,v.token);
  }catch(error){
    result={ok:false,reason:`Verification could not complete safely: ${String(error).slice(0,180)}`};
  }

  if(result.ok){
    const now=new Date();
    await db.$transaction([
      db.assetVerification.update({where:{id:v.id},data:{status:'VERIFIED',verifiedAt:now,failureReason:null}}),
      db.asset.update({where:{id:a.id},data:{verifiedAt:now}})
    ]);
    await audit(org.id,user.id,'domain.verified','Asset',a.id,{method:v.method,checked:result.checked});
    return NextResponse.redirect(new URL(`/assets/${a.id}?verification=verified`,req.url),303);
  }

  await db.assetVerification.update({
    where:{id:v.id},
    data:{status:'PENDING',failureReason:result.reason}
  });
  await audit(org.id,user.id,'verification.check_failed','AssetVerification',v.id,{method:v.method,reason:result.reason,checked:result.checked});
  return NextResponse.redirect(new URL(`/assets/${a.id}?verification=failed`,req.url),303);
}
