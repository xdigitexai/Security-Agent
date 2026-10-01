import { NextResponse } from 'next/server';
import { requireOrg } from '../../../../../lib/auth';
import { db } from '@xdigitex/database';

export async function POST(req:Request,{params}:{params:Promise<{id:string}>}){
  const {user,org,role}=await requireOrg();
  if(!['OWNER','ADMIN'].includes(role)) return new NextResponse('Forbidden',{status:403});
  const {id}=await params;
  const asset=await db.asset.findFirst({where:{id,organizationId:org.id},include:{testIdentities:true}});
  if(!asset?.verifiedAt) return new NextResponse('Verified asset required',{status:400});
  const form=await req.formData();
  const label=String(form.get('label')||'').trim();
  const rawUrl=String(form.get('url')||'').trim();
  const method=String(form.get('method')||'GET').toUpperCase();
  const ownerIdentityId=String(form.get('ownerIdentityId')||'');
  const comparatorIdentityIds=form.getAll('comparatorIdentityIds').map(String);
  const expectation=String(form.get('expectation')||'DENY_COMPARATORS');
  const proofMarker=String(form.get('proofMarker')||'').trim()||null;
  if(!label||!['GET','HEAD'].includes(method)||!['DENY_COMPARATORS','PUBLIC'].includes(expectation)) return new NextResponse('Invalid resource',{status:400});
  let url:URL;try{url=new URL(rawUrl);}catch{return new NextResponse('Invalid URL',{status:400});}
  if(url.hostname!==asset.normalizedHost) return new NextResponse('Resource must stay on the verified host',{status:400});
  const known=new Set(asset.testIdentities.map(i=>i.id));
  if(!known.has(ownerIdentityId)||comparatorIdentityIds.some(x=>!known.has(x))) return new NextResponse('Unknown test identity',{status:400});
  await db.testResource.create({data:{assetId:id,label,url:url.toString(),method,ownerIdentityId,comparatorIdentityIds,expectation:expectation as any,proofMarker,safeReadOnly:true}});
  await db.auditLog.create({data:{organizationId:org.id,actorUserId:user.id,action:'test_resource.created',targetType:'Asset',targetId:id,metadata:{label,url:url.toString(),method,ownerIdentityId,comparatorCount:comparatorIdentityIds.length,expectation}}});
  return NextResponse.redirect(new URL(`/assets/${id}`,req.url),303);
}
