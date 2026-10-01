import { NextResponse } from 'next/server';
import { requireOrg } from '../../../../../lib/auth';
import { db } from '@xdigitex/database';

export async function POST(req:Request,{params}:{params:Promise<{id:string}>}){
  const {user,org,role}=await requireOrg();
  if(!['OWNER','ADMIN'].includes(role)) return new NextResponse('Forbidden',{status:403});
  const {id}=await params;
  const asset=await db.asset.findFirst({where:{id,organizationId:org.id}});
  if(!asset?.verifiedAt) return new NextResponse('Verified asset required',{status:400});
  const form=await req.formData();
  const label=String(form.get('label')||'').trim();
  const roleLabel=String(form.get('roleLabel')||'').trim();
  const tenantLabel=String(form.get('tenantLabel')||'').trim()||null;
  const authType=String(form.get('authType')||'');
  const credentialRef=String(form.get('credentialRef')||'').trim();
  const expectedSessionState=String(form.get('expectedSessionState')||'ACTIVE');
  if(!label||!roleLabel||!credentialRef||!['BEARER','COOKIE','HEADERS'].includes(authType)||!['ACTIVE','REVOKED'].includes(expectedSessionState)) return new NextResponse('Invalid identity',{status:400});
  if(!/^[A-Z][A-Z0-9_]{2,100}$/.test(credentialRef)) return new NextResponse('Credential reference must be an environment-style name',{status:400});
  await db.testIdentity.create({data:{assetId:id,label,roleLabel,tenantLabel,authType:authType as any,credentialRef,expectedSessionState:expectedSessionState as any}});
  await db.auditLog.create({data:{organizationId:org.id,actorUserId:user.id,action:'test_identity.created',targetType:'Asset',targetId:id,metadata:{label,roleLabel,tenantLabel,authType,credentialRef,expectedSessionState}}});
  return NextResponse.redirect(new URL(`/assets/${id}`,req.url),303);
}
