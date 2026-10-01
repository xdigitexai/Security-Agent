import { NextResponse } from 'next/server';
import { requireOrg } from '../../../lib/auth';
import { db } from '@xdigitex/database';
import { normalizeUrl, resolvePublic } from '@xdigitex/scanner-core';
import { audit } from '../../../lib/audit';

export async function POST(req:Request){
  const {user,org}=await requireOrg();
  const form=await req.formData();
  let rawUrl=String(form.get('url')||'').trim();
  const requestedName=String(form.get('name')||'').trim();
  if(!rawUrl)return new NextResponse('Enter a domain or website URL.',{status:400});
  if(requestedName.length>100)return new NextResponse('Asset name must be 100 characters or fewer.',{status:400});
  if(!/^https?:\/\//i.test(rawUrl))rawUrl=`https://${rawUrl}`;

  let u:URL;
  try{
    u=normalizeUrl(rawUrl);
    await resolvePublic(u.hostname);
  }catch{
    return new NextResponse('That website could not be resolved to a public HTTP/HTTPS target. Check the domain and try again.',{status:400});
  }

  const existing=await db.asset.findFirst({where:{organizationId:org.id,normalizedHost:u.hostname}});
  if(existing)return NextResponse.redirect(new URL(`/assets/${existing.id}`,req.url),303);

  const a=await db.asset.create({
    data:{organizationId:org.id,name:requestedName||u.hostname,baseUrl:u.origin,normalizedHost:u.hostname}
  });
  await audit(org.id,user.id,'domain.added','Asset',a.id,{host:a.normalizedHost});
  return NextResponse.redirect(new URL(`/assets/${a.id}`,req.url),303);
}
