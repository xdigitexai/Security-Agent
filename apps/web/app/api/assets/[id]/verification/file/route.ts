import { NextResponse } from 'next/server';
import { requireOrg } from '../../../../../../lib/auth';
import { db } from '@xdigitex/database';

export async function GET(_req:Request,{params}:{params:Promise<{id:string}>}){
  const {org}=await requireOrg();
  const {id}=await params;
  const asset=await db.asset.findFirst({
    where:{id,organizationId:org.id},
    include:{verifications:{where:{status:'PENDING',method:'FILE'},orderBy:{createdAt:'desc'},take:1}}
  });
  if(!asset||!asset.verifications[0])return new NextResponse('No pending HTML-file verification for this asset.',{status:404});
  const token=asset.verifications[0].token;
  const html=`<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="xdigitex-security-verification" content="${token}">\n<title>Xdigitex ownership verification</title>\n</head>\n<body>\nxdigitex-security-verification=${token}\n</body>\n</html>\n`;
  return new NextResponse(html,{headers:{
    'content-type':'text/html; charset=utf-8',
    'content-disposition':'attachment; filename="xdigitex-security-verification.html"',
    'cache-control':'private, no-store'
  }});
}
