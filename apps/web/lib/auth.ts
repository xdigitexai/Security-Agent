import { SignJWT, jwtVerify } from 'jose'; import { cookies } from 'next/headers'; import { env } from '@xdigitex/shared'; import { db } from '@xdigitex/database';
const key=()=>new TextEncoder().encode(env().SESSION_SECRET);
export async function createSession(userId:string){const token=await new SignJWT({sub:userId}).setProtectedHeader({alg:'HS256'}).setIssuedAt().setExpirationTime('12h').sign(key());(await cookies()).set('xd_session',token,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge:43200});}
export async function destroySession(){(await cookies()).set('xd_session','',{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge:0});}
export async function currentUser(){try{const token=(await cookies()).get('xd_session')?.value;if(!token)return null;const {payload}=await jwtVerify(token,key());if(!payload.sub)return null;return db.user.findUnique({where:{id:payload.sub},include:{memberships:{include:{organization:true}}}});}catch{return null;}}
export async function requireUser(){const u=await currentUser();if(!u)throw new Error('UNAUTHENTICATED');return u;}
export async function requireOrg(){const u=await requireUser();const m=u.memberships[0];if(!m)throw new Error('NO_ORGANIZATION');return {user:u,org:m.organization,role:m.role};}
