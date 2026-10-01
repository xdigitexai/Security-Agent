import dns from 'node:dns/promises';
import { validateScopedUrl, defaultScope, ScanHttpClient } from '@xdigitex/scanner-core';
import type { VerificationMethod } from '@xdigitex/database';

export interface OwnershipVerificationResult {
  ok:boolean;
  reason:string;
  checked?:string;
}

const marker=(token:string)=>`xdigitex-security-verification=${token}`;
const wait=(ms:number)=>new Promise<never>((_,reject)=>setTimeout(()=>reject(new Error('VERIFICATION_TIMEOUT')),ms));

function metaMatches(body:string,token:string){
  const tags=body.match(/<meta\b[^>]*>/gi)||[];
  const name=/\bname\s*=\s*["']xdigitex-security-verification["']/i;
  const escaped=token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const content=new RegExp(`\\bcontent\\s*=\\s*["']${escaped}["']`,'i');
  return tags.some(tag=>name.test(tag)&&content.test(tag));
}

function readableError(error:unknown){
  const text=String(error);
  if(/abort|timeout/i.test(text)) return 'Verification request timed out. Confirm the proof URL is publicly reachable and try again.';
  if(/ENOTFOUND|EAI_AGAIN|DNS/i.test(text)) return 'The domain could not be resolved from the verification server yet.';
  if(/SSRF_BLOCKED/i.test(text)) return 'The verification target resolved to a private or blocked network address.';
  return 'The verification proof could not be reached yet. Confirm it is publicly available and try again.';
}

export async function verifyOwnership(baseUrl:string,method:VerificationMethod,token:string):Promise<OwnershipVerificationResult>{
  const u=new URL(baseUrl);
  if(method==='DNS_TXT'){
    try{
      const rows=await Promise.race([dns.resolveTxt(u.hostname),wait(5000)]);
      const expected=marker(token);
      const values=rows.map(parts=>parts.join(''));
      const ok=values.some(value=>value.trim()===expected||value.includes(expected));
      return ok
        ? {ok:true,reason:'DNS TXT ownership proof found.',checked:u.hostname}
        : {ok:false,reason:`DNS TXT record not found yet. Add ${expected} at the root/apex (@) of ${u.hostname}, then retry.`,checked:u.hostname};
    }catch(error){return {ok:false,reason:readableError(error),checked:u.hostname};}
  }

  const scope=defaultScope(u.hostname,u.protocol==='http:'?'http':'https');
  await validateScopedUrl(u,scope);
  const http=new ScanHttpClient(scope);
  try{
    if(method==='FILE'){
      const paths=[
        '/xdigitex-security-verification.html',
        '/.well-known/xdigitex-security-verification.html',
        '/.well-known/xdigitex-security-verification.txt'
      ];
      const checks=await Promise.all(paths.map(async path=>{
        const url=new URL(path,u).toString();
        try{
          const r=await http.request(url,{},6000);
          if(r.status!==200)return {ok:false,path,url,reason:`${path} returned HTTP ${r.status}.`};
          const body=r.body.trim();
          const ok=body===token||body.includes(marker(token))||metaMatches(body,token);
          return ok
            ? {ok:true,path,url,reason:'HTML verification file found.'}
            : {ok:false,path,url,reason:`${path} is reachable but does not contain the current verification token.`};
        }catch(error){return {ok:false,path,url,reason:readableError(error)};}
      }));
      const match=checks.find(check=>check.ok);
      if(match)return {ok:true,reason:match.reason,checked:match.url};
      const primary=checks[0];
      return {ok:false,reason:`${primary?.reason||'HTML verification file not found yet.'} Upload the generated HTML file to your site root as /xdigitex-security-verification.html and retry.`,checked:new URL('/xdigitex-security-verification.html',u).toString()};
    }

    try{
      const r=await http.request(u.toString(),{},6000);
      if(r.status<200||r.status>=400)return {ok:false,reason:`Homepage returned HTTP ${r.status}; the verification meta tag could not be confirmed.`,checked:u.toString()};
      const ok=metaMatches(r.body,token);
      return ok
        ? {ok:true,reason:'HTML meta ownership proof found.',checked:u.toString()}
        : {ok:false,reason:'Verification meta tag not found on the public homepage yet. Publish it in the <head> and retry.',checked:u.toString()};
    }catch(error){return {ok:false,reason:readableError(error),checked:u.toString()};}
  }finally{await http.close();}
}
