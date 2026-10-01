import Bottleneck from 'bottleneck';
import { Agent, fetch, type RequestInit } from 'undici';
import dns from 'node:dns';
import { isBlockedIp } from './ssrf';
import { validateScopedUrl } from './scope';
import { redactHeaders, redactText, env } from '@xdigitex/shared';
import type { ScanScope, EvidenceInput } from '@xdigitex/types';

export interface ScanResponse { url:string; status:number; headers:Record<string,string>; body:string; evidence:EvidenceInput; }
export class ScanHttpClient {
  private requestCount=0;
  private limiter: Bottleneck;
  private dispatcher: Agent;
  constructor(private scope:ScanScope) {
    const cfg=env();
    this.limiter=new Bottleneck({maxConcurrent:Math.min(cfg.MAX_CONCURRENT_REQUESTS,5),minTime:Math.ceil(1000/Math.min(scope.maxRequestsPerSecond,cfg.MAX_REQUESTS_PER_SECOND,5))});
    this.dispatcher=new Agent({connect:{lookup:(hostname, options, cb)=>{
      dns.lookup(hostname,{all:true,verbatim:true},(err,addresses)=>{
        if(err) return cb(err,undefined as never);
        if(!addresses.length || addresses.some(a=>isBlockedIp(a.address))) return cb(new Error('SSRF_BLOCKED_DNS_REBIND'),undefined as never);
        const first=addresses[0]!;
        cb(null, first.address, first.family);
      });
    }}});
  }
  async request(input:string, init:RequestInit={}):Promise<ScanResponse>{
    return this.limiter.schedule(async()=>{
      if(++this.requestCount>Math.min(this.scope.maxRequests,5000)) throw new Error('SCAN_REQUEST_LIMIT');
      let current=await validateScopedUrl(input,this.scope);
      const cfg=env();
      for(let redirects=0;redirects<=5;redirects++){
        const controller=new AbortController(); const timer=setTimeout(()=>controller.abort(),15000);
        try {
          const res=await fetch(current,{...init,headers:{'user-agent':cfg.SCAN_USER_AGENT,...(init.headers as Record<string,string>|undefined)},redirect:'manual',signal:controller.signal,dispatcher:this.dispatcher});
          const location=res.headers.get('location');
          if(location && [301,302,303,307,308].includes(res.status)){
            if(redirects===5) throw new Error('REDIRECT_LIMIT');
            current=await validateScopedUrl(new URL(location,current),this.scope);
            continue;
          }
          const contentLength=Number(res.headers.get('content-length')||0);
          if(contentLength>cfg.MAX_RESPONSE_SIZE) throw new Error('RESPONSE_TOO_LARGE');
          const reader=res.body?.getReader(); let total=0; const chunks:Uint8Array[]=[];
          while(reader){ const {done,value}=await reader.read(); if(done) break; total+=value.length; if(total>cfg.MAX_RESPONSE_SIZE){await reader.cancel();throw new Error('RESPONSE_TOO_LARGE');} chunks.push(value); }
          const body=new TextDecoder().decode(Buffer.concat(chunks.map(c=>Buffer.from(c))));
          const headers=Object.fromEntries(res.headers.entries());
          return {url:current.toString(),status:res.status,headers,body,evidence:{requestMethod:(init.method||'GET').toString(),requestUrl:current.toString(),requestHeaders:redactHeaders((init.headers as Record<string,string>)||{}),requestBody:redactText(typeof init.body==='string'?init.body:undefined),responseStatus:res.status,responseHeaders:redactHeaders(headers),responseExcerpt:redactText(body.slice(0,2048)),timestamp:new Date()}};
        } finally { clearTimeout(timer); }
      }
      throw new Error('UNREACHABLE');
    });
  }
  get count(){return this.requestCount;}
  async close(){await this.dispatcher.close();}
}
