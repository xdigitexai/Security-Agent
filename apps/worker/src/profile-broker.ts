const LOOPBACK=new Set(['127.0.0.1','localhost','::1','[::1]']);

export async function resolveRequestProfile(brokerUrl:string|undefined,credentialRef:string):Promise<Record<string,string>|null>{
  if(!brokerUrl) return null;
  const base=new URL(brokerUrl);
  if(!LOOPBACK.has(base.hostname)) throw new Error('IDENTITY_PROFILE_BROKER_MUST_BE_LOOPBACK');
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),3000);
  try{
    const response=await fetch(new URL('/resolve',base),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credentialRef}),signal:controller.signal});
    if(!response.ok) return null;
    const data=await response.json() as {headers?:unknown};
    if(!data.headers||typeof data.headers!=='object'||Array.isArray(data.headers)) return null;
    const headers:Record<string,string>={};
    for(const [key,value] of Object.entries(data.headers as Record<string,unknown>)) if(typeof value==='string') headers[key.toLowerCase()]=value;
    return Object.keys(headers).length?headers:null;
  } finally {clearTimeout(timer);}
}
