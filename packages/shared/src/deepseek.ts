import { env } from './env';

export async function deepseekJson<T>(system:string,user:string):Promise<T|null>{
  const cfg=env();
  if(!cfg.DEEPSEEK_API_KEY) return null;
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),45_000);
  try{
    const res=await fetch(`${cfg.DEEPSEEK_BASE_URL.replace(/\/$/,'')}/chat/completions`,{
      method:'POST',
      headers:{'content-type':'application/json','authorization':`Bearer ${cfg.DEEPSEEK_API_KEY}`},
      body:JSON.stringify({
        model:cfg.DEEPSEEK_MODEL,
        response_format:{type:'json_object'},
        temperature:0.1,
        max_tokens:3000,
        messages:[{role:'system',content:system},{role:'user',content:user}]
      }),
      signal:controller.signal
    });
    if(!res.ok) throw new Error(`DEEPSEEK_HTTP_${res.status}`);
    const json=await res.json() as any;
    const text=json?.choices?.[0]?.message?.content;
    if(typeof text!=='string'||!text.trim()) throw new Error('DEEPSEEK_EMPTY_RESPONSE');
    return JSON.parse(text) as T;
  }catch(e){
    console.error('DeepSeek request failed',String(e));
    return null;
  }finally{clearTimeout(timer);}
}
