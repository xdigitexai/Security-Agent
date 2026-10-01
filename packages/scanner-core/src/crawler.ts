import { chromium } from 'playwright';
import type { DiscoveredEndpointInput, ScanScope } from '@xdigitex/types';
import { hostAllowed, validateScopedUrl } from './scope';

export interface CrawlResult { pages:string[]; endpoints:DiscoveredEndpointInput[]; scripts:string[]; externalDependencies:string[]; }
export async function crawl(startUrl:string, scope:ScanScope, isCanceled:()=>Promise<boolean>):Promise<CrawlResult>{
  await validateScopedUrl(startUrl,scope);
  const browser=await chromium.launch({headless:true});
  const context=await browser.newContext({serviceWorkers:'block'});
  const queue:[string,number][]=[[startUrl,0]]; const seen=new Set<string>(); const endpoints=new Map<string,DiscoveredEndpointInput>(); const scripts=new Set<string>(); const external=new Set<string>();
  try{
    while(queue.length && seen.size<Math.min(scope.maxPages,500)){
      if(await isCanceled()) throw new Error('SCAN_CANCELED');
      const [url,depth]=queue.shift()!; if(seen.has(url)||depth>scope.maxDepth) continue;
      const safe=await validateScopedUrl(url,scope); seen.add(safe.toString());
      const page=await context.newPage();
      page.on('request',req=>{ try{ const u=new URL(req.url()); if(hostAllowed(u.hostname,scope)) endpoints.set(`${req.method()} ${u}`,{url:u.toString(),method:req.method()}); else external.add(u.origin);}catch{} });
      await page.route('**/*',async route=>{ try{ const u=new URL(route.request().url()); if(!hostAllowed(u.hostname,scope)){external.add(u.origin);return route.abort();} await validateScopedUrl(u,scope); return route.continue(); }catch{return route.abort();} });
      try{
        await page.goto(safe.toString(),{waitUntil:'domcontentloaded',timeout:15000});
        const data=await page.evaluate(()=>({links:[...document.querySelectorAll('a[href]')].map(a=>(a as HTMLAnchorElement).href),scripts:[...document.scripts].map(s=>s.src).filter(Boolean),forms:[...document.querySelectorAll('form')].map(f=>({action:(f as HTMLFormElement).action,method:(f as HTMLFormElement).method||'GET',names:[...f.querySelectorAll('input,select,textarea')].map(i=>(i as HTMLInputElement).name).filter(Boolean)}))}));
        for(const s of data.scripts) scripts.add(s);
        for(const f of data.forms){ try{const u=new URL(f.action||safe.toString()); if(hostAllowed(u.hostname,scope)) endpoints.set(`${f.method.toUpperCase()} ${u}`,{url:u.toString(),method:f.method.toUpperCase(),parameters:f.names});}catch{} }
        for(const href of data.links){ try{const u=new URL(href); u.hash=''; if(hostAllowed(u.hostname,scope)) queue.push([u.toString(),depth+1]); else external.add(u.origin);}catch{} }
      } finally { await page.close(); }
    }
  } finally { await context.close(); await browser.close(); }
  return {pages:[...seen],endpoints:[...endpoints.values()],scripts:[...scripts],externalDependencies:[...external]};
}
