import { chromium } from 'playwright';
import type { DiscoveredEndpointInput, ScanScope } from '@xdigitex/types';
import { hostAllowed, validateScopedUrl } from './scope';

export interface CrawlResult { pages:string[]; endpoints:DiscoveredEndpointInput[]; scripts:string[]; externalDependencies:string[]; }

function queryParameters(u:URL){return [...new Set([...u.searchParams.keys()])].filter(Boolean).slice(0,40);}
function safePathCandidate(value:string){const v=value.trim();if(!v||v.length>500||v.startsWith('#')||/^(?:data|javascript|mailto|tel):/i.test(v))return null;if(/[{}<>\s]/.test(v))return null;return v;}
function scriptCandidates(source:string){
  const out=new Set<string>();const patterns=[/(?:fetch|open)\s*\(\s*["'`]([^"'`]+)["'`]/g,/axios(?:\.[a-z]+)?\s*\(\s*["'`]([^"'`]+)["'`]/gi,/["'`]((?:\/|https?:\/\/)[^"'`]{1,300}\/(?:api|auth|login|admin|account|graphql|upload|payment|billing|search)[^"'`]{0,300})["'`]/gi,/["'`]((?:\/api\/|\/v\d+\/)[^"'`]{1,300})["'`]/gi];
  for(const re of patterns){for(const match of source.matchAll(re)){const candidate=safePathCandidate(match[1]||'');if(candidate)out.add(candidate);if(out.size>=150)return [...out];}}
  return [...out];
}

export async function crawl(startUrl:string, scope:ScanScope, isCanceled:()=>Promise<boolean>):Promise<CrawlResult>{
  const start=await validateScopedUrl(startUrl,scope);const browser=await chromium.launch({headless:true});const context=await browser.newContext({serviceWorkers:'block'});
  const seedPaths=['/robots.txt','/sitemap.xml','/sitemap_index.xml','/.well-known/security.txt','/.well-known/openid-configuration','/login','/signin','/register','/admin','/administrator','/api','/api/v1','/graphql','/graphiql','/swagger','/swagger.json','/openapi.json','/api-docs','/health','/status','/debug'];
  const queue:[string,number][]=[[start.toString(),0],...seedPaths.map(path=>[new URL(path,start).toString(),0] as [string,number])];
  const attempted=new Set<string>();const pages=new Set<string>();const endpoints=new Map<string,DiscoveredEndpointInput>();const scripts=new Set<string>();const external=new Set<string>();
  const setEndpoint=(method:string,u:URL,extra:Partial<DiscoveredEndpointInput>={})=>{const key=`${method} ${u}`;const prior=endpoints.get(key);const params=queryParameters(u);endpoints.set(key,{url:u.toString(),method,parameters:extra.parameters??prior?.parameters??(params.length?params:undefined),responseCode:extra.responseCode??prior?.responseCode,contentType:extra.contentType??prior?.contentType});};
  const enqueue=(raw:string,base:string,depth:number,source:'link'|'script'|'discovery'='link')=>{try{const u=new URL(raw,base);u.hash='';if(!['http:','https:'].includes(u.protocol))return;if(hostAllowed(u.hostname,scope)){setEndpoint('GET',u);if(source!=='script'||depth<=scope.maxDepth)queue.push([u.toString(),depth]);}else external.add(u.origin);}catch{}};
  try{
    while(queue.length&&attempted.size<Math.min(scope.maxPages,500)){
      if(await isCanceled())throw new Error('SCAN_CANCELED');const [url,depth]=queue.shift()!;if(attempted.has(url)||depth>scope.maxDepth)continue;
      const safe=await validateScopedUrl(url,scope);attempted.add(safe.toString());const page=await context.newPage();
      page.on('request',req=>{try{const u=new URL(req.url());if(hostAllowed(u.hostname,scope))setEndpoint(req.method(),u);else external.add(u.origin);}catch{}});
      page.on('response',async res=>{try{const u=new URL(res.url());if(!hostAllowed(u.hostname,scope))return;const headers=await res.allHeaders();setEndpoint(res.request().method(),u,{responseCode:res.status(),contentType:headers['content-type']});}catch{}});
      page.on('websocket',ws=>{try{const u=new URL(ws.url());if(hostAllowed(u.hostname,scope))endpoints.set(`WEBSOCKET ${u}`,{url:u.toString(),method:'WEBSOCKET'});else external.add(u.origin);}catch{}});
      await page.route('**/*',async route=>{try{const u=new URL(route.request().url());if(!hostAllowed(u.hostname,scope)){external.add(u.origin);return route.abort();}await validateScopedUrl(u,scope);return route.continue();}catch{return route.abort();}});
      try{
        const response=await page.goto(safe.toString(),{waitUntil:'domcontentloaded',timeout:15000});const status=response?.status()||0;const responseHeaders=response?await response.allHeaders():{};const contentType=(responseHeaders['content-type']||'').toLowerCase();const pathname=safe.pathname.toLowerCase();
        if(!status||status===404||status===410)continue;pages.add(safe.toString());
        if((pathname.endsWith('/robots.txt')||pathname==='/robots.txt')&&status>=200&&status<300){const text=await page.locator('body').innerText().catch(()=> '');for(const line of text.split(/\r?\n/)){const sitemap=line.match(/^\s*Sitemap\s*:\s*(.+)$/i)?.[1];if(sitemap)enqueue(sitemap,safe.toString(),0,'discovery');const path=line.match(/^\s*(?:Allow|Disallow)\s*:\s*(\/[^\s#]*)/i)?.[1];if(path&&!/[*$]/.test(path))enqueue(path,safe.toString(),1,'discovery');}continue;}
        if((/(?:sitemap|xml)/i.test(pathname)||contentType.includes('xml'))&&status>=200&&status<300){const xml=await page.content().catch(()=> '');for(const match of xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi))enqueue(match[1]!,safe.toString(),1,'discovery');continue;}
        if(!contentType.includes('html')&&!contentType.includes('xhtml'))continue;
        const data=await page.evaluate(()=>({links:[...document.querySelectorAll('a[href],link[href]')].map(a=>(a as HTMLAnchorElement).href),scripts:[...document.scripts].map(s=>s.src).filter(Boolean),inline:[...document.scripts].map(s=>s.src?'':s.textContent||'').join('\n').slice(0,300000),forms:[...document.querySelectorAll('form')].map(f=>({action:(f as HTMLFormElement).action,method:(f as HTMLFormElement).method||'GET',names:[...f.querySelectorAll('input,select,textarea,button')].map(i=>(i as HTMLInputElement).name).filter(Boolean)}))}));
        for(const s of data.scripts){scripts.add(s);enqueue(s,safe.toString(),depth+1,'script');}
        for(const f of data.forms){try{const u=new URL(f.action||safe.toString());if(hostAllowed(u.hostname,scope))setEndpoint(f.method.toUpperCase(),u,{parameters:[...new Set(f.names)].slice(0,40)});}catch{}}
        for(const href of data.links)enqueue(href,safe.toString(),depth+1,'link');for(const candidate of scriptCandidates(data.inline))enqueue(candidate,safe.toString(),depth+1,'script');
      }finally{await page.close();}
    }
  }finally{await context.close();await browser.close();}
  return {pages:[...pages],endpoints:[...endpoints.values()],scripts:[...scripts],externalDependencies:[...external]};
}
