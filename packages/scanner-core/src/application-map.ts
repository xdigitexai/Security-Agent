import type { ApplicationMap, ApplicationSurface, ApplicationSurfaceKind, DiscoveredEndpointInput } from '@xdigitex/types';

function classify(raw:string, method:string):ApplicationSurfaceKind {
  let p=''; try{p=new URL(raw).pathname.toLowerCase();}catch{return 'OTHER';}
  if(method==='WEBSOCKET'||raw.startsWith('ws:')||raw.startsWith('wss:')) return 'WEBSOCKET';
  if(/\/(?:swagger|openapi|api-docs)(?:\/|$)|\/docs\/(?:api|openapi)/.test(p)) return 'API_DOCS';
  if(/\/(?:graphql|graphiql)(?:\/|$)/.test(p)) return 'GRAPHQL';
  if(/\/(?:login|signin|sign-in|signup|register|logout|password|forgot|reset|verify|verification|otp|mfa|oauth|auth)(?:\/|$)/.test(p)) return 'AUTH';
  if(/\/(?:admin|administrator|staff|backoffice|back-office|moderator)(?:\/|$)/.test(p)) return 'ADMIN';
  if(/\/(?:upload|uploads|attachment|attachments|media|files)(?:\/|$)/.test(p)) return 'UPLOAD';
  if(/\/(?:checkout|payment|payments|billing|invoice|subscription|subscriptions|coupon|coupons|wallet|balance|transaction|transactions)(?:\/|$)/.test(p)) return 'PAYMENT';
  if(/\/(?:account|profile|settings|user|users|organization|organisations|organizations)(?:\/|$)/.test(p)) return 'ACCOUNT';
  if(/\/(?:search|query)(?:\/|$)/.test(p)) return 'SEARCH';
  if(/\/(?:api|v\d+)(?:\/|$)/.test(p)) return 'API';
  return 'OTHER';
}
function tech(name:string,evidence:string,out:Map<string,string>){if(!out.has(name))out.set(name,evidence.slice(0,180));}
export function buildApplicationMap(input:{pages:string[];endpoints:DiscoveredEndpointInput[];scripts:string[];externalDependencies:string[];rootHeaders?:Record<string,string>;rootBody?:string;}):ApplicationMap{
  const surfaces=new Map<string,ApplicationSurface>();
  const add=(url:string,method:string,source:ApplicationSurface['source'],parameters?:string[])=>{const kind=classify(url,method);if(kind==='OTHER'&&source==='script')return;const key=`${method} ${url}`;surfaces.set(key,{kind,url,method,source,parameters});};
  for(const p of input.pages)add(p,'GET','page');
  for(const e of input.endpoints)add(e.url,e.method,'network',e.parameters);
  for(const s of input.scripts)add(s,'GET','script');
  const technologies=new Map<string,string>(); const h=input.rootHeaders||{}; const body=input.rootBody||'';
  if(h.server)tech(h.server.split('/')[0]||'Server',`server: ${h.server}`,technologies);
  if(h['x-powered-by'])tech(h['x-powered-by'],`x-powered-by: ${h['x-powered-by']}`,technologies);
  if(h['cf-ray']||/cloudflare/i.test(h.server||''))tech('Cloudflare','Cloudflare response headers',technologies);
  if(/__NEXT_DATA__|\/_next\//i.test(body))tech('Next.js','Next.js bootstrap/static markers',technologies);
  if(/data-reactroot|react(?:\.production)?\.min\.js|\/_next\//i.test(body))tech('React','React/Next client markers',technologies);
  if(/__NUXT__|\/_nuxt\//i.test(body))tech('Nuxt/Vue','Nuxt client markers',technologies);
  if(/ng-version=|angular/i.test(body))tech('Angular','Angular client markers',technologies);
  const all=[...surfaces.values()]; const urls=(k:ApplicationSurfaceKind)=>[...new Set(all.filter(x=>x.kind===k).map(x=>x.url))];
  return {surfaces:all,technologies:[...technologies].map(([name,evidence])=>({name,evidence})),externalDependencies:[...new Set(input.externalDependencies)],authUrls:urls('AUTH'),apiUrls:urls('API'),adminUrls:urls('ADMIN'),uploadUrls:urls('UPLOAD'),paymentUrls:urls('PAYMENT'),graphqlUrls:urls('GRAPHQL'),apiDocsUrls:urls('API_DOCS'),websocketUrls:urls('WEBSOCKET')};
}
