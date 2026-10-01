import dns,{Resolver} from 'node:dns/promises';
import net from 'node:net';

const blockedNames=new Set(['localhost','localhost.localdomain','metadata.google.internal','instance-data','metadata']);
const fallbackDnsServers=['1.1.1.1','8.8.8.8'];
function ipv4ToInt(ip:string){return ip.split('.').reduce((n,p)=>(n<<8)+Number(p),0)>>>0;}
function inV4(ip:string,cidr:string,bits:number){const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;return (ipv4ToInt(ip)&mask)===(ipv4ToInt(cidr)&mask);}
export function isBlockedIp(ip:string):boolean{
  if(net.isIPv4(ip))return [
    ['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.168.0.0',16],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]
  ].some(([c,b])=>inV4(ip,c as string,b as number));
  if(net.isIPv6(ip)){
    const x=ip.toLowerCase();
    return x==='::1'||x==='::'||x.startsWith('fc')||x.startsWith('fd')||x.startsWith('fe8')||x.startsWith('fe9')||x.startsWith('fea')||x.startsWith('feb')||x.startsWith('ff')||x.startsWith('2001:db8:');
  }
  return true;
}

async function resolveWithSystemDns(host:string):Promise<string[]>{
  const answers=await dns.lookup(host,{all:true,verbatim:true});
  return [...new Set(answers.map(a=>String(a.address)))];
}

async function resolveWithPublicDns(host:string):Promise<string[]>{
  const resolver=new Resolver();
  resolver.setServers(fallbackDnsServers);
  const [v4,v6]=await Promise.allSettled([resolver.resolve4(host),resolver.resolve6(host)]);
  const ips:string[]=[];
  if(v4.status==='fulfilled')ips.push(...v4.value);
  if(v6.status==='fulfilled')ips.push(...v6.value);
  return [...new Set(ips)];
}

export async function resolvePublic(hostname:string):Promise<string[]>{
  const host=hostname.replace(/\.$/,'').toLowerCase();
  if(blockedNames.has(host)||host.endsWith('.local')||host.endsWith('.internal'))throw new Error('SSRF_BLOCKED_HOST');
  if(net.isIP(host)){
    if(isBlockedIp(host))throw new Error('SSRF_BLOCKED_IP');
    return [host];
  }

  let ips:string[]=[];
  try{ips=await resolveWithSystemDns(host);}catch{}
  if(!ips.length){
    try{ips=await resolveWithPublicDns(host);}catch{}
  }
  if(!ips.length)throw new Error('DNS_NO_ANSWERS');
  if(ips.some(isBlockedIp))throw new Error('SSRF_BLOCKED_RESOLUTION');
  return ips;
}
