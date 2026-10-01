import type { ScanScope, SecurityFinding, DiscoveredEndpointInput, ApplicationMap, AuthorizedTestIdentity, AuthorizedTestResource } from '@xdigitex/types';
import { ScanHttpClient } from './http-client';
export interface ScanContext { assetUrl:string; scope:ScanScope; http:ScanHttpClient; pages:string[]; endpoints:DiscoveredEndpointInput[]; scripts:string[]; applicationMap:ApplicationMap; testIdentities:AuthorizedTestIdentity[]; testResources:AuthorizedTestResource[]; resolvedIdentityHeaders:Record<string,Record<string,string>>; isCanceled:()=>Promise<boolean>; }
export interface SecurityCheck { id:string; name:string; category:string; run(context:ScanContext):Promise<SecurityFinding[]>; }
export async function runChecks(context:ScanContext, checks:SecurityCheck[], onCheck?:(check:SecurityCheck,index:number)=>Promise<void>){
  const findings:SecurityFinding[]=[];
  for(let i=0;i<checks.length;i++){
    if(await context.isCanceled()) throw new Error('SCAN_CANCELED');
    if(onCheck) await onCheck(checks[i]!,i);
    findings.push(...await checks[i]!.run(context));
  }
  return findings;
}
