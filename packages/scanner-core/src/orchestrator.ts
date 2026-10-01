import type { ScanScope, SecurityFinding, DiscoveredEndpointInput, ApplicationMap, AuthorizedTestIdentity, AuthorizedTestResource } from '@xdigitex/types';
import { ScanHttpClient } from './http-client';
export interface ScanContext { assetUrl:string; scope:ScanScope; http:ScanHttpClient; pages:string[]; endpoints:DiscoveredEndpointInput[]; scripts:string[]; applicationMap:ApplicationMap; testIdentities:AuthorizedTestIdentity[]; testResources:AuthorizedTestResource[]; resolvedIdentityHeaders:Record<string,Record<string,string>>; isCanceled:()=>Promise<boolean>; }
export interface SecurityCheck { id:string; name:string; category:string; run(context:ScanContext):Promise<SecurityFinding[]>; }
export async function runChecks(context:ScanContext, checks:SecurityCheck[], onCheck?:(check:SecurityCheck,index:number)=>Promise<void>, onCheckError?:(check:SecurityCheck,error:unknown,index:number)=>Promise<void>){
  const findings:SecurityFinding[]=[];
  for(let i=0;i<checks.length;i++){
    if(await context.isCanceled()) throw new Error('SCAN_CANCELED');
    if(onCheck) await onCheck(checks[i]!,i);
    try{
      findings.push(...await checks[i]!.run(context));
    }catch(error){
      // A canceled scan must stop, but a single failing check must not. One
      // check that cannot complete - for example one that reaches a URL outside
      // the authorized scope - previously aborted the whole assessment, so a
      // scan that had already mapped the application and planned its checks
      // finished with zero findings instead of the results of every other
      // check. Record the failure and carry on with the remaining checks.
      if(error instanceof Error&&error.message==='SCAN_CANCELED') throw error;
      if(onCheckError) await onCheckError(checks[i]!,error,i);
    }
  }
  return findings;
}
