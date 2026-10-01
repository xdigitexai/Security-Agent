import { describe,it,expect } from 'vitest';
import { controlledAuthorizationCheck, revokedSessionCheck } from './authorization';

function response(body:string,status=200){return {url:'https://app.test/api/resource/1',status,headers:{'content-type':'application/json'},body,evidence:{requestMethod:'GET',requestUrl:'https://app.test/api/resource/1',responseStatus:status,responseExcerpt:body,timestamp:new Date()}};}
function baseContext(){
  const calls:{headers?:Record<string,string>}[]=[];
  const ctx:any={
    assetUrl:'https://app.test',scope:{},pages:[],endpoints:[],scripts:[],applicationMap:{surfaces:[],technologies:[],externalDependencies:[],authUrls:[],apiUrls:[],adminUrls:[],uploadUrls:[],paymentUrls:[],graphqlUrls:[],apiDocsUrls:[],websocketUrls:[]},
    testIdentities:[
      {id:'owner',label:'Owner test account',roleLabel:'member',tenantLabel:'tenant-a',authType:'HEADERS',credentialRef:'OWNER_PROFILE',expectedSessionState:'ACTIVE'},
      {id:'other',label:'Other tenant account',roleLabel:'member',tenantLabel:'tenant-b',authType:'HEADERS',credentialRef:'OTHER_PROFILE',expectedSessionState:'ACTIVE'}
    ],
    testResources:[{id:'r1',label:'Owned fixture',url:'https://app.test/api/resource/1',method:'GET',ownerIdentityId:'owner',comparatorIdentityIds:['other'],expectation:'DENY_COMPARATORS',proofMarker:'TEST-RESOURCE-A'}],
    resolvedIdentityHeaders:{owner:{'x-test-profile':'owner'},other:{'x-test-profile':'other'}},isCanceled:async()=>false,
    http:{request:async(_url:string,init:any)=>{calls.push({headers:init.headers});return response('{"marker":"TEST-RESOURCE-A"}');}}
  };
  return {ctx,calls};
}

describe('controlled authorization differential',()=>{
  it('reports a cross-tenant controlled resource when both identities receive the proof marker',async()=>{
    const {ctx}=baseContext();const findings=await controlledAuthorizationCheck.run(ctx);expect(findings).toHaveLength(1);expect(findings[0]?.title).toContain('Cross-tenant');expect(findings[0]?.confidence).toBe('CONFIRMED');
  });
  it('skips when no resolved request profiles are available',async()=>{
    const {ctx}=baseContext();ctx.resolvedIdentityHeaders={};expect(await controlledAuthorizationCheck.run(ctx)).toEqual([]);
  });
});

describe('revoked session check',()=>{
  it('reports only when a revoked controlled identity still sees the configured proof marker',async()=>{
    const {ctx}=baseContext();ctx.testIdentities=[{id:'revoked',label:'Revoked test account',roleLabel:'member',tenantLabel:'tenant-a',authType:'HEADERS',credentialRef:'REVOKED_PROFILE',expectedSessionState:'REVOKED'}];ctx.resolvedIdentityHeaders={revoked:{'x-test-profile':'revoked'}};ctx.testResources[0].ownerIdentityId='revoked';const findings=await revokedSessionCheck.run(ctx);expect(findings).toHaveLength(1);expect(findings[0]?.confidence).toBe('CONFIRMED');
  });
});
