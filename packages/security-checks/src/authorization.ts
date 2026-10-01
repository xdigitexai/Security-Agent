import crypto from 'node:crypto';
import type { SecurityCheck } from '@xdigitex/scanner-core';

const digest=(body:string)=>crypto.createHash('sha256').update(body.replace(/\b\d{10,}\b/g,'<n>').replace(/[a-f0-9]{24,}/gi,'<id>').trim()).digest('hex');

export const controlledAuthorizationCheck:SecurityCheck={
  id:'authorization.controlled-differential',
  name:'Controlled authorization differential',
  category:'Authorization',
  async run(ctx){
    const findings=[];
    const identities=new Map(ctx.testIdentities.map(i=>[i.id,i]));
    for(const resource of ctx.testResources){
      if(resource.expectation!=='DENY_COMPARATORS') continue;
      const owner=identities.get(resource.ownerIdentityId);
      const ownerHeaders=owner?ctx.resolvedIdentityHeaders[owner.id]:undefined;
      if(!owner||!ownerHeaders||owner.expectedSessionState!=='ACTIVE') continue;
      const ownerResponse=await ctx.http.request(resource.url,{method:resource.method,headers:ownerHeaders});
      if(ownerResponse.status<200||ownerResponse.status>=300) continue;
      for(const comparatorId of resource.comparatorIdentityIds.slice(0,5)){
        if(await ctx.isCanceled()) throw new Error('SCAN_CANCELED');
        const comparator=identities.get(comparatorId);
        const comparatorHeaders=comparator?ctx.resolvedIdentityHeaders[comparator.id]:undefined;
        if(!comparator||!comparatorHeaders) continue;
        const compared=await ctx.http.request(resource.url,{method:resource.method,headers:comparatorHeaders});
        if(compared.status<200||compared.status>=300) continue;
        const markerConfirmed=!!resource.proofMarker&&ownerResponse.body.includes(resource.proofMarker)&&compared.body.includes(resource.proofMarker);
        const sameBody=ownerResponse.body.length>0&&digest(ownerResponse.body)===digest(compared.body);
        if(!markerConfirmed&&!sameBody) continue;
        const crossTenant=!!owner.tenantLabel&&!!comparator.tenantLabel&&owner.tenantLabel!==comparator.tenantLabel;
        findings.push({
          checkId:this.id,
          title:crossTenant?'Cross-tenant controlled resource readable by comparator':'Controlled resource readable by identity expected to be denied',
          description:`The owner-declared resource “${resource.label}” was readable by both the intended identity “${owner.label}” and comparator “${comparator.label}” using a read-only request.`,
          category:'Authorization',severity:'HIGH',confidence:markerConfirmed?'CONFIRMED':'HIGH',affectedUrl:resource.url,method:resource.method,parameter:`comparator:${comparator.label}`,
          impact:crossTenant?'A user in one tenant may be able to read a resource belonging to another tenant.':'A different controlled identity may be able to read an object that the asset owner marked as inaccessible to that identity.',
          remediation:'Enforce object ownership, tenant and role authorization on the server for every resource request. Do not rely on hidden UI controls or identifier unpredictability.',
          evidence:[ownerResponse.evidence,compared.evidence]
        });
      }
    }
    return findings;
  }
};

export const revokedSessionCheck:SecurityCheck={
  id:'authentication.revoked-session',name:'Revoked controlled session validation',category:'Authentication',
  async run(ctx){
    const findings=[];
    for(const identity of ctx.testIdentities.filter(i=>i.expectedSessionState==='REVOKED').slice(0,5)){
      const headers=ctx.resolvedIdentityHeaders[identity.id];if(!headers)continue;
      for(const resource of ctx.testResources.filter(r=>r.proofMarker).slice(0,10)){
        if(await ctx.isCanceled()) throw new Error('SCAN_CANCELED');
        const response=await ctx.http.request(resource.url,{method:resource.method,headers});
        if(response.status>=200&&response.status<300&&resource.proofMarker&&response.body.includes(resource.proofMarker)) findings.push({checkId:this.id,title:'Revoked controlled session still accesses protected test resource',description:`Identity “${identity.label}” is marked REVOKED by the asset owner but still reads “${resource.label}”.`,category:'Session Security',severity:'HIGH',confidence:'CONFIRMED',affectedUrl:resource.url,method:resource.method,impact:'Session invalidation may be incomplete, allowing a revoked session to continue accessing protected data.',remediation:'Invalidate server-side sessions or tokens on logout, password change, privilege removal and administrative revocation, and enforce revocation on each protected request.',evidence:[response.evidence]});
      }
    }
    return findings;
  }
};
