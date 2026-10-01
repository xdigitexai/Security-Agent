import { deepseekJson } from '@xdigitex/shared';
import type { ApplicationMap } from '@xdigitex/types';
import type { SecurityCheck } from '@xdigitex/scanner-core';

export interface AgentPlan { focusCheckIds:string[]; rationale:string; priorities:string[]; }

export async function buildAgentPlan(prompt:string|undefined,map:ApplicationMap,available:SecurityCheck[]):Promise<AgentPlan|null>{
  const catalog=available.map(c=>({id:c.id,name:c.name,category:c.category}));
  const system=`You are the planning brain for an authorized defensive web-security scanner. Return JSON only. You may ONLY select check IDs from the supplied catalog. Do not invent payloads, commands, targets, or third-party hosts. Prioritize evidence-driven, non-destructive verification. The execution engine independently enforces ownership verification, scope, SSRF protection, request caps, and safe proof-of-impact boundaries.`;
  const user=JSON.stringify({
    request:prompt||'Perform a comprehensive authorized security assessment and safely verify discovered weaknesses.',
    application:{technologies:map.technologies,surfaces:map.surfaces.slice(0,150),externalDependencies:map.externalDependencies.slice(0,50)},
    availableChecks:catalog,
    requiredOutput:{focusCheckIds:['exact check id'],rationale:'short explanation',priorities:['short priority']}
  });
  const plan=await deepseekJson<AgentPlan>(system,user);
  if(!plan||!Array.isArray(plan.focusCheckIds))return null;
  const allowed=new Set(catalog.map(c=>c.id));
  const ids=[...new Set(plan.focusCheckIds.filter(id=>allowed.has(id)))];
  return {focusCheckIds:ids.length?ids:catalog.map(c=>c.id),rationale:String(plan.rationale||'DeepSeek selected the registered safe checks.'),priorities:Array.isArray(plan.priorities)?plan.priorities.slice(0,10).map(String):[]};
}
