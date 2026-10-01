import { deepseekJson } from '@xdigitex/shared';
import type { ApplicationMap } from '@xdigitex/types';
import type { SecurityCheck } from '@xdigitex/scanner-core';

export interface AgentPlan {
  focusCheckIds:string[];
  rationale:string;
  priorities:string[];
  mission:string;
  focusAreas:string[];
  reportEmphasis:string[];
  executionStyle:'focused'|'balanced'|'comprehensive';
}

function wantsComprehensive(prompt:string|undefined){
  return /\b(full|complete|comprehensive|everything|all checks|entire|whole|end[- ]to[- ]end)\b/i.test(prompt||'');
}

export async function buildAgentPlan(prompt:string|undefined,map:ApplicationMap,available:SecurityCheck[]):Promise<AgentPlan|null>{
  const catalog=available.map(c=>({id:c.id,name:c.name,category:c.category}));
  const request=prompt||'Perform a comprehensive authorized security assessment and safely verify discovered weaknesses.';
  const system=`You are the planning brain for an authorized defensive web-security scanner. Convert ONE natural-language user request into a structured assessment mission. Return JSON only. You may ONLY select check IDs from the supplied catalog. Do not invent payloads, commands, capabilities, targets, credentials, or third-party hosts. Keep execution non-destructive and evidence-driven. The execution engine independently enforces ownership verification, target scope, SSRF protection, request caps, cancellation, and safe proof-of-impact boundaries. Use executionStyle "focused" when the request names a narrow area, "comprehensive" when the user asks for a full/end-to-end assessment, otherwise "balanced".`;
  const user=JSON.stringify({
    request,
    application:{
      technologies:map.technologies,
      surfaces:map.surfaces.slice(0,150),
      authUrls:map.authUrls.slice(0,40),
      apiUrls:map.apiUrls.slice(0,60),
      adminUrls:map.adminUrls.slice(0,30),
      uploadUrls:map.uploadUrls.slice(0,30),
      paymentUrls:map.paymentUrls.slice(0,30),
      graphqlUrls:map.graphqlUrls.slice(0,20),
      apiDocsUrls:map.apiDocsUrls.slice(0,20),
      externalDependencies:map.externalDependencies.slice(0,50)
    },
    availableChecks:catalog,
    requiredOutput:{
      mission:'one-sentence restatement of the requested assessment goal',
      executionStyle:'focused | balanced | comprehensive',
      focusCheckIds:['exact check id from availableChecks'],
      focusAreas:['short first-party areas to emphasize'],
      priorities:['short execution priority'],
      reportEmphasis:['short reporting goal'],
      rationale:'short explanation grounded in the application map and request'
    }
  });

  const plan=await deepseekJson<Partial<AgentPlan>>(system,user);
  if(!plan||!Array.isArray(plan.focusCheckIds))return null;

  const allowed=new Set(catalog.map(c=>c.id));
  const selected=[...new Set(plan.focusCheckIds.filter((id):id is string=>typeof id==='string'&&allowed.has(id)))];
  const comprehensiveRequested=wantsComprehensive(request);
  const executionStyle:AgentPlan['executionStyle']=comprehensiveRequested
    ? 'comprehensive'
    : plan.executionStyle==='focused'||plan.executionStyle==='comprehensive'||plan.executionStyle==='balanced'
      ? plan.executionStyle
      : 'balanced';
  const focusCheckIds=executionStyle==='comprehensive'
    ? catalog.map(c=>c.id)
    : selected.length?selected:catalog.map(c=>c.id);

  return {
    focusCheckIds,
    mission:String(plan.mission||request).slice(0,500),
    executionStyle,
    rationale:String(plan.rationale||'DeepSeek translated the prompt into registered safe scanner modules.').slice(0,1200),
    focusAreas:Array.isArray(plan.focusAreas)?plan.focusAreas.slice(0,10).map(String):[],
    priorities:Array.isArray(plan.priorities)?plan.priorities.slice(0,10).map(String):[],
    reportEmphasis:Array.isArray(plan.reportEmphasis)?plan.reportEmphasis.slice(0,10).map(String):[]
  };
}
