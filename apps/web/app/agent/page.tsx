import { redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page(){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const assets=await db.asset.findMany({
    where:{organizationId:org.id,verifiedAt:{not:null},scanningEnabled:true},
    orderBy:{createdAt:'desc'}
  });
  const single=assets.length===1?assets[0]:null;
  const defaultPrompt=single
    ? 'Perform a complete security assessment. Map the application, prioritize the highest-risk first-party surfaces, safely verify weaknesses, and prepare a remediation-focused report.'
    : 'Assess app.example.com comprehensively. Map the application, prioritize the highest-risk first-party surfaces, safely verify weaknesses, and prepare a remediation-focused report.';

  return <div className="stack">
    <div>
      <h1>AI Security Agent</h1>
      <p className="muted">One instruction starts the complete authorized assessment. Xdigitex resolves the verified target, maps the application, lets DeepSeek build the assessment mission, executes only registered safe checks, preserves evidence, and prepares the report.</p>
    </div>

    <div className="card stack">
      <div>
        <h2>What should the agent do?</h2>
        <p className="muted">Write the outcome you want in normal language. You do not need to select scanners or stages.</p>
      </div>
      <form action="/api/agent/run" method="post" className="stack">
        <textarea name="prompt" required rows={9} defaultValue={defaultPrompt}/>
        <div className="muted">
          {single
            ? `Target automatically resolved to your verified asset: ${single.normalizedHost}. You can still mention the domain explicitly.`
            : 'Because you have multiple verified assets, mention exactly one target domain in the prompt. A full URL is optional.'}
        </div>
        <button className="btn">Run One-Prompt Assessment</button>
      </form>
    </div>

    <div className="card stack">
      <h2>Prompt examples</h2>
      <div className="muted">Full: “Perform a comprehensive end-to-end assessment of example.com and give me the highest-risk confirmed issues first.”</div>
      <div className="muted">Focused: “Assess example.com with emphasis on authentication, authorization, APIs and sensitive data exposure.”</div>
      <div className="muted">Remediation: “Scan example.com, safely verify weaknesses, and make the final report developer-focused with clear fix priorities.”</div>
    </div>

    <div className="card">
      <h2>Verified targets</h2>
      {assets.length
        ? assets.map(a=><div key={a.id} className="muted" style={{padding:'6px 0'}}>{a.baseUrl}</div>)
        : <p className="muted">No verified enabled assets yet. Add and ownership-verify a site first.</p>}
    </div>
  </div>;
}
