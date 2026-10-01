import { redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page(){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const assets=await db.asset.findMany({where:{organizationId:org.id,verifiedAt:{not:null},scanningEnabled:true},orderBy:{createdAt:'desc'}});
  const single=assets.length===1?assets[0]:null;
  const sampleHost=assets[0]?.normalizedHost||'example.com';
  const defaultPrompt=single
    ? 'Perform a comprehensive end-to-end security assessment. Map the application, prioritize the highest-risk first-party surfaces, safely verify weaknesses, rank confirmed issues by remediation priority, and prepare a complete executive and technical report.'
    : `Assess ${sampleHost} comprehensively. Map the application, prioritize the highest-risk first-party surfaces, safely verify weaknesses, rank confirmed issues by remediation priority, and prepare a complete executive and technical report.`;

  return <div className="stack">
    <section className="hero-panel">
      <div className="eyebrow">One-prompt assessment</div>
      <h1>Tell the agent the outcome.</h1>
      <p className="lead">DeepSeek Flash translates one instruction into an authorized assessment mission. Xdigitex handles target resolution, application mapping, bounded checks, evidence capture and the completed report.</p>
      <div className="row" style={{marginTop:16}}><span className="status-pill">DeepSeek Flash online when API key is configured</span><span className="badge">{assets.length} verified target{assets.length===1?'':'s'}</span></div>
    </section>

    <section className="dashboard-grid">
      <div className="command-box stack">
        <div className="spread"><div><div className="eyebrow">Assessment command</div><h2>What should the security agent do?</h2></div><span className="badge">Natural language</span></div>
        <form action="/api/agent/run" method="post" className="stack">
          <textarea name="prompt" required rows={10} defaultValue={defaultPrompt}/>
          <div className="command-hint">{single?`This workspace has one enabled verified target, so the agent will resolve ${single.normalizedHost} automatically. You can still name it explicitly.`:'This workspace has multiple verified targets. Mention exactly one target domain in the prompt; a full URL is optional.'}</div>
          <div className="spread"><div className="muted" style={{fontSize:11}}>Comprehensive wording runs the complete registered safe-check set.</div><button className="btn">Run assessment</button></div>
        </form>
      </div>

      <div className="stack">
        <div className="card">
          <div className="eyebrow">Execution pipeline</div><h2>What happens next</h2>
          <div className="timeline">
            <div className="timeline-item"><strong>01 · Resolve target</strong>Match the instruction to an ownership-verified enabled asset.</div>
            <div className="timeline-item"><strong>02 · Map attack surface</strong>Crawl visible pages, forms, APIs, scripts and first-party application surfaces.</div>
            <div className="timeline-item"><strong>03 · Build AI mission</strong>DeepSeek Flash turns the prompt and application map into a focused or comprehensive plan.</div>
            <div className="timeline-item"><strong>04 · Verify evidence</strong>Registered checks execute through bounded HTTP/browser controls.</div>
            <div className="timeline-item"><strong>05 · Produce full report</strong>DeepSeek Flash writes the executive, risk, technical and remediation sections from stored findings.</div>
          </div>
        </div>
        <div className="card">
          <div className="eyebrow">Verified scope</div><h2>Available targets</h2>
          {assets.length?assets.map(a=><div className="finding-row" key={a.id}><div><div className="finding-title">{a.normalizedHost}</div><div className="finding-meta">{a.baseUrl}</div></div><span className="status-pill">Verified</span></div>):<div className="empty">Add and ownership-verify an asset before running an assessment.</div>}
        </div>
      </div>
    </section>

    <section className="grid-3">
      <div className="card"><div className="eyebrow">Example</div><h2>Full assessment</h2><p className="muted">“Perform a comprehensive end-to-end assessment of {sampleHost}. Put confirmed critical and high issues first and give me a full remediation plan.”</p></div>
      <div className="card"><div className="eyebrow">Example</div><h2>Focused assessment</h2><p className="muted">“Assess {sampleHost} with emphasis on authentication, authorization, APIs and sensitive-data exposure.”</p></div>
      <div className="card"><div className="eyebrow">Example</div><h2>Developer report</h2><p className="muted">“Scan {sampleHost}, verify weaknesses safely, then make the final report developer-focused with ordered fixes and retest steps.”</p></div>
    </section>
  </div>;
}
