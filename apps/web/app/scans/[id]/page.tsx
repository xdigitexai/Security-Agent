import Link from 'next/link';
import { redirect,notFound } from 'next/navigation';
import { currentUser,requireOrg } from '../../../lib/auth';
import { db } from '@xdigitex/database';
import type { FullSecurityReport } from '@xdigitex/shared';
import AutoRefresh from './auto-refresh';

export const dynamic='force-dynamic';

export default async function Page({params}:{params:Promise<{id:string}>}){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const {id}=await params;
  const s=await db.scan.findFirst({
    where:{id,organizationId:org.id},
    include:{asset:true,logs:{orderBy:{createdAt:'desc'},take:50},findings:{take:100,orderBy:{createdAt:'desc'}},_count:{select:{endpoints:true,findings:true}}}
  });
  if(!s)notFound();
  const plan=s.agentPlan as any;
  const report=(s.agentReport||null) as unknown as FullSecurityReport|null;
  const active=['QUEUED','RUNNING'].includes(s.status);
  const severity=(name:string)=>s.findings.filter(f=>f.severity===name).length;
  const critical=severity('CRITICAL');const high=severity('HIGH');
  const stages=['Scope','Map','Plan','Verify','Report'];
  const stageIndex=s.progress<10?0:s.progress<30?1:s.progress<35?2:s.progress<92?3:4;

  return <div className="stack">
    <AutoRefresh active={active}/>

    <section className="hero-panel">
      <div className="spread">
        <div><div className="eyebrow">Assessment operation</div><h1>{s.asset.normalizedHost}</h1><p className="lead">{s.agentPrompt||'Authorized defensive security assessment'}</p></div>
        <div className="row"><span className="status-pill">{s.status}</span>{report&&<span className="report-source">{report.generatedBy==='deepseek-flash'?'DeepSeek Flash report':'Fallback report'}</span>}</div>
      </div>
      <div style={{marginTop:20}}><div className="spread" style={{marginBottom:8}}><span className="muted" style={{fontSize:11}}>{s.stage}</span><b style={{fontSize:11}}>{s.progress}%</b></div><div className="progress-track"><div className="progress-fill" style={{width:`${Math.max(active?2:0,s.progress)}%`}}/></div></div>
      <div className="stage-strip" style={{marginTop:11}}>{stages.map((name,i)=><div key={name} className={`stage-step ${i<=stageIndex?'active':''}`}>{name}</div>)}</div>
    </section>

    <div className="spread">
      <div className="row">{active&&<form action={`/api/scans/${s.id}/cancel`} method="post"><button className="btn btn2">Stop assessment</button></form>}{s.status==='COMPLETED'&&<><Link className="btn" href={`/scans/${s.id}/report`}>Open full report</Link><a className="btn btn2" href={`/api/scans/${s.id}/report`}>Download PDF</a></>}</div>
      <div className="mono muted" style={{fontSize:10}}>Scan {s.id}</div>
    </div>

    <section className="grid">
      <div className="card stat-card"><div className="stat-label">Mapped surfaces</div><div><div className="metric">{s._count.endpoints}</div><div className="metric-sub">URLs and API observations</div></div></div>
      <div className="card stat-card"><div className="stat-label">Findings</div><div><div className="metric">{s._count.findings}</div><div className="metric-sub">Recorded in this operation</div></div></div>
      <div className="card stat-card"><div className="stat-label">Critical / high</div><div><div className={`metric ${critical+high?'metric-danger':''}`}>{critical+high}</div><div className="metric-sub">Prioritized remediation</div></div></div>
      <div className="card stat-card"><div className="stat-label">Report engine</div><div><div className="metric" style={{fontSize:18}}>{report?.generatedBy==='deepseek-flash'?'DeepSeek Flash':s.status==='COMPLETED'?'Fallback':'Pending'}</div><div className="metric-sub">Generated after verification</div></div></div>
    </section>

    {plan&&<section className="card">
      <div className="spread"><div><div className="eyebrow">AI mission</div><h2>{plan.mission||'Assessment plan'}</h2></div><span className="badge">{plan.executionStyle||'balanced'}</span></div>
      <p className="muted" style={{fontSize:12,lineHeight:1.65}}>{plan.rationale}</p>
      <div className="grid-3" style={{marginTop:14}}>
        <div><div className="stat-label">Focus areas</div><div className="muted" style={{fontSize:11,marginTop:6}}>{Array.isArray(plan.focusAreas)&&plan.focusAreas.length?plan.focusAreas.join(' · '):'Mapped first-party surfaces'}</div></div>
        <div><div className="stat-label">Priorities</div><div className="muted" style={{fontSize:11,marginTop:6}}>{Array.isArray(plan.priorities)&&plan.priorities.length?plan.priorities.join(' · '):'Evidence-driven checks'}</div></div>
        <div><div className="stat-label">Approved modules</div><div className="muted" style={{fontSize:11,marginTop:6}}>{Array.isArray(plan.focusCheckIds)?plan.focusCheckIds.length:'Registered'} scanner modules</div></div>
      </div>
    </section>}

    {s.status==='COMPLETED'&&report&&<section className="stack">
      <div className="report-hero report-section">
        <div><div className="eyebrow">Completed assessment report</div><h2>Executive summary</h2><p>{report.executiveSummary}</p></div>
        <span className="report-source">{report.generatedBy==='deepseek-flash'?'DeepSeek Flash':'Deterministic fallback'}</span>
      </div>
      <div className="grid-2">
        <div className="report-section"><div className="eyebrow">Security posture</div><h2>Risk interpretation</h2><p>{report.securityPosture}</p></div>
        <div className="report-section"><div className="eyebrow">Coverage</div><h2>What was assessed</h2><p>{report.assessmentCoverage}</p></div>
      </div>
      <div className="report-section"><div className="spread"><div><div className="eyebrow">Remediation</div><h2>Priority action plan</h2></div><Link className="btn btn-ghost" href={`/scans/${s.id}/report`}>View complete report</Link></div><div className="report-list">{report.prioritizedRemediation.slice(0,5).map((item,i)=><div className="report-item" key={`${item.title}-${i}`}><div className="row"><span className="priority">{item.priority}</span><span className="report-item-title">{item.title}</span></div><p>{item.action}</p></div>)}</div></div>
    </section>}

    <section className="dashboard-grid">
      <div className="card">
        <div className="spread"><div><div className="eyebrow">Evidence</div><h2>{active?'Live findings':'Recorded findings'}</h2></div><Link className="btn btn-ghost" href="/findings">All findings</Link></div>
        <div className="finding-list">{s.findings.length?s.findings.map(f=><Link className="finding-row" href={`/findings/${f.id}`} key={f.id}><div><div className="finding-title">{f.title}</div><div className="finding-meta">{f.category} · {f.affectedUrl}</div></div><span className={`severity-pill severity-${f.severity.toLowerCase()}`}>{f.severity}</span></Link>):<div className="empty">{active?'No finding recorded yet. The assessment is still running.':'No finding was recorded by the executed checks.'}</div>}</div>
      </div>
      <div className="card">
        <div className="eyebrow">Activity stream</div><h2>Agent timeline</h2>
        <div className="timeline">{s.logs.length?s.logs.map(l=><div className="timeline-item" key={l.id}><strong>{l.stage} · {l.createdAt.toLocaleTimeString()}</strong>{l.message}</div>):<div className="muted">Waiting for activity.</div>}</div>
      </div>
    </section>
  </div>;
}
