import { redirect,notFound } from 'next/navigation';
import { currentUser,requireOrg } from '../../../lib/auth';
import { db } from '@xdigitex/database';

export const dynamic='force-dynamic';

export default async function Page({params}:{params:Promise<{id:string}>}){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const {id}=await params;
  const s=await db.scan.findFirst({
    where:{id,organizationId:org.id},
    include:{
      asset:true,
      logs:{orderBy:{createdAt:'desc'},take:40},
      findings:{take:20,orderBy:{createdAt:'desc'}},
      _count:{select:{endpoints:true,findings:true}}
    }
  });
  if(!s)notFound();
  const plan=s.agentPlan as any;

  return <div className="stack">
    <div>
      <h1>Assessment · {s.asset.normalizedHost}</h1>
      <p className="muted">{s.stage} · {s.progress}% · {s.status}</p>
      {s.agentPrompt&&<div className="card"><div className="muted">One-prompt mission</div><div style={{marginTop:8}}>{s.agentPrompt}</div></div>}
    </div>

    <div className="row">
      {['QUEUED','RUNNING'].includes(s.status)&&<form action={`/api/scans/${s.id}/cancel`} method="post"><button className="btn btn2">Stop scan</button></form>}
      {s.status==='COMPLETED'&&<a className="btn" href={`/api/scans/${s.id}/report`}>Download PDF Report</a>}
    </div>

    {plan&&<div className="card stack">
      <div>
        <h2>AI assessment mission</h2>
        {plan.mission&&<p>{plan.mission}</p>}
        <div className="muted">Execution style: {plan.executionStyle||'balanced'}</div>
      </div>
      <div><b>Why this plan</b><p className="muted">{plan.rationale}</p></div>
      {Array.isArray(plan.focusAreas)&&plan.focusAreas.length>0&&<div><b>Focus areas</b><div className="muted">{plan.focusAreas.join(' · ')}</div></div>}
      {Array.isArray(plan.priorities)&&plan.priorities.length>0&&<div><b>Priorities</b><div className="muted">{plan.priorities.join(' · ')}</div></div>}
      {Array.isArray(plan.reportEmphasis)&&plan.reportEmphasis.length>0&&<div><b>Report emphasis</b><div className="muted">{plan.reportEmphasis.join(' · ')}</div></div>}
      <div><b>Approved modules</b><div className="muted">{Array.isArray(plan.focusCheckIds)?plan.focusCheckIds.join(', '):'registered safe checks'}</div></div>
    </div>}

    <div className="grid">
      <div className="card"><div className="muted">URLs / APIs</div><div className="metric">{s._count.endpoints}</div></div>
      <div className="card"><div className="muted">Findings</div><div className="metric">{s._count.findings}</div></div>
    </div>

    <div className="card">
      <h2>Live findings</h2>
      {s.findings.map(f=><div key={f.id} style={{padding:'12px 0',borderBottom:'1px solid var(--line)'}}>
        <a href={`/findings/${f.id}`}><b>{f.title}</b></a>
        <div className="muted">{f.severity} · {f.category} · {f.affectedUrl}</div>
      </div>)}
    </div>

    <div className="card">
      <h2>Agent activity</h2>
      {s.logs.map(l=><div key={l.id} className="muted" style={{padding:5}}>{l.createdAt.toLocaleTimeString()} [{l.stage}] {l.message}</div>)}
    </div>
  </div>;
}
