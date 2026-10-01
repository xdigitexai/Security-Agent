import Link from 'next/link';
import { notFound,redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../../../lib/auth';
import { db } from '@xdigitex/database';
import { generateSecurityReport, type FullSecurityReport } from '@xdigitex/shared';

export const dynamic='force-dynamic';
function isReport(value:unknown):value is FullSecurityReport{return !!value&&typeof value==='object'&&typeof (value as any).executiveSummary==='string'&&Array.isArray((value as any).prioritizedRemediation);}

export default async function ReportPage({params}:{params:Promise<{id:string}>}){
  if(!await currentUser())redirect('/login');const {org}=await requireOrg();const {id}=await params;
  const scan=await db.scan.findFirst({where:{id,organizationId:org.id},include:{asset:true,_count:{select:{endpoints:true}},findings:{include:{evidence:{take:1,orderBy:{capturedAt:'desc'}}},orderBy:[{severity:'asc'},{createdAt:'asc'}]}}});
  if(!scan)notFound();if(scan.status!=='COMPLETED')redirect(`/scans/${scan.id}`);
  let report=isReport(scan.agentReport)?scan.agentReport:null;
  if(!report){report=await generateSecurityReport({target:scan.asset.baseUrl,scanId:scan.id,prompt:scan.agentPrompt,plan:scan.agentPlan,findings:scan.findings.map(f=>({title:f.title,severity:f.severity,confidence:f.confidence,category:f.category,affectedUrl:f.affectedUrl,method:f.method,description:f.description,impact:f.impact,remediation:f.remediation,status:f.status})),endpointCount:scan._count.endpoints,scope:scan.scope});await db.scan.update({where:{id:scan.id},data:{agentReport:report as any}});}
  const risk=report.riskOverview;const coverage=(report as any).checkCoverage||{completed:[],skipped:[]};
  return <div className="stack">
    <section className="hero-panel"><div className="report-hero"><div><div className="eyebrow">Final security assessment</div><h1>{scan.asset.normalizedHost}</h1><p className="lead">Complete executive, technical and remediation report generated from evidence recorded during this authorized operation.</p></div><span className="report-source">{report.generatedBy==='deepseek-flash'?'DeepSeek Flash':'Deterministic fallback'}</span></div><div className="row" style={{marginTop:17}}><span className="badge">Scan {scan.id.slice(0,8)}</span><span className="badge">Completed {(scan.completedAt||scan.createdAt).toLocaleString()}</span></div></section>
    <div className="spread"><Link className="btn btn2" href={`/scans/${scan.id}`}>Back to operation</Link><a className="btn" href={`/api/scans/${scan.id}/report`}>Download PDF report</a></div>

    <section className="grid">
      <div className="card stat-card"><div className="stat-label">Total findings</div><div><div className="metric">{risk.total}</div><div className="metric-sub">All recorded severities</div></div></div>
      <div className="card stat-card"><div className="stat-label">Critical</div><div><div className={`metric ${risk.critical?'metric-danger':''}`}>{risk.critical}</div><div className="metric-sub">P0 review</div></div></div>
      <div className="card stat-card"><div className="stat-label">High</div><div><div className={`metric ${risk.high?'metric-warn':''}`}>{risk.high}</div><div className="metric-sub">P1 review</div></div></div>
      <div className="card stat-card"><div className="stat-label">Confirmed / high confidence</div><div><div className="metric">{risk.confirmed}</div><div className="metric-sub">Evidence-backed observations</div></div></div>
      <div className="card stat-card"><div className="stat-label">Modules completed</div><div><div className="metric">{coverage.completed.length}</div><div className="metric-sub">Completed safely</div></div></div>
      <div className="card stat-card"><div className="stat-label">Modules skipped</div><div><div className={`metric ${coverage.skipped.length?'metric-warn':''}`}>{coverage.skipped.length}</div><div className="metric-sub">No negative assurance</div></div></div>
    </section>

    <section className="grid-2">
      <div className="report-section"><div className="eyebrow">Executive summary</div><h2>What the assessment found</h2><p>{report.executiveSummary}</p></div>
      <div className="report-section"><div className="eyebrow">Security posture</div><h2>Risk interpretation</h2><p>{report.securityPosture}</p></div>
      <div className="report-section"><div className="eyebrow">Coverage</div><h2>What was assessed</h2><p>{report.assessmentCoverage}</p></div>
      <div className="report-section"><div className="eyebrow">Attack surface</div><h2>Application exposure</h2><p>{report.attackSurfaceSummary}</p></div>
    </section>

    {(coverage.completed.length||coverage.skipped.length)?<section className="report-section"><div className="eyebrow">Scanner assurance</div><h2>Module completion</h2><p className="muted">Only completed modules can support a negative conclusion. Skipped modules are explicitly excluded from clean-bill-of-health language.</p><div className="grid-2"><div><h3>Completed</h3><div className="row">{coverage.completed.map((id:string)=><span className="status-pill" key={id}>{id}</span>)}</div></div><div><h3>Skipped</h3>{coverage.skipped.length?coverage.skipped.map((x:any)=><div className="report-item" key={x.id}><b>{x.id}</b>{x.error&&<p className="muted">{x.error}</p>}</div>):<p className="muted">None.</p>}</div></div></section>:null}

    <section className="report-section"><div className="eyebrow">Key findings</div><h2>Highest-priority recorded issues</h2><div className="report-list">{report.keyFindings.length?report.keyFindings.map((f,i)=><div className="report-item" key={`${f.title}-${i}`}><div className="spread"><div className="report-item-title">{f.title}</div><div className="row"><span className="priority">{f.remediationPriority}</span><span className={`severity-pill severity-${f.severity.toLowerCase()}`}>{f.severity}</span></div></div><p>{f.whyItMatters}</p><p><b>Impact:</b> {f.impact}</p><div className="finding-meta">{f.confidence} confidence · {f.affectedUrl}</div></div>):<div className="empty">No key finding was recorded by the executed checks.</div>}</div></section>
    <section className="report-section"><div className="eyebrow">Remediation plan</div><h2>Ordered actions and validation</h2><div className="report-list">{report.prioritizedRemediation.length?report.prioritizedRemediation.map((item,i)=><div className="report-item" key={`${item.title}-${i}`}><div className="row"><span className="priority">{item.priority}</span><span className="report-item-title">{item.title}</span></div><p><b>Why:</b> {item.reason}</p><p><b>Action:</b> {item.action}</p><p><b>Validate:</b> {item.validation}</p></div>):<div className="empty">No remediation item was required from the recorded findings.</div>}</div></section>
    <section className="report-section"><div className="eyebrow">Technical summary</div><h2>Assessment interpretation</h2><p>{report.technicalSummary}</p></section>
    <section className="card"><div className="eyebrow">Technical evidence</div><h2>Detailed findings</h2><div className="finding-list">{scan.findings.length?scan.findings.map(f=><Link className="finding-row" href={`/findings/${f.id}`} key={f.id}><div><div className="finding-title">{f.title}</div><div className="finding-meta">{f.confidence} · {f.category} · {f.method||'GET'} {f.affectedUrl}</div></div><span className={`severity-pill severity-${f.severity.toLowerCase()}`}>{f.severity}</span></Link>):<div className="empty">No finding was recorded by the executed registered checks.</div>}</div></section>
    <section className="grid-3"><div className="report-section"><div className="eyebrow">Positive observations</div><h2>What held up</h2><div className="report-list">{report.positiveObservations.length?report.positiveObservations.map((x,i)=><div className="report-item" key={i}><p>{x}</p></div>):<p>No explicit positive observation was produced.</p>}</div></div><div className="report-section"><div className="eyebrow">Limitations</div><h2>Assessment boundaries</h2><div className="report-list">{report.limitations.map((x,i)=><div className="report-item" key={i}><p>{x}</p></div>)}</div></div><div className="report-section"><div className="eyebrow">Next actions</div><h2>Recommended follow-up</h2><div className="report-list">{report.nextActions.map((x,i)=><div className="report-item" key={i}><p>{i+1}. {x}</p></div>)}</div></div></section>
    <div className="muted mono" style={{fontSize:10,textAlign:'center'}}>Report generated {new Date(report.generatedAt).toLocaleString()} · {report.generatedBy} · Findings and module completion remain the source of truth.</div>
  </div>;
}
