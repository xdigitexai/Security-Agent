import Link from 'next/link';
import { redirect } from 'next/navigation';
import { currentUser, requireOrg } from '../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page(){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const [assets,scans,crit,high,med,low,fixed,running,recent,recentFindings]=await Promise.all([
    db.asset.count({where:{organizationId:org.id,verifiedAt:{not:null}}}),
    db.scan.count({where:{organizationId:org.id}}),
    db.finding.count({where:{organizationId:org.id,status:'OPEN',severity:'CRITICAL'}}),
    db.finding.count({where:{organizationId:org.id,status:'OPEN',severity:'HIGH'}}),
    db.finding.count({where:{organizationId:org.id,status:'OPEN',severity:'MEDIUM'}}),
    db.finding.count({where:{organizationId:org.id,status:'OPEN',severity:'LOW'}}),
    db.finding.count({where:{organizationId:org.id,status:'FIXED'}}),
    db.scan.count({where:{organizationId:org.id,status:{in:['QUEUED','RUNNING']}}}),
    db.scan.findMany({where:{organizationId:org.id},include:{asset:true},take:8,orderBy:{createdAt:'desc'}}),
    db.finding.findMany({where:{organizationId:org.id,status:'OPEN'},take:6,orderBy:{createdAt:'desc'}})
  ]);
  const open=crit+high+med+low;
  const posture=crit>0?'Critical findings require immediate attention':high>0?'High-risk findings require prioritized remediation':open>0?'Open findings remain under review':'No open critical-to-low findings recorded';
  const severity=[['Critical',crit],['High',high],['Medium',med],['Low',low]] as const;
  const maxSeverity=Math.max(1,...severity.map(([,v])=>v));

  return <div className="stack">
    <section className="hero-panel">
      <div className="eyebrow">Security control center</div>
      <div className="spread">
        <div><h1>Security posture</h1><p className="lead">One view for verified scope, AI-directed assessments, confirmed findings and remediation progress.</p></div>
        <Link className="btn" href="/agent">Start assessment</Link>
      </div>
      <div className="row" style={{marginTop:18}}><span className="status-pill">{posture}</span><span className="badge">{running} active scan{running===1?'':'s'}</span></div>
    </section>

    <section className="grid">
      <div className="card stat-card"><div className="stat-label">Verified assets</div><div><div className="metric">{assets}</div><div className="metric-sub">Ownership-confirmed targets</div></div></div>
      <div className="card stat-card"><div className="stat-label">Total assessments</div><div><div className="metric">{scans}</div><div className="metric-sub">Historical scan operations</div></div></div>
      <div className="card stat-card"><div className="stat-label">Open high risk</div><div><div className={`metric ${crit+high?'metric-danger':''}`}>{crit+high}</div><div className="metric-sub">Critical + high findings</div></div></div>
      <div className="card stat-card"><div className="stat-label">Recently fixed</div><div><div className="metric metric-success">{fixed}</div><div className="metric-sub">Findings no longer reproduced</div></div></div>
    </section>

    <section className="dashboard-grid">
      <div className="card">
        <div className="spread"><div><div className="eyebrow">Operations</div><h2>Recent assessments</h2></div><Link className="btn btn-ghost" href="/scans">View all</Link></div>
        {recent.length?<div className="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Stage</th><th>Progress</th><th>Started</th></tr></thead><tbody>{recent.map(s=><tr key={s.id}><td><Link href={`/scans/${s.id}`}><b>{s.asset.normalizedHost}</b></Link></td><td><span className="badge">{s.status}</span></td><td>{s.stage}</td><td><div style={{minWidth:120}}><div className="progress-track"><div className="progress-fill" style={{width:`${Math.max(2,s.progress)}%`}}/></div></div></td><td>{s.createdAt.toLocaleString()}</td></tr>)}</tbody></table></div>:<div className="empty">No assessments yet. Start one from AI Security Agent.</div>}
      </div>

      <div className="stack">
        <div className="card">
          <div className="eyebrow">Risk distribution</div><h2>Open findings</h2>
          <div className="risk-stack">{severity.map(([label,value])=><div className="risk-row" key={label}><span>{label}</span><div className="risk-bar"><span style={{width:`${Math.max(value?8:0,(value/maxSeverity)*100)}%`}}/></div><b>{value}</b></div>)}</div>
        </div>
        <div className="card">
          <div className="eyebrow">Latest detections</div><h2>Needs attention</h2>
          <div className="finding-list">{recentFindings.length?recentFindings.map(f=><Link className="finding-row" href={`/findings/${f.id}`} key={f.id}><div><div className="finding-title">{f.title}</div><div className="finding-meta">{f.category} · {f.affectedUrl}</div></div><span className={`severity-pill severity-${f.severity.toLowerCase()}`}>{f.severity}</span></Link>):<div className="muted">No open findings.</div>}</div>
        </div>
      </div>
    </section>
  </div>;
}
