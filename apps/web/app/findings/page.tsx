import Link from 'next/link';
import { redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page({searchParams}:{searchParams:Promise<Record<string,string|undefined>>}){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const q=await searchParams;
  const findings=await db.finding.findMany({where:{organizationId:org.id,severity:q.severity as any||undefined,status:q.status as any||undefined,category:q.category||undefined},include:{asset:true},orderBy:[{severity:'asc'},{lastSeenAt:'desc'}],take:200});
  const critical=findings.filter(f=>f.severity==='CRITICAL').length;
  const high=findings.filter(f=>f.severity==='HIGH').length;
  return <div className="stack">
    <section className="hero-panel"><div className="eyebrow">Vulnerability intelligence</div><h1>Findings</h1><p className="lead">Review evidence-backed observations, track lifecycle state and prioritize remediation across verified applications.</p><div className="row" style={{marginTop:15}}><span className="badge">{findings.length} in current view</span><span className={`badge ${critical+high?'critical':''}`}>{critical+high} critical/high</span></div></section>
    <section className="card"><div className="eyebrow">Filters</div><form className="row"><select name="severity" defaultValue={q.severity||''}><option value="">All severities</option>{['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL'].map(x=><option key={x}>{x}</option>)}</select><select name="status" defaultValue={q.status||''}><option value="">All statuses</option>{['OPEN','FIXED','IGNORED','FALSE_POSITIVE','RETESTING'].map(x=><option key={x}>{x}</option>)}</select><button className="btn btn2">Apply filters</button></form></section>
    <section className="card"><div className="eyebrow">Evidence register</div><h2>Recorded findings</h2>{findings.length?<div className="table-wrap"><table><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Status</th><th>Last detected</th></tr></thead><tbody>{findings.map(f=><tr key={f.id}><td><span className={`severity-pill severity-${f.severity.toLowerCase()}`}>{f.severity}</span></td><td><Link href={`/findings/${f.id}`}><b>{f.title}</b></Link><div className="finding-meta">{f.category}</div></td><td>{f.asset.normalizedHost}</td><td><span className="badge">{f.status}</span></td><td>{f.lastSeenAt.toLocaleString()}</td></tr>)}</tbody></table></div>:<div className="empty">No findings match the selected filters.</div>}</section>
  </div>;
}
