import Link from 'next/link';
import { redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page(){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const [assets,scans]=await Promise.all([
    db.asset.findMany({where:{organizationId:org.id,verifiedAt:{not:null},scanningEnabled:true}}),
    db.scan.findMany({where:{organizationId:org.id},include:{asset:true,_count:{select:{endpoints:true,findings:true}}},orderBy:{createdAt:'desc'},take:50})
  ]);
  const active=scans.filter(s=>['QUEUED','RUNNING'].includes(s.status)).length;
  const completed=scans.filter(s=>s.status==='COMPLETED').length;
  return <div className="stack">
    <section className="hero-panel"><div className="eyebrow">Assessment history</div><h1>Security operations</h1><p className="lead">Track queued, active and completed assessments across your ownership-verified targets.</p><div className="row" style={{marginTop:15}}><span className="status-pill">{active} active</span><span className="badge">{completed} completed</span></div></section>
    <section className="card"><div className="spread"><div><div className="eyebrow">Quick scan</div><h2>Start a standard assessment</h2></div><Link className="btn btn-ghost" href="/agent">Use one-prompt agent</Link></div><form action="/api/scans" method="post" className="row"><select name="assetId" required><option value="">Select verified asset</option>{assets.map(a=><option key={a.id} value={a.id}>{a.normalizedHost}</option>)}</select><button className="btn">Start scan</button></form></section>
    <section className="card"><div className="eyebrow">Operations</div><h2>Assessment log</h2>{scans.length?<div className="table-wrap"><table><thead><tr><th>Target</th><th>Status</th><th>Stage</th><th>Progress</th><th>Surfaces</th><th>Findings</th><th>Report</th></tr></thead><tbody>{scans.map(s=><tr key={s.id}><td><Link href={`/scans/${s.id}`}><b>{s.asset.normalizedHost}</b></Link></td><td><span className="badge">{s.status}</span></td><td>{s.stage}</td><td><div style={{minWidth:110}}><div className="progress-track"><div className="progress-fill" style={{width:`${Math.max(s.progress,2)}%`}}/></div><div className="finding-meta">{s.progress}%</div></div></td><td>{s._count.endpoints}</td><td>{s._count.findings}</td><td>{s.status==='COMPLETED'?<Link className="btn btn-ghost" href={`/scans/${s.id}/report`}>Open report</Link>:<Link className="btn btn-ghost" href={`/scans/${s.id}`}>Open</Link>}</td></tr>)}</tbody></table></div>:<div className="empty">No assessments yet.</div>}</section>
  </div>;
}
