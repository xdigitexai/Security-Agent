import Link from 'next/link';
import { redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page(){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const assets=await db.asset.findMany({where:{organizationId:org.id},include:{verifications:{orderBy:{createdAt:'desc'},take:1}},orderBy:{createdAt:'desc'}});
  const verified=assets.filter(a=>a.verifiedAt).length;
  return <div className="stack">
    <section className="hero-panel"><div className="eyebrow">Scope management</div><h1>Assets</h1><p className="lead">Register first-party targets and prove ownership before any security assessment can begin.</p><div className="row" style={{marginTop:15}}><span className="badge">{assets.length} total</span><span className="status-pill">{verified} verified</span></div></section>
    <section className="card"><div className="spread"><div><div className="eyebrow">Add target</div><h2>Register an application</h2></div></div><form action="/api/assets" method="post" className="row"><input name="url" placeholder="https://app.example.com" required/><input name="name" placeholder="Asset name" required/><button className="btn">Add asset</button></form></section>
    <section className="card"><div className="eyebrow">Asset inventory</div><h2>Verified scope</h2>{assets.length?<div className="table-wrap"><table><thead><tr><th>Asset</th><th>Ownership</th><th>Scanning</th><th>Action</th></tr></thead><tbody>{assets.map(a=><tr key={a.id}><td><b>{a.name}</b><div className="finding-meta">{a.baseUrl}</div></td><td>{a.verifiedAt?<span className="status-pill">Verified</span>:<span className="badge">Pending</span>}</td><td><span className="badge">{a.scanningEnabled?'Enabled':'Disabled'}</span></td><td><Link className="btn btn-ghost" href={`/assets/${a.id}`}>{a.verifiedAt?'Manage':'Verify ownership'}</Link></td></tr>)}</tbody></table></div>:<div className="empty">No assets registered yet.</div>}</section>
  </div>;
}
