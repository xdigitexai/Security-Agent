import { redirect } from 'next/navigation';
import { currentUser,requireOrg } from '../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page(){
  if(!await currentUser())redirect('/login');
  const {org}=await requireOrg();
  const assets=await db.asset.findMany({where:{organizationId:org.id,verifiedAt:{not:null},scanningEnabled:true},orderBy:{createdAt:'desc'}});
  return <div className="stack">
    <div><h1>DeepSeek Security Agent</h1><p className="muted">One prompt. Verified target only. Xdigitex maps the application, DeepSeek prioritizes approved checks, the scanner safely verifies evidence, and the completed assessment can be exported to PDF.</p></div>
    <div className="card stack">
      <h2>Run assessment</h2>
      <form action="/api/agent/run" method="post" className="stack">
        <textarea name="prompt" required rows={7} defaultValue={assets[0]?`Assess ${assets[0].baseUrl}. Find security weaknesses, safely verify their real impact, prioritize confirmed issues, and prepare a clear remediation report.`:'Assess https://example.com. Find security weaknesses, safely verify their real impact, prioritize confirmed issues, and prepare a clear remediation report.'}/>
        <div className="muted">The URL must already be an ownership-verified asset. DeepSeek cannot expand scope or execute arbitrary commands.</div>
        <button className="btn">Start AI Security Assessment</button>
      </form>
    </div>
    <div className="card"><h2>Verified targets</h2>{assets.length?assets.map(a=><div key={a.id} className="muted" style={{padding:'6px 0'}}>{a.baseUrl}</div>):<p className="muted">No verified enabled assets yet. Add and verify a site first.</p>}</div>
  </div>;
}
