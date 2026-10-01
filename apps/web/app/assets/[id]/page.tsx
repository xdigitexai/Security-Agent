import { redirect,notFound } from 'next/navigation';
import { currentUser,requireOrg } from '../../../lib/auth';
import { db } from '@xdigitex/database';

export default async function Page({params,searchParams}:{params:Promise<{id:string}>;searchParams:Promise<Record<string,string|undefined>>}){
  if(!await currentUser()) redirect('/login');
  const {org,role}=await requireOrg();
  const {id}=await params;
  const q=await searchParams;
  const a=await db.asset.findFirst({where:{id,organizationId:org.id},include:{verifications:{orderBy:{createdAt:'desc'},take:1},testIdentities:{orderBy:{createdAt:'asc'}},testResources:{orderBy:{createdAt:'asc'}}}});
  if(!a) notFound();
  const v=a.verifications[0];
  const canManage=['OWNER','ADMIN'].includes(role);
  const fileUrl=new URL('/xdigitex-security-verification.html',a.baseUrl).toString();
  const verificationNotice=q.verification==='verified'?'Ownership verified successfully.':q.verification==='failed'?'Proof was not found yet. Fix the item below and press Verify now again.':q.verification==='expired'?'That verification token expired. Generate a new one.':q.verification==='created'?'Verification proof generated. Publish it using the selected method, then press Verify now.':null;

  return <div className="stack"><div><div className="eyebrow">Asset ownership</div><h1>{a.normalizedHost}</h1><p className="lead">Prove that you control this site once, then scanning can run without repeating verification.</p></div>
    {a.verifiedAt?<div className="card"><b>Ownership verified</b><p className="muted" style={{marginTop:8,marginBottom:0}}>Safe scanning and controlled identity testing can be configured for this asset.</p></div>:<div className="card stack">
      <div><h2>Verify ownership</h2><p className="muted">HTML file is the easiest option for cPanel, shared hosting, VPS and most website builders. DNS TXT and HTML meta tag remain available.</p></div>
      {verificationNotice&&<div className="card" style={{borderColor:q.verification==='verified'?'rgba(56,211,159,.35)':'rgba(247,186,80,.35)'}}>{verificationNotice}</div>}
      <form action={`/api/assets/${a.id}/verification`} method="post" className="row">
        <select name="method" defaultValue="FILE">
          <option value="FILE">HTML verification file — recommended</option>
          <option value="DNS_TXT">DNS TXT record</option>
          <option value="META">HTML meta tag</option>
        </select>
        <button className="btn">Generate verification</button>
      </form>

      {v&&<div className="stack">
        <div className="spread"><div><div className="muted" style={{fontSize:11}}>Current method</div><b>{v.method==='FILE'?'HTML verification file':v.method==='DNS_TXT'?'DNS TXT record':'HTML meta tag'}</b></div><span className="status-pill">{v.status}</span></div>

        {v.method==='FILE'&&<div className="card stack">
          <div><h3>1. Download the generated file</h3><p className="muted">The file already contains your current ownership token. You do not need to edit it.</p></div>
          <div className="row"><a className="btn" href={`/api/assets/${a.id}/verification/file`}>Download HTML file</a></div>
          <div><h3>2. Upload it to your website root</h3><p className="muted">For cPanel this is normally <code>public_html/xdigitex-security-verification.html</code>.</p><div className="card"><code>{fileUrl}</code></div></div>
          <div><h3>3. Confirm it opens publicly</h3><p className="muted">Open the URL below. If the page displays the Xdigitex verification marker, come back and press Verify now.</p><a href={fileUrl} target="_blank" rel="noreferrer">Open verification file →</a></div>
          <details><summary className="muted">Manual file content</summary><pre>{`<!doctype html>\n<html>\n<head><meta name="xdigitex-security-verification" content="${v.token}"></head>\n<body>xdigitex-security-verification=${v.token}</body>\n</html>`}</pre></details>
        </div>}

        {v.method==='DNS_TXT'&&<div className="card stack">
          <div><h3>Add this DNS record</h3><p className="muted">Use the root/apex of the domain. DNS providers may display the host as <code>@</code> or leave it blank.</p></div>
          <div className="grid-3"><div><div className="muted">Type</div><b>TXT</b></div><div><div className="muted">Host / Name</div><b>@</b></div><div><div className="muted">TTL</div><b>Auto / 300</b></div></div>
          <div><div className="muted">Value</div><pre>{`xdigitex-security-verification=${v.token}`}</pre></div>
          <p className="muted">DNS propagation can take time. You can keep pressing Verify now with the same token until it appears or the token expires.</p>
        </div>}

        {v.method==='META'&&<div className="card stack">
          <div><h3>Add this tag inside your homepage &lt;head&gt;</h3><p className="muted">Publish the change, confirm the public homepage contains it, then press Verify now.</p></div>
          <pre>{`<meta name="xdigitex-security-verification" content="${v.token}">`}</pre>
        </div>}

        {v.failureReason&&<div className="card" style={{borderColor:'rgba(255,107,129,.28)'}}><b>Last check</b><p className="muted" style={{marginTop:7,marginBottom:0}}>{v.failureReason}</p></div>}
        <form action={`/api/assets/${a.id}/verification/check`} method="post" className="row"><button className="btn">Verify now</button><span className="muted">Checks are bounded and normally return within a few seconds.</span></form>
      </div>}
    </div>}

    {a.verifiedAt&&<><div className="card stack"><h2>Controlled identities</h2><p className="muted">Identity records hold labels, roles, tenants and a deployment profile reference only. Reusable access material is not stored in the application database.</p>{a.testIdentities.length===0?<p className="muted">No identities configured.</p>:a.testIdentities.map(i=><div className="row" key={i.id}><b>{i.label}</b><span>{i.roleLabel}</span><span>{i.tenantLabel||'no tenant'}</span><span>{i.expectedSessionState}</span><code>{i.credentialRef}</code></div>)}{canManage&&<form action={`/api/assets/${a.id}/test-identities`} method="post" className="stack"><div className="row"><input name="label" placeholder="Identity label" required/><input name="roleLabel" placeholder="Role label" required/><input name="tenantLabel" placeholder="Tenant label"/></div><div className="row"><select name="authType"><option value="HEADERS">Header profile</option><option value="BEARER">Token profile</option><option value="COOKIE">Session profile</option></select><input name="credentialRef" placeholder="XD_TEST_PROFILE_MEMBER_A" required/><select name="expectedSessionState"><option value="ACTIVE">Expected active</option><option value="REVOKED">Expected revoked</option></select><button className="btn">Register identity</button></div></form>}</div>
    <div className="card stack"><h2>Authorization test resources</h2><p className="muted">Only owner-declared read-only URLs on this verified host are eligible. A harmless marker in test data can be supplied to improve evidence confidence.</p>{a.testResources.length===0?<p className="muted">No resources configured.</p>:a.testResources.map(r=><div key={r.id}><b>{r.label}</b> <code>{r.method} {r.url}</code> <span>{r.expectation}</span></div>)}{canManage&&a.testIdentities.length>0&&<form action={`/api/assets/${a.id}/test-resources`} method="post" className="stack"><div className="row"><input name="label" placeholder="Resource label" required/><input name="url" placeholder={`https://${a.normalizedHost}/api/test-resource/123`} required/><select name="method"><option value="GET">GET</option><option value="HEAD">HEAD</option></select></div><div className="row"><label>Owner <select name="ownerIdentityId">{a.testIdentities.map(i=><option key={i.id} value={i.id}>{i.label}</option>)}</select></label><select name="expectation"><option value="DENY_COMPARATORS">Deny selected comparators</option><option value="PUBLIC">Public</option></select><input name="proofMarker" placeholder="Optional harmless marker"/></div><div>{a.testIdentities.map(i=><label key={i.id} style={{marginRight:16}}><input type="checkbox" name="comparatorIdentityIds" value={i.id}/> {i.label}</label>)}</div><button className="btn">Add resource</button></form>}</div></>}
  </div>;
}
