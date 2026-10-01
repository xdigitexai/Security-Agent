import './globals.css';
import Link from 'next/link';
import { currentUser } from '../lib/auth';

export const metadata={title:'Xdigitex Security Agent',description:'Authorized defensive web security testing with verified ownership, DeepSeek Flash planning, bounded verification, and complete assessment reports.'};

export default async function Layout({children}:{children:React.ReactNode}){
  const u=await currentUser();
  if(!u)return <html lang="en"><body>{children}</body></html>;
  const org=u.memberships[0]?.organization.name||'Security Workspace';
  const nav=[['Overview','/'],['AI Security Agent','/agent'],['Assets','/assets'],['Scans','/scans'],['Findings','/findings']];
  return <html lang="en"><body>
    <div className="shell">
      <aside className="side">
        <Link href="/" className="brand">
          <span className="brand-mark"/>
          <span className="brand-copy"><strong>XDIGITEX</strong><small>SECURITY AGENT</small></span>
        </Link>
        <div className="nav-label">Workspace</div>
        <nav className="nav">
          {nav.map(([label,href])=><Link href={href} key={href}><span className="nav-dot"/><span>{label}</span></Link>)}
        </nav>
        <div className="side-spacer"/>
        <div className="side-footer">
          <div className="signal"><span className="signal-dot"/>Guardrails active</div>
          <p>Verified scope, bounded requests, centralized scanner transport and sanitized evidence.</p>
        </div>
      </aside>
      <main className="main">
        <div className="top">
          <div><div className="workspace-name">{org}</div><div className="workspace-sub">Authorized defensive security operations</div></div>
          <div className="top-actions"><div className="model-chip">DeepSeek Flash</div><form action="/api/auth/logout" method="post"><button className="btn btn2">Sign out</button></form></div>
        </div>
        {children}
      </main>
    </div>
  </body></html>;
}
