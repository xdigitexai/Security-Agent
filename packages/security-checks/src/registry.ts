import { headerCheck } from './headers';
import { cookieCheck } from './cookies';
import { secretCheck } from './secrets';
import { exposureCheck } from './exposure';
import { corsCheck } from './cors';
import { clientCheck } from './client';
import { reflectionCheck } from './reflection';
import { redirectCheck } from './redirect';
import { apiDocsCheck } from './api-docs';
import { apiReconCheck } from './api-recon';
import { inputErrorCheck } from './input-errors';
import { errorDisclosureCheck } from './error-disclosure';
import { sensitiveCacheCheck } from './cache-sensitive';
import { controlledAuthorizationCheck, revokedSessionCheck } from './authorization';
import { endpointCoverageCheck } from './coverage';
import { apiSurfaceCheck } from './api-surface';
import { artifactCheck } from './artifacts';

export const checks=[
  headerCheck,
  cookieCheck,
  secretCheck,
  exposureCheck,
  corsCheck,
  apiDocsCheck,
  apiReconCheck,
  errorDisclosureCheck,
  inputErrorCheck,
  sensitiveCacheCheck,
  controlledAuthorizationCheck,
  revokedSessionCheck,
  clientCheck,
  reflectionCheck,
  redirectCheck,
  endpointCoverageCheck,
  apiSurfaceCheck,
  artifactCheck
];
export function checkById(id:string){return checks.find(check=>check.id===id);}
