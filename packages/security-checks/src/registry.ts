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
import { errorDisclosureCheck } from './error-disclosure';
import { sensitiveCacheCheck } from './cache-sensitive';
import { controlledAuthorizationCheck, revokedSessionCheck } from './authorization';

export const checks=[
  headerCheck,
  cookieCheck,
  secretCheck,
  exposureCheck,
  corsCheck,
  apiDocsCheck,
  apiReconCheck,
  errorDisclosureCheck,
  sensitiveCacheCheck,
  controlledAuthorizationCheck,
  revokedSessionCheck,
  clientCheck,
  reflectionCheck,
  redirectCheck
];
export function checkById(id:string){return checks.find(check=>check.id===id);}
