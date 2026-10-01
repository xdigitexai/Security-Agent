import { headerCheck } from './headers';
import { cookieCheck } from './cookies';
import { secretCheck } from './secrets';
import { corsCheck } from './cors';
import { clientCheck } from './client';
import { reflectionCheck } from './reflection';
import { redirectCheck } from './redirect';
import { apiDocsCheck } from './api-docs';
import { errorDisclosureCheck } from './error-disclosure';
import { sensitiveCacheCheck } from './cache-sensitive';
export const checks=[headerCheck,cookieCheck,secretCheck,corsCheck,apiDocsCheck,errorDisclosureCheck,sensitiveCacheCheck,clientCheck,reflectionCheck,redirectCheck];
export function checkById(id:string){return checks.find(check=>check.id===id);}
