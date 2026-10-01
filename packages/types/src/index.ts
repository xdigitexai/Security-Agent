export type Severity = 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFORMATIONAL';
export type Confidence = 'CONFIRMED'|'HIGH'|'MEDIUM'|'LOW'|'NEEDS_REVIEW';
export type FindingStatus = 'OPEN'|'FIXED'|'IGNORED'|'FALSE_POSITIVE'|'RETESTING';

export interface ScanScope {
  allowedHosts: string[];
  allowedProtocols: Array<'http'|'https'>;
  maxDepth: number;
  maxPages: number;
  maxRequests: number;
  maxRequestsPerSecond: number;
  allowSubdomains: boolean;
}

export interface EvidenceInput {
  requestMethod?: string;
  requestUrl?: string;
  requestHeaders?: Record<string,string>;
  requestBody?: string;
  responseStatus?: number;
  responseHeaders?: Record<string,string>;
  responseExcerpt?: string;
  timestamp: Date;
}

export interface SecurityFinding {
  checkId: string;
  title: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  affectedUrl: string;
  method?: string;
  parameter?: string;
  impact: string;
  remediation: string;
  evidence?: EvidenceInput[];
}

export interface DiscoveredEndpointInput {
  url: string;
  method: string;
  parameters?: string[];
  responseCode?: number;
  contentType?: string;
}

export type ApplicationSurfaceKind = 'AUTH'|'ADMIN'|'UPLOAD'|'PAYMENT'|'API'|'GRAPHQL'|'API_DOCS'|'WEBSOCKET'|'ACCOUNT'|'SEARCH'|'OTHER';
export interface ApplicationSurface { kind:ApplicationSurfaceKind; url:string; method:string; source:'page'|'network'|'form'|'script'|'websocket'; parameters?:string[]; }
export interface TechnologySignal { name:string; evidence:string; }
export interface ApplicationMap {
  surfaces: ApplicationSurface[];
  technologies: TechnologySignal[];
  externalDependencies: string[];
  authUrls: string[];
  apiUrls: string[];
  adminUrls: string[];
  uploadUrls: string[];
  paymentUrls: string[];
  graphqlUrls: string[];
  apiDocsUrls: string[];
  websocketUrls: string[];
}
