import type { NextConfig } from 'next';
const config:NextConfig={transpilePackages:['@xdigitex/database','@xdigitex/shared','@xdigitex/types','@xdigitex/scanner-core'],poweredByHeader:false,experimental:{serverActions:{bodySizeLimit:'1mb'}}}; export default config;
