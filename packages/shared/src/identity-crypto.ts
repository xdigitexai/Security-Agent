import crypto from 'node:crypto';
import { env } from './env';

export interface EncryptedValue { ciphertext:string; iv:string; tag:string; }

function key(){
  const cfg=env();
  if(cfg.IDENTITY_ENCRYPTION_KEY){
    const decoded=Buffer.from(cfg.IDENTITY_ENCRYPTION_KEY,'base64');
    if(decoded.length!==32) throw new Error('IDENTITY_ENCRYPTION_KEY must decode to exactly 32 bytes');
    return decoded;
  }
  if(process.env.NODE_ENV==='production') throw new Error('IDENTITY_ENCRYPTION_KEY is required in production');
  return crypto.createHash('sha256').update(cfg.SESSION_SECRET).digest();
}

export function encryptIdentitySecret(secret:string):EncryptedValue{
  const iv=crypto.randomBytes(12);
  const cipher=crypto.createCipheriv('aes-256-gcm',key(),iv);
  const ciphertext=Buffer.concat([cipher.update(secret,'utf8'),cipher.final()]);
  return {ciphertext:ciphertext.toString('base64'),iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64')};
}

export function decryptIdentitySecret(value:EncryptedValue){
  const decipher=crypto.createDecipheriv('aes-256-gcm',key(),Buffer.from(value.iv,'base64'));
  decipher.setAuthTag(Buffer.from(value.tag,'base64'));
  return Buffer.concat([decipher.update(Buffer.from(value.ciphertext,'base64')),decipher.final()]).toString('utf8');
}
