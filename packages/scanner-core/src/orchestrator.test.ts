import { describe,it,expect,vi } from 'vitest';
import { runChecks, type ScanContext, type SecurityCheck } from './orchestrator';

const ctx=(canceled=false)=>({isCanceled:async()=>canceled}) as unknown as ScanContext;
const check=(id:string,run:()=>Promise<never[]>):SecurityCheck=>({id,name:id,category:'Test',run});

describe('runChecks',()=>{
  it('continues with the remaining checks when one check throws',async()=>{
    const ran:string[]=[];
    const failing=check('secrets.public',async()=>{throw new Error('SCOPE_HOST_BLOCKED');});
    const next=check('headers.baseline',async()=>{ran.push('headers.baseline');return [];});
    const skipped:Array<{id:string;error:unknown;index:number}>=[];

    const findings=await runChecks(ctx(),[failing,next],undefined,async(c,e,i)=>{skipped.push({id:c.id,error:e,index:i});});

    expect(ran).toEqual(['headers.baseline']);
    expect(findings).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0]!.id).toBe('secrets.public');
    expect((skipped[0]!.error as Error).message).toBe('SCOPE_HOST_BLOCKED');
  });

  it('keeps findings from checks that ran while another one failed',async()=>{
    const failing=check('broken',async()=>{throw new Error('SCOPE_HOST_BLOCKED');});
    const good=check('good',async()=>[{checkId:'good'} as never]);
    const findings=await runChecks(ctx(),[failing,good]);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.checkId).toBe('good');
  });

  it('still propagates cancellation from a check',async()=>{
    const canceling=check('x',async()=>{throw new Error('SCAN_CANCELED');});
    await expect(runChecks(ctx(),[canceling])).rejects.toThrow('SCAN_CANCELED');
  });

  it('does not start a check when the scan is already canceled',async()=>{
    const run=vi.fn(async()=>[] as never[]);
    await expect(runChecks(ctx(true),[check('x',run)])).rejects.toThrow('SCAN_CANCELED');
    expect(run).not.toHaveBeenCalled();
  });
});
