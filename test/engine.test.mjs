import test from 'node:test';import assert from 'node:assert/strict';import os from 'node:os';import path from 'node:path';import {mkdtemp,readFile,writeFile} from 'node:fs/promises';import {randomUUID} from 'node:crypto';import {execFileSync} from 'node:child_process';
import {runEngine} from '../transport.mjs';import {subprocess} from './adapter.mjs';
const enabled=process.env.DSH_SECURITY_CONTAINER_TESTS==='1';
const image=JSON.parse(await readFile(new URL('../image.json',import.meta.url),'utf8')).image;
async function fixture(){const repo=await mkdtemp(path.join(os.tmpdir(),'security-fixture-')),state=await mkdtemp(path.join(os.tmpdir(),'security-state-'));await writeFile(path.join(repo,'example.py'),'print("fixture")\n');execFileSync('/usr/bin/git',['init','--quiet',repo]);return{repo,state};}
test('real isolated container is read-only and transports HTTP via Host only',{skip:!enabled,timeout:30000},async()=>{
 const paths=await fixture();let calls=0;
 const result=await runEngine({subprocess,docker:'/usr/local/bin/docker',image,...paths,job:{id:randomUUID(),operation:'probe',model:'deepseek-v4-pro'},signal:AbortSignal.timeout(20000),gateway:async(body,signal)=>{
  calls++;assert.equal(body.model,'deepseek-v4-pro');assert.equal(body.store,false);assert.ok(signal instanceof AbortSignal);return new Response('transport-ok',{headers:{'content-type':'text/plain'}});
 }});
 assert.equal(result.readonly,true);assert.equal(result.transportStatus,200);assert.equal(result.transportBody,'transport-ok');assert.equal(calls,1);
});
test('published Codex Security SDK mock scan and all exports work without credentials or inference',{skip:!enabled,timeout:90000},async()=>{
 const paths=await fixture();const noInference=()=>{throw Error('Mock must not request inference');};
 const result=await runEngine({subprocess,docker:'/usr/local/bin/docker',image,...paths,job:{id:randomUUID(),operation:'scan',mode:'standard',model:'deepseek-v4-pro',minutes:1,mock:true},signal:AbortSignal.timeout(60000),gateway:noInference});
 assert.ok(result.manifest);assert.ok(Array.isArray(result.findings.findings));assert.ok(result.report);assert.ok(result.manifest.scan);
 for(const format of ['json','csv','sarif']){const exported=await runEngine({subprocess,docker:'/usr/local/bin/docker',image,...paths,job:{id:randomUUID(),operation:'export',model:'deepseek-v4-pro',format},signal:AbortSignal.timeout(20000),gateway:noInference});assert.ok(exported.export.length>10);if(format!=='csv')assert.doesNotThrow(()=>JSON.parse(exported.export));}
});
