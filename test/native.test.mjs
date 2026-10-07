import test from 'node:test';import assert from 'node:assert/strict';import os from 'node:os';import path from 'node:path';import {mkdtemp,readFile,writeFile} from 'node:fs/promises';import {randomUUID} from 'node:crypto';import {execFileSync} from 'node:child_process';import {runEngine} from '../transport.mjs';import {subprocess} from './adapter.mjs';
import vm from 'node:vm';
const enabled=process.env.DSH_SECURITY_CONTAINER_TESTS==='1';
test('native runner binds a generic copied catalog to job model/context without rewriting prompt',async()=>{
 const source=await readFile(new URL('../engine/runner.mjs',import.meta.url),'utf8'),template=await readFile(new URL('../engine/models.json',import.meta.url),'utf8'),writes=new Map(),configs=[];
 assert.doesNotMatch(template,/DeepSeek|api\.deepseek\.com/i);assert.doesNotMatch(source,/deepseek|base_instructions\s*=/i);
 class CodexSecurity{constructor(config){configs.push(config);}async run(){return {toJSON:()=>({}),reportPath:'/state/report'};}async close(){}}
 const run=vm.runInNewContext('('+source.slice(source.indexOf('async function run(job)'))+')',{mkdir:async()=>{},readFile:async file=>file==='/opt/security/models.json'?template:'fixture report',writeFile:async(file,value)=>writes.set(file,value),CodexSecurity,port:12345,controller:new AbortController(),emit:()=>{}});
 for(const job of [{model:'custom-native-model',contextWindow:131072},{model:'another-native-model'}]){
  await run({operation:'scan',...job});const catalog=JSON.parse(writes.get('/scratch/models.json')),original=JSON.parse(template);assert.equal(catalog.models[0].slug,job.model);assert.equal(catalog.models[0].base_instructions,original.models[0].base_instructions);assert.equal(catalog.models[0].context_window,job.contextWindow??original.models[0].context_window);assert.equal(catalog.models[0].max_context_window,job.contextWindow??original.models[0].max_context_window);assert.equal(configs.at(-1).codexOverrides.model,job.model);assert.equal(configs.at(-1).codexOverrides.model_provider,'harness');assert.deepEqual(Object.keys(configs.at(-1).codexOverrides.model_providers),['harness']);assert.equal(configs.at(-1).codexOverrides.model_catalog_json,'/scratch/models.json');
 }
});
test('native scanner command auth reaches only the controlled Harness gateway (no paid inference)',{skip:!enabled,timeout:90000},async()=>{
 const repo=await mkdtemp(path.join(os.tmpdir(),'security-native-')),state=await mkdtemp(path.join(os.tmpdir(),'security-native-state-'));await writeFile(path.join(repo,'example.py'),'print("native fixture")\n');execFileSync('/usr/bin/git',['init','--quiet',repo]);
 const image=JSON.parse(await readFile(new URL('../image.json',import.meta.url),'utf8')).image;let calls=0,failure;const requests=[];
 await assert.rejects(runEngine({subprocess,docker:'/usr/local/bin/docker',image,repo,state,job:{id:randomUUID(),operation:'scan',mode:'standard',model:'fixture-native-model',contextWindow:131072,minutes:1},signal:AbortSignal.timeout(60000),gateway:async(body,signal)=>{
  calls++;assert.equal(body.model,'fixture-native-model');assert.ok(signal instanceof AbortSignal);requests.push(body);
  return new Response(JSON.stringify({error:{message:'Offline native provider probe intentionally denied',type:'invalid_api_key'}}),{status:401,headers:{'content-type':'application/json'}});
 }}),error=>{failure=error;return true;});assert.ok(calls>0,'Native scanner must actually reach the controlled gateway: '+failure?.message);for(const request of requests)assert.equal(request.model,'fixture-native-model');
});
