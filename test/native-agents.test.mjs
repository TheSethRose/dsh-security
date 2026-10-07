import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {mkdtemp,readFile,writeFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {runEngine} from '../transport.mjs';
import {createHarnessGateway} from '../harness-gateway.mjs';
import {subprocess} from './adapter.mjs';

const enabled=process.env.DSH_SECURITY_CONTAINER_TESTS==='1';
const task='Offline delegated task: reply with the exact text offline-child-result. Do not execute commands or delegate.';
const prefixAnswer='Message Type: FINAL_ANSWER\nTask name: /root\nSender: /root/offline_worker\nPayload:\noffline-child-result';
function* text(value){
  yield {type:'block-start',index:0,blockType:'text'};
  yield {type:'text-delta',index:0,text:value};
  yield {type:'block-end',index:0,block:{type:'text',text:value}};
  yield {type:'finish',reason:{kind:'stop'}};
}
function* call(tool,args,id){
  const argumentsText=JSON.stringify(args);
  yield {type:'block-start',index:0,blockType:'tool-call'};
  yield {type:'tool-call-delta',index:0,id,name:tool.name,argumentsDelta:argumentsText};
  yield {type:'block-end',index:0,block:{type:'tool-call',id,name:tool.name,arguments:argumentsText}};
  yield {type:'finish',reason:{kind:'tool-calls'}};
}
for(const forkTurns of ['none','all'])test(`real native V2 spawn and child return preserve attributable plaintext (offline, fork ${forkTurns})`,{skip:!enabled,timeout:90000},async()=>{
  const repo=await mkdtemp(path.join(os.tmpdir(),'security-native-agents-'));
  const state=await mkdtemp(path.join(os.tmpdir(),'security-native-agents-state-'));
  await writeFile(path.join(repo,'example.py'),'print("offline agent fixture")\n');
  execFileSync('/usr/bin/git',['init','--quiet',repo]);
  const image=JSON.parse(await readFile(new URL('../image.json',import.meta.url),'utf8')).image;
  const selection={provider:'offline-configured-oauth',model:'fixture-native-model'};
  const requests=[],diagnostics=[];
  let started=false,childReceived=false,parentReceived=false;
  const gateway=createHarnessGateway({selection,onDiagnostic:d=>diagnostics.push(d),llm:{async prepareCall(config){
    assert.deepEqual(config,selection);
    return {config,stream:async function*(options){
      const userText=options.messages.filter(m=>m.role==='user').flatMap(m=>m.content).map(p=>p.text??'').join('\n');
      if(userText.includes(task)){
        const delegated=options.messages.find(m=>m.role==='user'&&m.content.some(p=>p.text===task));
        assert.deepEqual(delegated?.content,[{type:'text',text:'Message Type: NEW_TASK\nTask name: /root/offline_worker\nSender: /root\nPayload:\n'},{type:'text',text:task}]);
        childReceived=true;
        yield* text('offline-child-result');return;
      }
      if(userText.includes('offline-child-result')){
        assert.ok(options.messages.some(m=>m.role==='user'&&m.content.length===1&&m.content[0].text==='Message Type: FINAL_ANSWER\nTask name: /root\nSender: /root/offline_worker\nPayload:\noffline-child-result'),'Parent must receive the exact owned child answer');
        parentReceived=true;
        throw Error('Offline adapter intentionally stops after child return');
      }
      if(!started){
        const spawn=options.tools.find(t=>t.parameters?.properties?.task_name&&t.parameters?.properties?.fork_turns&&t.parameters?.properties?.message);
        assert.ok(spawn,'Native V2 collaboration spawn tool required');started=true;
        yield* call(spawn,{task_name:'offline_worker',fork_turns:forkTurns,message:task},'offline-spawn');return;
      }
      const wait=options.tools.find(t=>t.parameters?.properties?.timeout_ms&&!t.parameters?.properties?.cmd&&!t.parameters?.properties?.command);
      assert.ok(wait,'Native V2 wait tool required');
      const args={timeout_ms:1000};
      for(const key of wait.parameters.required??[])assert.ok(Object.hasOwn(args,key),'Unexpected wait parameter: '+key);
      yield* call(wait,args,'offline-wait-'+requests.length);
    }};
  }}});
  await assert.rejects(runEngine({subprocess,docker:'/usr/local/bin/docker',image,repo,state,job:{id:randomUUID(),operation:'scan',mode:'standard',model:selection.model,minutes:1},signal:AbortSignal.timeout(60000),gateway:async(body,signal)=>{
    requests.push({types:body.input?.map?.(i=>i.type??i.role),agents:body.input?.filter?.(i=>i.type==='agent_message').map(i=>({keys:Object.keys(i),author:i.author,recipient:i.recipient,fixtureHeader:i.content?.[0]?.text,parts:i.content?.map(p=>({keys:Object.keys(p),type:p.type,ownedTask:p.encrypted_content===task,ownedReply:p.encrypted_content==='offline-child-result'}))}))});
    return gateway(body,signal);
  }}));
  const evidence=JSON.stringify({requests,failures:diagnostics.filter(d=>d.outcome==='failed')});
  assert.ok(started,evidence);assert.ok(childReceived,'Child task never reached adapter: '+evidence);assert.ok(parentReceived,'Child reply never reached parent adapter: '+evidence);
  const agents=requests.flatMap(r=>r.agents??[]);
  assert.ok(agents.some(a=>a.author==='/root'&&a.recipient==='/root/offline_worker'&&a.parts.some(p=>p.type==='encrypted_content'&&p.ownedTask)),evidence);
  assert.ok(agents.some(a=>a.author==='/root/offline_worker'&&a.recipient==='/root'&&a.fixtureHeader===prefixAnswer),evidence);
  assert.equal(diagnostics.filter(d=>d.outcome==='failed'&&d.code==='PROTOCOL_ERROR').length,0,evidence);
});
