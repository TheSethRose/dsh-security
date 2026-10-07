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
const followup='Offline follow-up task: reply with the exact text offline-followup-result.';
const notification='Offline owned notification for the delegated worker.';
const prefixAnswer=value=>'Message Type: FINAL_ANSWER\nTask name: /root\nSender: /root/offline_worker\nPayload:\n'+value;
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
for(const forkTurns of ['none','all'])test(`real native V2 spawn, notification, follow-up and child returns preserve attributable plaintext (offline, fork ${forkTurns})`,{skip:!enabled,timeout:90000},async()=>{
  const repo=await mkdtemp(path.join(os.tmpdir(),'security-native-agents-'));
  const state=await mkdtemp(path.join(os.tmpdir(),'security-native-agents-state-'));
  await writeFile(path.join(repo,'example.py'),'print("offline agent fixture")\n');
  execFileSync('/usr/bin/git',['init','--quiet',repo]);
  const image=JSON.parse(await readFile(new URL('../image.json',import.meta.url),'utf8')).image;
  const selection={provider:'offline-configured-oauth',model:'fixture-native-model'};
  const requests=[],diagnostics=[];
  let started=false,childReceived=false,parentReceived=false,messageSent=false,messageReceived=false,followupStarted=false,followupReceived=false;
  const nativeTool=(options,name)=>{
    const raw=requests.flatMap(r=>r.collaboration??[]).find(t=>t.name===name);
    const tool=options.tools.find(t=>t.description===raw?.description);
    assert.ok(tool,'Native collaboration tool required: '+name);
    return tool;
  };
  const gateway=createHarnessGateway({selection,onDiagnostic:d=>diagnostics.push(d),llm:{async prepareCall(config){
    assert.deepEqual(config,selection);
    return {config,stream:async function*(options){
      const users=options.messages.filter(m=>m.role==='user');
      const delegated=users.filter(m=>m.content[0]?.text.startsWith('Message Type: NEW_TASK\nTask name: /root/offline_worker\n')).at(-1);
      if(delegated){
        if(users.some(m=>m.content.map(p=>p.text??'').join('').includes('Message Type: MESSAGE\nTask name: /root/offline_worker\nSender: /root\nPayload:\n'+notification)))messageReceived=true;
        const isFollowup=delegated.content.some(p=>p.text===followup);
        assert.deepEqual(delegated.content,[{type:'text',text:'Message Type: NEW_TASK\nTask name: /root/offline_worker\nSender: /root\nPayload:\n'},{type:'text',text:isFollowup?followup:task}]);
        if(isFollowup)followupReceived=true;else childReceived=true;
        yield* text(isFollowup?'offline-followup-result':'offline-child-result');return;
      }
      if(!started){
        started=true;
        yield* call(nativeTool(options,'spawn_agent'),{task_name:'offline_worker',fork_turns:forkTurns,message:task},'offline-spawn');return;
      }
      if(!messageSent){
        messageSent=true;
        yield* call(nativeTool(options,'send_message'),{target:'/root/offline_worker',message:notification},'offline-send');return;
      }
      const returned=users.filter(m=>m.content.length===1&&m.content[0].text.startsWith('Message Type: FINAL_ANSWER\nTask name: /root\nSender: /root/offline_worker\n')).at(-1);
      if(returned?.content[0].text===prefixAnswer('offline-followup-result')){
        parentReceived=true;
        throw Error('Offline adapter intentionally stops after follow-up child return');
      }
      if(returned?.content[0].text===prefixAnswer('offline-child-result')&&!followupStarted){
        followupStarted=true;
        yield* call(nativeTool(options,'followup_task'),{target:'/root/offline_worker',message:followup},'offline-followup');return;
      }
      const wait=nativeTool(options,'wait_agent');
      const args={timeout_ms:1000};
      for(const key of wait.parameters.required??[])assert.ok(Object.hasOwn(args,key),'Unexpected wait parameter: '+key);
      yield* call(wait,args,'offline-wait-'+requests.length);
    }};
  }}});
  await assert.rejects(runEngine({subprocess,docker:'/usr/local/bin/docker',image,repo,state,job:{id:randomUUID(),operation:'scan',mode:'standard',model:selection.model,minutes:1},signal:AbortSignal.timeout(60000),onDiagnostic:d=>diagnostics.push(d),gateway:async(body,signal)=>{
    requests.push({collaboration:(body.tools??[]).flatMap(t=>t.type==='namespace'&&t.name==='collaboration'?t.tools:t.namespace==='collaboration'?[t]:[]).map(t=>({name:t.name,description:t.description,keys:Object.keys(t.parameters?.properties??{}),required:t.parameters?.required??[]})),types:body.input?.map?.(i=>i.type??i.role),agents:body.input?.filter?.(i=>i.type==='agent_message').map(i=>({keys:Object.keys(i),author:i.author,recipient:i.recipient,fixtureHeader:i.content?.[0]?.text,parts:i.content?.map(p=>({keys:Object.keys(p),type:p.type,ownedTask:p.encrypted_content===task,ownedReply:p.encrypted_content==='offline-child-result'}))}))});
    return gateway(body,signal);
  }}));
  const evidence=JSON.stringify({requests:requests.map(r=>({...r,collaboration:r.collaboration.map(({description,...t})=>t)})),failures:diagnostics.filter(d=>d.outcome==='failed')});
  for(const [name,received]of Object.entries({started,childReceived,messageSent,messageReceived,followupStarted,followupReceived,parentReceived}))assert.ok(received,name+': '+evidence);
  const collaboration=requests.flatMap(r=>r.collaboration??[]);
  for(const name of ['spawn_agent','followup_task','send_message']){
    const tool=collaboration.find(t=>t.name===name);
    const route=name==='spawn_agent'?'task_name':'target';
    assert.ok(tool?.keys.includes(route)&&tool.keys.includes('message'),'Native collaboration route schema: '+name);
    assert.deepEqual(tool.required,[route,'message']);
  }
  const agents=requests.flatMap(r=>r.agents??[]);
  assert.ok(agents.some(a=>a.author==='/root'&&a.recipient==='/root/offline_worker'&&a.parts.some(p=>p.type==='encrypted_content'&&p.ownedTask)),evidence);
  assert.ok(agents.some(a=>a.author==='/root/offline_worker'&&a.recipient==='/root'&&a.fixtureHeader===prefixAnswer('offline-child-result')),evidence);
  assert.ok(agents.some(a=>a.author==='/root/offline_worker'&&a.recipient==='/root'&&a.fixtureHeader===prefixAnswer('offline-followup-result')),evidence);
  assert.equal(diagnostics.filter(d=>d.outcome==='failed'&&d.code==='PROTOCOL_ERROR').length,0,evidence);
});
