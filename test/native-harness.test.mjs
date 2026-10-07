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
import {setTimeout as delay} from 'node:timers/promises';

const enabled=process.env.DSH_SECURITY_CONTAINER_TESTS==='1';
for(const mixed of [false,true,'empty-text','empty-reasoning','interleaved','late-reasoning','late-reasoning-only','namespaced','multiturn'])test('real native scanner consumes Harness SSE and replays '+(mixed==='empty-text'?'empty text alongside reasoning and tools':mixed==='empty-reasoning'?'empty reasoning alongside text and tools':mixed==='late-reasoning-only'?'reasoning completed after tools with no text and a delayed stream':mixed==='late-reasoning'?'reasoning completed after text and tools':mixed==='interleaved'?'interleaved reasoning and text before multiple tools':mixed==='multiturn'?'five consecutive native turns ending with a namespaced MCP tool':mixed==='namespaced'?'reasoning, text, a namespaced MCP tool and container tools':mixed?'reasoning, text and multiple tools':'a container tool')+' (offline)',{skip:!enabled,timeout:90000},async()=>{
  const repo=await mkdtemp(path.join(os.tmpdir(),'security-native-bridge-'));
  const state=await mkdtemp(path.join(os.tmpdir(),'security-native-bridge-state-'));
  await writeFile(path.join(repo,'example.py'),'print("offline bridge fixture")\n');
  execFileSync('/usr/bin/git',['init','--quiet',repo]);
  const image=JSON.parse(await readFile(new URL('../image.json',import.meta.url),'utf8')).image;
  const selection={provider:'offline-configured-oauth',model:'fixture-native-model'};
  const prepares=[],requests=[],responses=[];
  let generated=0,toolOutput=false,toolChosen=false;
  const replayState={response:{fixture:'opaque offline provider state'}};
  const gateway=createHarnessGateway({selection,llm:{async prepareCall(config,signal){
    assert.deepEqual(config,selection);assert.ok(signal instanceof AbortSignal);prepares.push(config);
    return {config,stream:async function*(options){
      const turn=generated++,reasoningText=mixed==='empty-reasoning'?'':'offline planning',assistantText=mixed==='empty-text'?'':'offline command check';
      if(turn<(mixed==='multiturn'?5:1)){
        const tool=options.tools.find(t=>t.parameters?.properties?.cmd||t.parameters?.properties?.command);
        assert.ok(tool,'Native scanner must advertise a local command tool');toolChosen=true;
        const properties=tool.parameters.properties;
        const args={...(properties.cmd?{cmd:'pwd'}:{command:'pwd'}),...(properties.workdir?{workdir:'/repo'}:{})};
        for(const key of tool.parameters.required??[])assert.ok(Object.hasOwn(args,key),'Unexpected required command-tool field: '+key);
        const argumentsText=JSON.stringify(args);
        const lateOnly=mixed==='late-reasoning-only',late=lateOnly||mixed==='late-reasoning';
        const interleaved=mixed==='interleaved'||late||mixed==='multiturn'&&turn===4;
        if(mixed){
          yield {type:'block-start',index:0,blockType:'reasoning'};
          yield {type:'reasoning-delta',index:0,text:reasoningText};
          if(!interleaved)yield {type:'block-end',index:0,block:{type:'reasoning',text:reasoningText}};
          if(!lateOnly){
            yield {type:'block-start',index:1,blockType:'text'};
            yield {type:'text-delta',index:1,text:assistantText};
            if(interleaved&&!late)yield {type:'block-end',index:0,block:{type:'reasoning',text:reasoningText}};
            yield {type:'block-end',index:1,block:{type:'text',text:assistantText}};
          }
        }
        const namespaced=mixed==='namespaced'||mixed==='multiturn'&&turn===4;
        if(namespaced){
          const progress=options.tools.find(t=>t.parameters?.properties?.scanId&&t.parameters?.properties?.preflightChecks);
          assert.ok(progress,'Native scanner must advertise its namespaced MCP progress tool');
          const argumentsText=JSON.stringify({scanId:randomUUID(),phase:'preflight',preflightChecks:[]});
          yield {type:'block-start',index:2,blockType:'tool-call'};
          yield {type:'tool-call-delta',index:2,id:'offline-adapter-progress',name:progress.name,argumentsDelta:argumentsText};
          yield {type:'block-end',index:2,block:{type:'tool-call',id:'offline-adapter-progress',name:progress.name,arguments:argumentsText}};
        }
        for(let n=0;n<(mixed?2:1);n++){
          const index=mixed?n+(lateOnly?1:namespaced?3:2):0,callId=(n?'offline-adapter-call-2':'offline-adapter-call')+(turn?'-turn-'+turn:'');
          yield {type:'block-start',index,blockType:'tool-call'};
          yield {type:'tool-call-delta',index,id:callId,name:tool.name,argumentsDelta:argumentsText};
          yield {type:'block-end',index,block:{type:'tool-call',id:callId,name:tool.name,arguments:argumentsText}};
          if(lateOnly)await delay(300);
        }
        if(late)yield {type:'block-end',index:0,block:{type:'reasoning',text:reasoningText}};
         yield {type:'finish',reason:{kind:'tool-calls'},replayState};
        return;
      }
      const assistant=options.messages.find(m=>m.role==='assistant'&&m.content.some(b=>b.type==='tool-call'&&b.id==='offline-adapter-call'));
      assert.ok(assistant,'Native history must restore the cached adapter tool-call identity');
      assert.deepEqual(assistant.source.replayState,replayState);
      const output=options.messages.find(m=>m.role==='tool'&&m.toolCallId==='offline-adapter-call');
      assert.ok(output,'Native local-tool result must map back to the adapter call');
      assert.match(JSON.stringify(output.content),/\/repo/);
      if(mixed){
        assert.deepEqual(assistant.content.map(block=>block.type),mixed==='late-reasoning-only'?['reasoning','tool-call','tool-call']:mixed==='namespaced'?['reasoning','text','tool-call','tool-call','tool-call']:['reasoning','text','tool-call','tool-call']);
        assert.ok(options.messages.some(m=>m.role==='tool'&&m.toolCallId==='offline-adapter-call-2'));
        if(mixed==='namespaced'||mixed==='multiturn'){
          assert.ok(options.messages.some(m=>m.role==='tool'&&m.toolCallId==='offline-adapter-progress'));
          const progressAssistant=options.messages.find(m=>m.role==='assistant'&&m.content.some(b=>b.id==='offline-adapter-progress'));
          assert.deepEqual(progressAssistant.content.map(b=>b.type),['reasoning','text','tool-call','tool-call','tool-call']);
          assert.deepEqual(progressAssistant.source.replayState,replayState);
        }
      }
      toolOutput=true;
      throw Error('Offline adapter intentionally stops after tool roundtrip');
    }};
  }}});
  let engineFailure,nativeReplay;
  await assert.rejects(runEngine({subprocess,docker:process.env.DSH_SECURITY_DOCKER??'/usr/local/bin/docker',image,repo,state,job:{id:randomUUID(),operation:'scan',mode:'standard',model:selection.model,minutes:1},signal:AbortSignal.timeout(60000),gateway:async(body,signal)=>{
    requests.push({model:body.model,reasoning:body.reasoning,types:body.input?.map?.(i=>i.type??i.role),outputKinds:body.input?.filter?.(i=>i.type==='function_call_output').map(i=>({kind:Array.isArray(i.output)?'array':typeof i.output,partTypes:Array.isArray(i.output)?i.output.map(p=>p.type):undefined}))});
    if(mixed&&requests.length===2)nativeReplay=body.input.filter(item=>item.type==='reasoning'||item.role==='assistant'||item.type==='function_call');
    const response=await gateway(body,signal);
    responses.push({status:response.status,...(response.status>=400?{error:await response.clone().text()}:{})});
    return response;
  }}),error=>{engineFailure=error;return true;});
  if(mixed){
    assert.equal(nativeReplay?.length,mixed==='late-reasoning-only'?3:mixed==='namespaced'?5:4,'Offline native replay did not reach the second request: '+JSON.stringify({requests,responses,failure:engineFailure?.message}));
    if(mixed==='late-reasoning')assert.deepEqual(nativeReplay.map(i=>i.type),['message','function_call','function_call','reasoning']);
    const reasoning=nativeReplay.find(i=>i.type==='reasoning'),message=nativeReplay.find(i=>i.type==='message');
    assert.equal(reasoning.content,null);
    assert.equal(reasoning.encrypted_content,null);
    if(mixed==='late-reasoning-only')assert.deepEqual(nativeReplay.map(i=>i.type),['function_call','function_call','reasoning']);
    else assert.equal(message.content[0].annotations,undefined);
  }
  assert.ok(prepares.length>=(mixed==='multiturn'?6:2),'Native scanner must reach every prepared adapter turn: '+JSON.stringify({requests,responses,failure:engineFailure?.message}));
  assert.ok(toolChosen);assert.ok(toolOutput,'Offline container-tool roundtrip must complete: '+JSON.stringify({requests,responses}));
});
