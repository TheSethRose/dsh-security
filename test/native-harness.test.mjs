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
test('real native scanner consumes Harness SSE, executes only a container tool and replays its output (offline)',{skip:!enabled,timeout:90000},async()=>{
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
      if(generated++===0){
        const tool=options.tools.find(t=>t.parameters?.properties?.cmd||t.parameters?.properties?.command);
        assert.ok(tool,'Native scanner must advertise a local command tool');toolChosen=true;
        const properties=tool.parameters.properties;
        const args={...(properties.cmd?{cmd:'pwd'}:{command:'pwd'}),...(properties.workdir?{workdir:'/repo'}:{})};
        for(const key of tool.parameters.required??[])assert.ok(Object.hasOwn(args,key),'Unexpected required command-tool field: '+key);
        const argumentsText=JSON.stringify(args);
        yield {type:'block-start',index:0,blockType:'tool-call'};
        yield {type:'tool-call-delta',index:0,id:'offline-adapter-call',name:tool.name,argumentsDelta:argumentsText};
        yield {type:'block-end',index:0,block:{type:'tool-call',id:'offline-adapter-call',name:tool.name,arguments:argumentsText}};
        yield {type:'finish',reason:{kind:'tool-calls'},replayState};
        return;
      }
      const assistant=options.messages.find(m=>m.role==='assistant'&&m.content.some(b=>b.type==='tool-call'&&b.id==='offline-adapter-call'));
      assert.ok(assistant,'Native history must restore the cached adapter tool-call identity');
      assert.deepEqual(assistant.source.replayState,replayState);
      const output=options.messages.find(m=>m.role==='tool'&&m.toolCallId==='offline-adapter-call');
      assert.ok(output,'Native local-tool result must map back to the adapter call');
      assert.match(JSON.stringify(output.content),/\/repo/);
      toolOutput=true;
      throw Error('Offline adapter intentionally stops after tool roundtrip');
    }};
  }}});
  let engineFailure;
  await assert.rejects(runEngine({subprocess,docker:process.env.DSH_SECURITY_DOCKER??'/usr/local/bin/docker',image,repo,state,job:{id:randomUUID(),operation:'scan',mode:'standard',model:selection.model,minutes:1},signal:AbortSignal.timeout(60000),gateway:async(body,signal)=>{
    requests.push({model:body.model,reasoning:body.reasoning,types:body.input?.map?.(i=>i.type??i.role)});
    const response=await gateway(body,signal);
    responses.push({status:response.status,...(response.status>=400?{error:await response.clone().text()}:{})});
    return response;
  }}),error=>{engineFailure=error;return true;});
  assert.ok(prepares.length>=2,'Native scanner must reach the prepared adapter twice: '+JSON.stringify({requests,responses,failure:engineFailure?.message}));
  assert.ok(toolChosen);assert.ok(toolOutput,'Offline container-tool roundtrip must complete: '+JSON.stringify({requests,responses}));
});
