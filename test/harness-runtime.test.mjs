import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createHarnessGateway} from '../harness-gateway.mjs';

// Resolve the actual runtime shipped with the pinned Harness tools package.
const require=createRequire(import.meta.url);
const shipped=createRequire(require.resolve('@deepseek-ai/dsh-tools'));
const {Context}=await import(shipped.resolve('@deepseek-ai/cordis'));
const {LlmRuntime,LlmAdapter}=await import(shipped.resolve('@deepseek-ai/dsh-llm'));
const selection={provider:'offline-runtime-fixture',model:'offline-model'};

function fixture(){
  const ctx=new Context(),llm=new LlmRuntime(ctx),calls=[];
  class OfflineAdapter extends LlmAdapter {
    async prepareCall(provider,model){
      return {model:{provider,id:model,name:model,defaultMaxTokens:8192},stream:async function*(options){
        calls.push(options);
        yield {type:'block-start',index:0,blockType:'text'};
        yield {type:'text-delta',index:0,text:'offline'};
        yield {type:'block-end',index:0,block:{type:'text',text:'offline'}};
        yield {type:'finish',reason:{kind:'stop'}};
      }};
    }
  }
  llm.registerAdapter([selection.provider],new OfflineAdapter());
  return {ctx,llm,calls};
}

test('shipped Harness rejects request controls changed after prepareCall',async()=>{
  const f=fixture();
  try {
    const prepared=await f.llm.prepareCall(selection);
    assert.equal(prepared.config.maxTokens,8192);
    assert.throws(()=>prepared.stream({...prepared.config,maxTokens:50,messages:[]}),{code:'INVALID_PREPARED_CALL'});
    assert.equal(f.calls.length,0);
  } finally {await f.ctx.fiber.dispose();}
});

test('gateway binds native request controls before real Harness preparation and dispatch',async()=>{
  for(const stream of [false,true])for(const controls of [{},{max_output_tokens:50},{temperature:0},{max_output_tokens:50,temperature:0.2}]){
    const f=fixture();
    try {
      const gateway=createHarnessGateway({llm:f.llm,selection});
      const response=await gateway({model:selection.model,input:'offline fixture',stream,...controls});
      assert.equal(response.status,200,await response.clone().text());
      const text=await response.text();
      assert.ok(!text.includes('"status":"failed"'),text);
      assert.ok(text.includes('"status":"completed"'),text);
      assert.equal(f.calls.length,1);
      assert.equal(f.calls[0].maxTokens,controls.max_output_tokens??8192);
      assert.equal(f.calls[0].temperature,controls.temperature);
    } finally {await f.ctx.fiber.dispose();}
  }
});
