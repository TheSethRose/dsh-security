import test from 'node:test';import assert from 'node:assert/strict';import os from 'node:os';import path from 'node:path';import {mkdtemp,mkdir,lstat,writeFile,readFile,symlink,chmod} from 'node:fs/promises';
import * as core from '../core.mjs';
import {checkRequest,dockerArgs,privateState,ownedScan,localRequestAllowed} from '../core.mjs';
const frame=(body={model:'deepseek-v4-pro',input:'test'})=>({method:'POST',path:'/responses',body:JSON.stringify(body)});
test('any exact bound model and only POST Responses endpoint can leave isolation',()=>{
 assert.equal(checkRequest(frame(),'deepseek-v4-pro').store,false);
 for(const model of ['gpt-5.6-sol','deepseek-flash','deepseek/deepseek-v4-pro'])assert.throws(()=>checkRequest(frame({model}),'deepseek-v4-pro'),/fallback/);
 for(const endpoint of ['https://api.openai.com/responses','//api.openai.com/responses','/v1/chat/completions','/responses/compact','/responses?x=1','/../responses'])assert.throws(()=>checkRequest({...frame(),path:endpoint},'deepseek-v4-pro'));
 assert.throws(()=>checkRequest({...frame(),method:'GET'},'deepseek-v4-pro'));
 for(const type of ['mcp','web_search','web_search_preview_2025_03_11','computer_use_preview','computer','shell','code_interpreter','image_generation','file_search','unknown_future_hosted_tool'])assert.throws(()=>checkRequest(frame({model:'deepseek-v4-pro',tools:[{type}]}),'deepseek-v4-pro'));
 assert.throws(()=>checkRequest(frame({model:'deepseek-v4-pro',background:true}),'deepseek-v4-pro'));
 assert.throws(()=>checkRequest(frame({model:'deepseek-v4-pro',store:true}),'deepseek-v4-pro'));
 assert.throws(()=>checkRequest(frame({model:'deepseek-v4-pro',tools:[{type:'namespace',tools:[{type:'web_search'}]}]}),'deepseek-v4-pro'));
 assert.equal(checkRequest(frame({model:'deepseek-v4-pro',tools:[{type:'function'},{type:'custom'},{type:'namespace',tools:[{type:'function'}]}]}),'deepseek-v4-pro').store,false);
});
test('Docker has immutable image, no network, read-only root/source and no secrets',()=>{
 const args=dockerArgs({image:'sha256:'+'a'.repeat(64),repo:'/repo-source',state:'/private-state',name:'unit-test'});
 for(const value of ['none','--read-only','--cap-drop','no-new-privileges:true','type=bind,src=/repo-source,dst=/repo,readonly,bind-propagation=rprivate,bind-recursive=readonly'])assert.ok(args.includes(value));
 assert.ok(!args.includes('--env'));assert.ok(!args.includes('/var/run/docker.sock'));
 assert.throws(()=>dockerArgs({image:'tag',repo:'/r',state:'/s',name:'t'}));
 assert.throws(()=>dockerArgs({image:'sha256:'+'a'.repeat(64),repo:'/r,readonly=false',state:'/s',name:'t'}));
});
test('cross-workspace scan IDs are rejected',()=>{
 const table=new Map([['id',{id:'id',workspaceId:'a'}]]);assert.equal(ownedScan(table,'a','id').id,'id');assert.throws(()=>ownedScan(table,'b','id'));assert.throws(()=>ownedScan(table,'a','absent'));
});
test('private state rejects source and all enclosing Git worktrees',async()=>{
 const base=await mkdtemp(path.join(os.tmpdir(),'dsh-security-core-')),repo=path.join(base,'repo');await mkdir(repo,{mode:0o700});
 await assert.rejects(privateState(path.join(repo,'state'),repo),/outside/);
 await mkdir(path.join(base,'.git'));await assert.rejects(privateState(path.join(base,'state'),repo),/Git worktree/);
});
test('HTTP requires custom header, same origin and loopback address',()=>{
 const request={method:'POST',headers:{host:'127.0.0.1:19387',origin:'http://127.0.0.1:19387','x-dsh-security':'1'},socket:{remoteAddress:'127.0.0.1'}};
 assert.equal(localRequestAllowed(request),true);for(const origin of ['https://evil.test','null'])assert.equal(localRequestAllowed({...request,headers:{...request.headers,origin}}),false);
 assert.equal(localRequestAllowed({...request,socket:{remoteAddress:'10.0.0.1'}}),false);assert.equal(localRequestAllowed({...request,headers:{host:request.headers.host}}),false);
});

test('SDK runtime directories are host-created private and owned without modifying existing state',async()=>{
 const state=await mkdtemp(path.join(os.tmpdir(),'dsh-security-runtime-'));await core.prepareRuntimeState(state,'scan');const home=path.join(state,'codex-home'),before=await lstat(home);for(const name of ['codex-home','result']){const st=await lstat(path.join(state,name));assert.equal(st.uid,process.geteuid());assert.equal(st.mode&0o777,0o700);assert.equal(st.isDirectory(),true);}await writeFile(path.join(home,'fixture'),'private fixture');await core.prepareRuntimeState(state,'validate');await core.prepareRuntimeState(state,'scan');assert.equal((await lstat(home)).ino,before.ino);assert.equal(await readFile(path.join(home,'fixture'),'utf8'),'private fixture');assert.equal((await lstat(path.join(state,'validation'))).mode&0o777,0o700);
});
test('runtime preparation rejects symlinks, files, foreign ownership and permissive modes without repairs',async()=>{
 const target=await mkdtemp(path.join(os.tmpdir(),'dsh-security-runtime-target-'));
 for(const type of ['symlink','file','permissions']){const state=await mkdtemp(path.join(os.tmpdir(),'dsh-security-runtime-reject-')),home=path.join(state,'codex-home');if(type==='symlink')await symlink(target,home);else if(type==='file')await writeFile(home,'unmodified');else{await mkdir(home,{mode:0o700});await chmod(home,0o755);}const before=await lstat(home);await assert.rejects(core.prepareRuntimeState(state,'scan'),/must be private and owned/);const after=await lstat(home);assert.equal(after.mode,before.mode);assert.equal(after.ino,before.ino);}
 await assert.rejects(core.prepareRuntimeState('/','scan'),/must be private and owned/);await assert.rejects(core.prepareRuntimeState(target,'export'),/Invalid runtime-state operation/);const parent=await mkdtemp(path.join(os.tmpdir(),'dsh-security-runtime-parent-')),alias=path.join(parent,'alias');await symlink(target,alias);await assert.rejects(core.prepareRuntimeState(alias,'scan'),/must be private and owned/);
});
test('core exposes no provider catalog, credentials, or endpoint constants',()=>{for(const key of ['MODELS','CREDENTIAL','ENDPOINT'])assert.equal(Object.hasOwn(core,key),false);});
test('non-DeepSeek model identifiers are accepted only when exactly bound',()=>{for(const model of ['gpt-5.6-sol','claude-custom','provider/model']){assert.equal(checkRequest(frame({model}),model).model,model);assert.throws(()=>checkRequest(frame({model:model+'-other'}),model));}});
