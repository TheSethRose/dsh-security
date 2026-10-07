import test from 'node:test';import assert from 'node:assert/strict';import os from 'node:os';import path from 'node:path';import {mkdtemp,readFile,writeFile} from 'node:fs/promises';import {randomUUID} from 'node:crypto';import {execFile} from 'node:child_process';import {promisify} from 'node:util';import {dockerArgs} from '../core.mjs';
const exec=promisify(execFile),enabled=process.env.DSH_SECURITY_CONTAINER_TESTS==='1';
test('native Bubblewrap sandbox reads source but cannot write or remount it, nor reach external networking',{skip:!enabled,timeout:30000},async()=>{
 const repo=await mkdtemp(path.join(os.tmpdir(),'security-sandbox-')),state=await mkdtemp(path.join(os.tmpdir(),'security-sandbox-state-'));await writeFile(path.join(repo,'example.py'),'readonly-source-sentinel\n');
 const image=JSON.parse(await readFile(new URL('../image.json',import.meta.url),'utf8')).image;
 const args=dockerArgs({image,repo,state,name:'dsh-security-test-'+randomUUID()});args[0]='run';args.splice(1,0,'--rm');args.splice(args.length-1,0,'--entrypoint','/bin/sh');
 const script='set -eu; cat /repo/example.py; if touch /repo/forbidden; then exit 91; fi; if mount -o remount,rw /repo; then exit 92; fi; if touch /opt/forbidden; then exit 93; fi; test -z "${DEEPSEEK_API_KEY:-}"; touch /state/native-output; /usr/local/bin/node -e \'fetch("https://api.deepseek.com/",{signal:AbortSignal.timeout(1500)}).then(()=>process.exit(94)).catch(()=>console.log("NETWORK-BLOCKED"))\'';
 const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";
 const {stdout}=await exec('/usr/local/bin/docker',[...args,'-c',`mkdir -p /scratch/home /scratch/codex; cd /state; exec /opt/security/node_modules/.bin/codex sandbox -c 'sandbox_mode="workspace-write"' -- /bin/sh -c ${quote(script)}`],{timeout:25000});
 assert.match(stdout,/readonly-source-sentinel/);assert.match(stdout,/NETWORK-BLOCKED/);assert.equal(await readFile(path.join(repo,'example.py'),'utf8'),'readonly-source-sentinel\n');assert.equal(await readFile(path.join(state,'native-output'),'utf8'),'');
});
