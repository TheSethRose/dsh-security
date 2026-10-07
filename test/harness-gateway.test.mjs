import test from 'node:test';
import assert from 'node:assert/strict';
import { createHarnessGateway } from '../harness-gateway.mjs';

const selection = { provider: 'configured-oauth', model: 'any-model', reasoningEffort: 'high' };
const textChunks = text => [
  { type: 'block-start', index: 0, blockType: 'text' },
  { type: 'text-delta', index: 0, text },
  { type: 'block-end', index: 0, block: { type: 'text', text } },
  { type: 'usage', usage: { inputTokens: 2, outputTokens: 3, cacheReadTokens: 1, reasoningTokens: 2 } },
  { type: 'finish', reason: { kind: 'stop' } },
];
const callChunks = (name, args, replayState) => [
  { type: 'block-start', index: 0, blockType: 'reasoning' },
  { type: 'reasoning-delta', index: 0, text: 'summary' },
  { type: 'block-end', index: 0, block: { type: 'reasoning', text: 'summary' } },
  { type: 'block-start', index: 1, blockType: 'tool-call' },
  { type: 'tool-call-delta', index: 1, id: 'adapter-call-id', name, argumentsDelta: args },
  { type: 'block-end', index: 1, block: { type: 'tool-call', id: 'adapter-call-id', name, arguments: args } },
  { type: 'finish', reason: { kind: 'tool-calls' }, replayState },
];
function fixture(chunks = textChunks('hello')) {
  const prepares = [], streams = [];
  const llm = {
    async prepareCall(config, signal) {
      prepares.push({ config, signal });
      return { config, stream(options) {
        streams.push(options);
        return (async function* () { yield* typeof chunks === 'function' ? chunks(options, streams.length) : chunks; })();
      } };
    },
  };
  return { gateway: createHarnessGateway({ llm, selection }), prepares, streams };
}
const request = extra => ({ model: selection.model, input: 'audit this', ...extra });
async function parseSSE(response) {
  assert.equal(response.headers.get('content-type'), 'text/event-stream');
  return (await response.text()).trim().split('\n\n').map(frame => {
    const lines = frame.split('\n');
    const value = JSON.parse(lines.find(line => line.startsWith('data: ')).slice(6));
    assert.equal(lines[0], `event: ${value.type}`);
    return value;
  });
}

test('exact selected Harness route, options and native JSON without Host tools', async () => {
  const f = fixture();
  const response = await f.gateway(request({ instructions: 'system', max_output_tokens: 50, temperature: 0.2 }));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.status, 'completed');
  assert.equal(body.output[0].content[0].text, 'hello');
  assert.deepEqual(body.usage, { input_tokens: 2, output_tokens: 3, total_tokens: 5, input_tokens_details: { cached_tokens: 1 }, output_tokens_details: { reasoning_tokens: 2 } });
  assert.deepEqual(f.prepares[0].config, { ...selection, maxTokens: 50, temperature: 0.2 });
  assert.equal(f.streams.length, 1);
  assert.equal(f.streams[0].system, 'system');
  assert.equal(f.streams[0].maxTokens, 50);
  assert.equal(f.streams[0].temperature, 0.2);
  assert.deepEqual(f.streams[0].messages[0].source, { kind: 'user' });
});

test('native planning hint cannot override selected effort or the Harness adapter default', async () => {
  for (const effort of [undefined, 'minimal']) {
    const route = { provider: selection.provider, model: selection.model, ...(effort ? { reasoningEffort: effort } : {}) };
    const prepares = [];
    const gateway = createHarnessGateway({ selection: route, llm: { async prepareCall(config) { prepares.push(config); return { config, stream: async function* () { yield* textChunks('fixture'); } }; } } });
    assert.equal((await gateway(request({ reasoning: { effort: 'high' } }))).status, 200);
    assert.deepEqual(prepares, [route]);
  }
});

test('SSE is typed, parsable, ordered and includes final native output', async () => {
  const f = fixture();
  const events = await parseSSE(await f.gateway(request({ stream: true })));
  assert.deepEqual(events.map(e => e.type), ['response.created', 'response.output_item.added', 'response.content_part.added', 'response.output_text.delta', 'response.output_text.done', 'response.content_part.done', 'response.output_item.done', 'response.completed']);
  assert.deepEqual(events.map(e => e.sequence_number), events.map((_, i) => i));
  assert.equal(events[3].delta, 'hello');
  assert.equal(events.at(-1).response.output[0].id, events[1].item.id);
  assert.notEqual(events[0].response.id, events[1].item.id);
});

for (const type of ['function', 'custom']) {
  test(`${type} namespace aliases, native events, replay and changed catalog history roundtrip`, async () => {
    const replay = { response: { encrypted: 'opaque-provider-state' }, blocks: [{ private: true }] };
    const args = type === 'custom' ? '{"input":"raw shell\ntext"}'.replace('\n', '\\n') : '{"path":"file"}';
    const f = fixture((options, n) => n === 1 ? callChunks(options.tools[0].name, args, replay) : textChunks('done'));
    const parameters = { type: 'object', properties: { path: { type: 'string' } } };
    const tools = [{ type: 'namespace', name: 'outer', tools: [{ type: 'namespace', name: 'inner', tools: [{ type, name: 'a.b', description: 'test', ...(type === 'function' ? { parameters } : {}) }] }] }];
    const events = await parseSSE(await f.gateway(request({ tools, stream: true })));
    const output = events.at(-1).response.output;
    const call = output[1];
    assert.match(f.streams[0].tools[0].name, /^dsh_tool_\d+$/);
    assert.equal(call.type, `${type === 'custom' ? 'custom_tool' : 'function'}_call`);
    assert.equal(call.name, 'a.b');
    assert.equal(call.namespace, 'outer.inner');
    assert.notEqual(call.call_id, 'adapter-call-id');
    assert.equal(type === 'custom' ? call.input : call.arguments, type === 'custom' ? 'raw shell\ntext' : args);
    const eventStem = type === 'custom' ? 'custom_tool_call_input' : 'function_call_arguments';
    assert.ok(events.some(e => e.type === `response.${eventStem}.delta`));
    assert.ok(events.some(e => e.type === `response.${eventStem}.done`));
    const next = await f.gateway(request({ tools: [{ type: 'function', name: 'new-tool', parameters: { type: 'object' } }], input: [...output, { type: type === 'custom' ? 'custom_tool_call_output' : 'function_call_output', call_id: call.call_id, output: 'result' }] }));
    assert.equal(next.status, 200);
    const messages = f.streams[1].messages;
    assert.equal(messages.length, 2);
    assert.deepEqual(messages[0].source.replayState, replay);
    assert.equal(messages[0].content.length, 2);
    assert.equal(messages[0].content[1].id, 'adapter-call-id');
    assert.equal(messages[1].toolCallId, 'adapter-call-id');
    assert.equal(messages[1].source.callId, 'adapter-call-id');
    assert.equal(f.streams[1].toolHistory.tools[0].name, f.streams[0].tools[0].name);
    assert.deepEqual(f.streams[1].toolHistory.tools[0].parameters, type === 'function' ? parameters : { type: 'object', properties: { input: { type: 'string' } }, required: ['input'], additionalProperties: false });
  });
}

test('typed uncached function and custom histories convert to Harness blocks', async () => {
  const f = fixture();
  const tools = [{ type: 'function', name: 'f', parameters: { type: 'object' } }, { type: 'custom', name: 'c' }];
  const input = [
    { role: 'developer', content: [{ type: 'input_text', text: 'rules' }] },
    { role: 'assistant', content: [{ type: 'output_text', text: 'calling' }] },
    { type: 'reasoning', summary: [{ type: 'summary_text', text: 'summary' }] },
    { type: 'function_call', call_id: 'f-id', name: 'f', arguments: '{}' },
    { type: 'function_call_output', call_id: 'f-id', output: 'ok' },
    { type: 'custom_tool_call', call_id: 'c-id', name: 'c', input: 'raw' },
    { type: 'custom_tool_call_output', call_id: 'c-id', output: 'ok' },
  ];
  assert.equal((await f.gateway(request({ tools, input }))).status, 200);
  const m = f.streams[0].messages;
  assert.deepEqual(m[0].source, { kind: 'system-prompt' });
  assert.deepEqual(m[2].content, [{ type: 'reasoning', text: 'summary' }]);
  assert.equal(m[3].content[0].name, f.streams[0].tools[0].name);
  assert.equal(m[5].content[0].arguments, '{"input":"raw"}');
});

test('JSON schema format is an exact system requirement, not a strict adapter option', async () => {
  const f = fixture(textChunks('{"ok":true}'));
  const schema = { type: 'object', properties: { ok: { const: true } }, required: ['ok'], additionalProperties: false };
  await f.gateway(request({ instructions: 'audit', text: { format: { type: 'json_schema', name: 'result', strict: true, schema } } }));
  assert.ok(f.streams[0].system.includes(JSON.stringify(schema)));
  assert.ok(f.streams[0].system.includes('Return only JSON'));
  assert.equal(f.streams[0].response_format, undefined);
});

test('protocol rejection precedes adapter dispatch', async () => {
  for (const extra of [
    { model: 'different' }, { provider: 'different' }, { reasoning: { effort: 42 } },
    { tools: [{ type: 'web_search' }] }, { tools: [{ type: 'namespace', name: 'ns', tools: [{ type: 'computer' }] }] },
    { input: [{ role: 'user', content: [{ type: 'input_image', image_url: 'https://never-fetch.invalid' }] }] },
    { input: [{ type: 'reasoning', encrypted_content: 'secret', summary: [] }] },
    { previous_response_id: 'unknown' }, { tool_choice: 'required' }, { text: { format: { type: 'json_object' } } },
    { modalities: ['audio'] }, { audio: { voice: 'test' } },
  ]) {
    const f = fixture();
    assert.equal((await f.gateway(request(extra))).status, 400);
    assert.equal(f.prepares.length, 0);
  }
});

test('incomplete or edited cached replay is rejected instead of losing provider state', async () => {
  const f = fixture(o => callChunks(o.tools[0].name, '{}', { response: { encrypted: true } }));
  const tools = [{ type: 'function', name: 'f', parameters: {} }];
  const first = await (await f.gateway(request({ tools }))).json();
  assert.equal((await f.gateway(request({ tools, input: [first.output[1]] }))).status, 400);
  const modified = structuredClone(first.output);
  modified[0].summary[0].text = 'changed';
  assert.equal((await f.gateway(request({ tools, input: modified }))).status, 400);
  assert.equal(f.streams.length, 1);
});

test('terminal errors and thrown adapter failures are sanitized with no retry or fallback', async () => {
  for (const kind of ['error', 'aborted']) {
    const f = fixture([{ type: 'finish', reason: { kind, failure: { code: 'SECRET', message: 'credential=secret' } } }]);
    const response = await f.gateway(request());
    assert.equal(response.status, 502);
    const body = await response.json();
    assert.equal(body.status, 'failed');
    assert.ok(!JSON.stringify(body).includes('secret'));
    assert.equal(f.streams.length, 1);
    assert.equal(f.prepares.length, 1);
  }
  const gateway = createHarnessGateway({ selection, llm: { prepareCall() { throw new Error('secret-token'); } } });
  const response = await gateway(request());
  assert.equal(response.status, 502);
  assert.ok(!(await response.text()).includes('secret-token'));
});

test('allowlisted Harness failure codes survive preparation, dispatch and terminal failure without raw diagnostics', async () => {
  for (const code of ['AUTH', 'RATE_LIMIT', 'QUOTA_EXCEEDED', 'CONTEXT_WINDOW_EXCEEDED', 'INVALID_PREPARED_CALL', 'PI_AI_ERROR', 'TIMEOUT', 'TRANSPORT', 'SERVER', 'INVALID_REQUEST', 'secret-token']) {
    const error = Object.assign(new Error('credential=secret-token https://secret.invalid'), { code, headers: { authorization: 'secret-token' } });
    for (const phase of ['prepare', 'dispatch', 'terminal']) {
      let calls = 0;
      const gateway = phase === 'terminal' ? fixture([{ type: 'finish', reason: { kind: 'error', failure: { code, message: error.message } } }]).gateway : createHarnessGateway({ selection, llm: { prepareCall(config) {
        if (phase === 'prepare') throw error;
        return { config, stream() { calls++; throw error; } };
      } } });
      const response = await gateway(request({ stream: phase === 'terminal' }));
      const result = phase === 'terminal' ? (await parseSSE(response)).at(-1).response : await response.json();
      assert.equal(result.status ?? 'failed', 'failed');
      const message = result.error.message;
      assert.ok(!message.includes('secret-token'));
      assert.ok(!message.includes('secret.invalid'));
      assert.equal(message.includes(`(${code})`), code !== 'secret-token');
      assert.ok(calls <= 1);
    }
  }
});

test('adapter error diagnostics never evaluate code or failure accessors', async () => {
  let reads = 0;
  const error = new Error('secret-token');
  for (const key of ['code', 'failure']) Object.defineProperty(error, key, { get() { reads++; throw new Error('secret-token'); } });
  const gateway = createHarnessGateway({ selection, llm: { prepareCall() { throw error; } } });
  const response = await gateway(request());
  assert.equal(response.status, 502);
  assert.ok(!(await response.text()).includes('secret-token'));
  assert.equal(reads, 0);
});

test('authoritative final text may extend deltas without duplicating streamed text', async () => {
  for (const partial of ['', 'hello', 'hello world']) {
    const f = fixture([{ type: 'block-start', index: 0, blockType: 'text' }, { type: 'text-delta', index: 0, text: partial }, { type: 'block-end', index: 0, block: { type: 'text', text: 'hello world' } }, { type: 'finish', reason: { kind: 'stop' } }]);
    const events = await parseSSE(await f.gateway(request({ stream: true })));
    assert.equal(events.filter(e => e.type === 'response.output_text.delta').map(e => e.delta).join(''), 'hello world');
    assert.equal(events.at(-1).response.status, 'completed');
    assert.equal(events.at(-1).response.output[0].content[0].text, 'hello world');
  }
});

test('final text cannot silently rewrite already emitted deltas', async () => {
  const chunks = textChunks('original');
  chunks[2].block.text = 'replacement';
  const events = await parseSSE(await fixture(chunks).gateway(request({ stream: true })));
  assert.equal(events.at(-1).response.status, 'failed');
  assert.equal(events.at(-1).response.error.message, 'Harness protocol translation failed: Adapter text completion differs from deltas.');
});

test('locally authored translation errors identify the failing invariant', async () => {
  const f = fixture([{ type: 'block-start', index: 0, blockType: 'unknown-secret' }]);
  const response = await f.gateway(request());
  const body = await response.json();
  assert.equal(body.error.message, 'Harness protocol translation failed: Unsupported adapter block.');
  assert.ok(!body.error.message.includes('unknown-secret'));
});

test('max-tokens finish reports a native incomplete response', async () => {
  const chunks = textChunks('partial');
  chunks.at(-1).reason.kind = 'max-tokens';
  const events = await parseSSE(await fixture(chunks).gateway(request({ stream: true })));
  assert.equal(events.at(-1).type, 'response.incomplete');
  assert.equal(events.at(-1).response.incomplete_details.reason, 'max_output_tokens');
});

test('abort during preparation interrupts even an uncooperative adapter', async () => {
  const controller = new AbortController();
  let prepareSignal;
  const gateway = createHarnessGateway({ selection, llm: { prepareCall(config, signal) { prepareSignal = signal; return new Promise(() => {}); } } });
  const pending = gateway(request(), controller.signal);
  controller.abort();
  const response = await pending;
  assert.equal(response.status, 499);
  assert.equal(prepareSignal.aborted, true);
});

test('pre-aborted request never invokes prepareCall', async () => {
  const f = fixture();
  const controller = new AbortController();
  controller.abort();
  assert.equal((await f.gateway(request(), controller.signal)).status, 499);
  assert.equal(f.prepares.length, 0);
});

test('abort during iteration produces sanitized terminal SSE and releases iterator', async () => {
  const controller = new AbortController();
  let streamSignal, returned = false;
  let entered;
  const started = new Promise(resolve => { entered = resolve; });
  const gateway = createHarnessGateway({ selection, llm: { async prepareCall(config) {
    return { config, stream(options) {
      streamSignal = options.signal;
      return { [Symbol.asyncIterator]() { return this; }, next() { entered(); return new Promise(() => {}); }, return() { returned = true; return Promise.resolve({ done: true }); } };
    } };
  } } });
  const response = await gateway(request({ stream: true }), controller.signal);
  const pending = parseSSE(response);
  await started;
  controller.abort();
  const events = await pending;
  assert.equal(events.at(-1).type, 'response.failed');
  assert.equal(events.at(-1).response.error.code, 'request_aborted');
  assert.equal(streamSignal.aborted, true);
  assert.equal(returned, true);
});

test('consumer cancellation aborts adapter iteration', async () => {
  const f = fixture();
  const response = await f.gateway(request({ stream: true }));
  const reader = response.body.getReader();
  await reader.read();
  await reader.cancel();
  assert.equal(f.prepares[0].signal.aborted, true);
});

test('bounded request cache explicitly rejects evicted local output instead of dropping replay', async () => {
  const chunks = textChunks('reply');
  chunks.at(-1).replayState = { response: { encrypted: 'state' } };
  const f = fixture(chunks);
  const first = await (await f.gateway(request())).json();
  for (let i = 0; i < 256; i++) assert.equal((await f.gateway(request())).status, 200);
  assert.equal((await f.gateway(request({ input: first.output }))).status, 400);
});

test('unknown blocks, missing finish and non-JSON or unattributable replay fail safely', async () => {
  const nonJson = textChunks('text');
  nonJson.at(-1).replayState = { response: new Map([['state', 'secret']]) };
  for (const chunks of [
    [{ type: 'block-start', index: 0, blockType: 'image' }],
    textChunks('text').slice(0, -1), nonJson,
    [{ type: 'finish', reason: { kind: 'stop' }, replayState: { response: 'opaque' } }],
  ]) {
    const response = await fixture(chunks).gateway(request());
    assert.equal(response.status, 502);
    assert.equal((await response.json()).status, 'failed');
  }
});

test('prepared route mismatch cannot dispatch to a fallback', async () => {
  let streamed = false;
  const gateway = createHarnessGateway({ selection, llm: { async prepareCall() { return { config: { ...selection, provider: 'fallback' }, stream() { streamed = true; } }; } } });
  assert.equal((await gateway(request())).status, 400);
  assert.equal(streamed, false);
});
