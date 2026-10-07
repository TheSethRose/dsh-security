import { randomUUID } from 'node:crypto';

const LIMIT = 64 * 1024 * 1024;
const MAX_REQUESTS = 256;
const encoder = new TextEncoder();
const id = prefix => `${prefix}_${randomUUID().replaceAll('-', '')}`;
function bytes(value) {
  const pending = [value], seen = new WeakSet();
  while (pending.length) {
    const part = pending.pop();
    if (['function', 'symbol', 'bigint'].includes(typeof part)) throw new ProtocolError('Non-JSON state is unsupported.');
    if (!part || typeof part !== 'object' || seen.has(part)) continue;
    seen.add(part);
    if ((!Array.isArray(part) && ![Object.prototype, null].includes(Object.getPrototypeOf(part))) || Object.getOwnPropertySymbols(part).length) throw new ProtocolError('Non-JSON state is unsupported.');
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(part))) {
      if (descriptor.get || descriptor.set || (!descriptor.enumerable && !(Array.isArray(part) && key === 'length'))) throw new ProtocolError('Non-JSON state is unsupported.');
      pending.push(descriptor.value);
    }
  }
  return encoder.encode(JSON.stringify(value)).byteLength;
}
const fail = message => { throw new ProtocolError(message); };
class ProtocolError extends Error {}
// Only fixed Harness taxonomy is public. Never copy provider messages, headers,
// request/response bodies, stacks, URLs or arbitrary error codes into reports.
const PUBLIC_FAILURE_CODES = new Set(['AUTH', 'RATE_LIMIT', 'QUOTA', 'ACCOUNT_QUOTA', 'CONTEXT_WINDOW_EXCEEDED', 'EMPTY_RESPONSE', 'INVALID_CREDENTIAL', 'MISSING_CREDENTIAL', 'NO_ADAPTER', 'INVALID_CONFIG', 'INVALID_PREPARED_CALL', 'UNSUPPORTED_REASONING_EFFORT', 'PI_AI_ERROR', 'NETWORK', 'TIMEOUT', 'TRANSPORT', 'SERVER', 'INVALID_REQUEST', 'QUOTA_EXCEEDED']);
function adapterMessage(error, fallback) {
  if (error instanceof ProtocolError) return `Harness protocol translation failed: ${error.message}`;
  try {
    const nested = Object.getOwnPropertyDescriptor(error, 'failure')?.value;
    const code = Object.getOwnPropertyDescriptor(nested ?? error, 'code')?.value;
    if (PUBLIC_FAILURE_CODES.has(code)) return `${fallback.slice(0, -1)} (${code}).`;
  } catch {} // Unknown objects and accessors are not diagnostic inputs.
  return fallback;
}
const string = value => typeof value === 'string' ? value : fail('Expected text.');
const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : fail('Expected object.');
const abortError = () => new DOMException('Request aborted.', 'AbortError');
function interrupt(promise, signal) {
  if (signal.aborted) return Promise.reject(abortError());
  return new Promise((resolve, reject) => {
    const aborted = () => reject(abortError());
    signal.addEventListener('abort', aborted, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
  });
}
function json(value, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
}
function signature(item) {
  // Ignore transport status, but never accept modified cached assistant content.
  const { status, ...rest } = item;
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  return JSON.stringify(canonical(rest));
}

/** Local Responses-to-Harness translation. Never executes tools or accesses credentials/network. */
export const DIAGNOSTIC_CODES = Object.freeze(['NONE', 'UNKNOWN', 'PROTOCOL_ERROR', ...PUBLIC_FAILURE_CODES]);
const count = value => Number.isSafeInteger(value) && value >= 0 ? Math.min(value, Number.MAX_SAFE_INTEGER) : 0;
// Provider text is inspected transiently, never retained. Every emitted string
// below is a fixed enum: even JSON error bodies may echo source or credentials.
export const PROVIDER_CODES = Object.freeze(['invalid_request_error','invalid_value','unsupported_parameter','missing_required_parameter','invalid_json_schema','invalid_function_parameters','model_not_found','context_length_exceeded','token_limit_exceeded','insufficient_quota','rate_limit_exceeded','invalid_api_key','permission_denied','not_found_error','authentication_error','server_error','bad_request','BadRequest','InvalidParameter']);
export const REJECTED_PARAMETERS = Object.freeze(['tools','messages','model','max_tokens','max_completion_tokens','max_output_tokens','temperature','top_p','stream','reasoning_effort','reasoning','response_format']);
export const REJECTION_HINTS = Object.freeze(['tool_schema_invalid','schema_invalid','schema_additional_properties','schema_required','unsupported_parameter','invalid_parameter_value','missing_parameter','output_token_limit','context_limit','request_body_too_large','model_unavailable','authentication','rate_limit','quota','unclassified']);
const MESSAGE_LIMIT = 32768;
function own(value, key) { try { return Object.getOwnPropertyDescriptor(value, key)?.value; } catch {} }
function rejectionDetails(failure) {
  const raw = own(failure, 'message');
  const details = { messageAvailable: typeof raw === 'string', rejectionHints: [] };
  if (typeof raw !== 'string') { details.rejectionHints.push('unclassified'); return details; }
  details.providerMessageChars = raw.length;
  details.providerMessageTruncated = raw.length > MESSAGE_LIMIT;
  const text = raw.slice(0, MESSAGE_LIMIT).trim();
  // This is quoted SDK-message evidence, NOT a trusted transport status.
  const prefix = /^(?:HTTP(?:\/\d(?:\.\d)?)?\s+)?([45]\d{2})(?=\s|:|$)\s*:?[ \t]*/.exec(text);
  if (prefix) details.reportedHttpStatus = Number(prefix[1]);
  let payload;
  const body = prefix ? text.slice(prefix[0].length) : text;
  if (!details.providerMessageTruncated && body.startsWith('{')) {
    try { const parsed = JSON.parse(body), error = own(parsed, 'error'); payload = error !== null && typeof error === 'object' ? error : parsed; } catch {}
  }
  const structured = payload ?? own(failure, 'error');
  for (const [key, target] of [['code','providerErrorCode'],['type','providerErrorType']]) {
    const value = own(structured, key);
    if (PROVIDER_CODES.includes(value)) details[target] = value;
  }
  const candidateParam = own(structured, 'param');
  const param = typeof candidateParam === 'string' && candidateParam.length <= 1024 ? candidateParam : undefined;
  const parameter = typeof param === 'string' ? /^([a-z_]+)(?:$|[.\[])/.exec(param)?.[1] : undefined;
  if (REJECTED_PARAMETERS.includes(parameter)) details.rejectedParameter = parameter;
  const toolIndex = typeof param === 'string' ? /^tools\[(\d{1,6})\](?:$|\.)/.exec(param) : undefined;
  if (toolIndex) details.rejectedToolIndex = Number(toolIndex[1]);
  const providerMessage = own(structured, 'message');
  // Never match source/body fields elsewhere in parsed JSON.
  const inspectable = typeof providerMessage === 'string' ? providerMessage : payload || body.startsWith('{') || body.startsWith('[') ? '' : text;
  details.inspectedMessageChars = inspectable.length;
  details.providerMessageTruncated ||= inspectable.length > MESSAGE_LIMIT;
  const message = inspectable.slice(0, MESSAGE_LIMIT);
  const hint = (name, matches) => { if (matches) details.rejectionHints.push(name); };
  const code = details.providerErrorCode ?? details.providerErrorType;
  const invalidSchema = code === 'invalid_json_schema' || /(?:invalid|unsupported)\s+(?:json\s+)?schema/i.test(message);
  const toolSchema = code === 'invalid_function_parameters' || /schema\s+(?:for|of)\s+(?:function|tool)/i.test(message) || details.rejectedParameter === 'tools' && invalidSchema;
  hint('tool_schema_invalid', toolSchema);
  hint('schema_invalid', invalidSchema && !toolSchema);
  hint('schema_additional_properties', /additionalProperties.{0,120}(?:required|false|missing|not allowed)|(?:required|missing).{0,120}additionalProperties/i.test(message));
  hint('schema_required', /(?:['"]required['"]|required\s+(?:array|list|field)).{0,160}(?:missing|include|supplied|required|extra|must)|(?:missing|extra).{0,80}(?:required\s+(?:key|field)|['"]required['"])/i.test(message));
  hint('unsupported_parameter', code === 'unsupported_parameter' || /(?:unsupported|unrecognized|unknown)\s+(?:parameter|argument)|(?:parameter|argument).{0,80}(?:not supported|unsupported)/i.test(message));
  hint('invalid_parameter_value', code === 'invalid_value' || /invalid\s+(?:value|parameter)|(?:must be|must have).{0,60}(?:between|at most|less than|greater than)/i.test(message));
  hint('missing_parameter', code === 'missing_required_parameter' || /missing\s+(?:required\s+)?(?:parameter|argument)/i.test(message));
  hint('output_token_limit', /(?:max[_ ](?:completion[_ ]|output[_ ])?tokens|output tokens).{0,100}(?:exceed|too (?:large|high)|at most|must be|maximum|range|limit)/i.test(message));
  hint('context_limit', code === 'context_length_exceeded' || /(?:context (?:length|window)|input tokens).{0,100}(?:exceed|maximum|limit|too (?:large|long))/i.test(message));
  hint('request_body_too_large', details.reportedHttpStatus === 413 || /(?:request|body|payload).{0,40}too large/i.test(message));
  hint('model_unavailable', code === 'model_not_found' || /model.{0,100}(?:not found|does not exist|not supported|unavailable|do not have access)/i.test(message));
  hint('authentication', ['invalid_api_key','authentication_error','permission_denied'].includes(code) || /invalid api key|authentication failed|unauthorized/i.test(message));
  hint('rate_limit', code === 'rate_limit_exceeded' || /rate limit/i.test(message));
  hint('quota', code === 'insufficient_quota' || /insufficient (?:quota|balance|credits)|quota.{0,30}(?:exhausted|exceeded)/i.test(message));
  if (!details.rejectionHints.length) details.rejectionHints.push('unclassified');
  return details;
}
function safeFailure(error) {
  if (error instanceof ProtocolError) return { code: 'PROTOCOL_ERROR', reason: 'protocol_rejection' };
  try {
    const failure = Object.getOwnPropertyDescriptor(error, 'failure')?.value ?? error;
    const code = Object.getOwnPropertyDescriptor(failure, 'code')?.value;
    const status = Object.getOwnPropertyDescriptor(failure, 'status')?.value;
    const upstreamStatus = Number.isInteger(status) && status >= 100 && status <= 599 ? status : undefined;
    return { code: PUBLIC_FAILURE_CODES.has(code) ? code : 'UNKNOWN',
      reason: upstreamStatus === 413 ? 'size_rejection' : upstreamStatus === 400 ? 'request_rejected' : code === 'INVALID_REQUEST' ? 'ambiguous_request_rejection' : 'adapter_failure',
      ...(upstreamStatus === undefined ? {} : { upstreamStatus }), ...rejectionDetails(failure) };
  } catch { return { code: 'UNKNOWN', reason: 'adapter_failure' }; }
}
export function createHarnessGateway({ llm, selection, sessionId = randomUUID(), onDiagnostic = () => {}, onPrivateError }) {
  if (!llm || typeof llm.prepareCall !== 'function') throw new TypeError('llm.prepareCall is required.');
  if (typeof sessionId !== 'string' || !/^[A-Za-z0-9._:-]{1,256}$/.test(sessionId)) throw new TypeError('A bounded session routing ID is required.');
  const route = { provider: string(selection?.provider), model: string(selection?.model) };
  if (selection.reasoningEffort !== undefined) route.reasoningEffort = string(selection.reasoningEffort);
  const gatewayTag = randomUUID().replaceAll('-', '');
  const localId = prefix => id(`${prefix}_dsh_${gatewayTag}`);
  const cache = new Map();
  const lookup = new Map();
  let cacheBytes = 0;
  let nextAlias = 0;
  const retainedTools = () => {
    const tools = new Map();
    for (const entry of cache.values()) for (const tool of entry.tools) tools.set(tool.key, tool);
    return tools;
  };
  function remember(entry) {
    const size = bytes(entry);
    if (size > LIMIT) fail('Assistant replay state exceeds the local cache limit.');
    while (cache.size >= MAX_REQUESTS || cacheBytes + size > LIMIT) {
      const oldest = cache.values().next().value;
      cache.delete(oldest.responseId);
      cacheBytes -= oldest.size;
      for (const key of oldest.keys) if (lookup.get(key) === oldest) lookup.delete(key);
    }
    entry.size = size;
    cache.set(entry.responseId, entry);
    cacheBytes += size;
    for (const key of entry.keys) lookup.set(key, entry);
  }
  function translate(body) {
    object(body);
    if (body.model !== route.model) fail('Model does not match the bound selection.');
    if (body.provider !== undefined && body.provider !== route.provider) fail('Provider does not match the bound selection.');
    // Codex's planning hint is not a Harness ReasoningEffortId. The selected
    // Harness effort (or adapter default) alone controls the prepared route.
    if (body.reasoning?.effort !== undefined && typeof body.reasoning.effort !== 'string') fail('Invalid native reasoning hint.');
    if (body.previous_response_id) fail('Use explicit input history; previous_response_id is unsupported.');
    if (body.audio !== undefined || (body.modalities !== undefined && (!Array.isArray(body.modalities) || body.modalities.some(mode => mode !== 'text')))) fail('Unsupported output modality.');
    if (body.tool_choice !== undefined && body.tool_choice !== 'auto') fail('Only automatic tool choice is supported.');
    const known = retainedTools();
    const current = [];
    const keyOf = (type, namespace, name) => JSON.stringify([type, namespace ?? null, name]);
    function descriptor(raw, namespace) {
      object(raw);
      const name = string(raw.name);
      if (!['function', 'custom'].includes(raw.type)) fail('Unsupported tool type.');
      if (raw.namespace !== undefined) namespace = string(raw.namespace);
      const key = keyOf(raw.type, namespace, name);
      const existing = known.get(key);
      const alias = existing?.alias ?? `dsh_tool_${nextAlias++}`;
      const parameters = raw.type === 'custom'
        ? { type: 'object', properties: { input: { type: 'string' } }, required: ['input'], additionalProperties: false }
        : object(raw.parameters ?? { type: 'object', properties: {} });
      const tool = { key, alias, type: raw.type, name, ...(namespace === undefined ? {} : { namespace }), description: raw.description ?? '', parameters };
      known.set(key, tool);
      return tool;
    }
    function catalog(list, parent) {
      if (!Array.isArray(list)) fail('Expected tool catalog.');
      for (const raw of list) {
        if (raw.type === 'namespace') {
          const ns = parent ? `${parent}.${string(raw.name)}` : string(raw.name);
          catalog(raw.tools, ns);
        } else {
          const tool = descriptor(raw, parent);
          if (current.some(t => t.key === tool.key)) fail('Duplicate tool definition.');
          current.push(tool);
        }
      }
    }
    catalog(body.tools ?? []);
    const input = typeof body.input === 'string' ? [{ role: 'user', content: body.input }] : body.input ?? [];
    if (!Array.isArray(input)) fail('Expected input array or text.');
    const requestBytes = bytes(body);
    if (requestBytes > LIMIT) fail('Request exceeds the local byte limit.');
    const messages = [];
    const historyTools = new Map();
    function message(role, content, extra = {}) {
      const source = role === 'assistant' ? { kind: 'model', provider: route.provider, model: route.model } : role === 'tool' ? { kind: 'tool', callId: extra.toolCallId } : role === 'user' ? { kind: 'user' } : { kind: 'system-prompt' };
      messages.push({ id: id('msg'), role, source, content, ...extra });
    }
    for (let i = 0; i < input.length; i++) {
      const item = object(input[i]);
      const isToolOutput = item.type === 'function_call_output' || item.type === 'custom_tool_call_output';
      const saved = isToolOutput ? undefined : lookup.get(item.id) ?? lookup.get(item.call_id);
      if (saved) {
        // Replay is opaque: only an intact, consecutive locally emitted group is safe.
        if (saved.output.some((out, j) => !input[i + j] || signature(input[i + j]) !== signature(out))) fail('Cached assistant replay group is incomplete or modified.');
        for (const tool of saved.tools) historyTools.set(tool.alias, tool);
        messages.push(structuredClone(saved.message));
        i += saved.output.length - 1;
        continue;
      }
      if (!isToolOutput && [item.id, item.call_id].some(key => typeof key === 'string' && /^(msg|rs|fc|ctc|call)_dsh_/.test(key))) fail('Local assistant replay state is no longer available.');
      if (item.encrypted_content !== undefined) fail('Encrypted reasoning has no attributable local replay state.');
      if (item.type === 'function_call' || item.type === 'custom_tool_call') {
        const type = item.type === 'function_call' ? 'function' : 'custom';
        const tool = known.get(keyOf(type, item.namespace, item.name));
        if (!tool) fail('Historical tool call has no known schema.');
        historyTools.set(tool.alias, tool);
        message('assistant', [{ type: 'tool-call', id: string(item.call_id), name: tool.alias, arguments: type === 'custom' ? JSON.stringify({ input: string(item.input) }) : string(item.arguments) }]);
      } else if (item.type === 'function_call_output' || item.type === 'custom_tool_call_output') {
        const nativeCallId = string(item.call_id);
        const owner = lookup.get(nativeCallId);
        if (!owner && /^call_dsh_/.test(nativeCallId)) fail('Local tool call replay state is no longer available.');
        const callIndex = owner?.output.findIndex(out => out.call_id === nativeCallId);
        const callId = callIndex !== undefined && callIndex >= 0 ? owner.message.content[callIndex].id : nativeCallId;
        message('tool', [{ type: 'text', text: string(item.output) }], { toolCallId: callId });
      } else if (item.type === 'reasoning') {
        if (!Array.isArray(item.summary)) fail('Unsupported reasoning item.');
        message('assistant', item.summary.map(part => {
          if (part.type !== 'summary_text') fail('Unsupported reasoning summary.');
          return { type: 'reasoning', text: string(part.text) };
        }));
      } else if (item.type === undefined || item.type === 'message') {
        if (!['user', 'developer', 'system', 'assistant'].includes(item.role)) fail('Unsupported message role.');
        const content = typeof item.content === 'string' ? [{ type: 'text', text: item.content }] : item.content;
        if (!Array.isArray(content)) fail('Unsupported message content.');
        message(item.role, content.map(part => {
          if (!['text', 'input_text', 'output_text'].includes(part.type)) fail('Unsupported input modality.');
          return { type: 'text', text: string(part.text) };
        }));
      } else fail('Unsupported input item.');
    }
    let system = body.instructions === undefined ? '' : string(body.instructions);
    if (body.text?.format) {
      const format = body.text.format;
      if (format.type === 'json_schema') {
        const schema = object(format.schema);
        system += `\nReturn only JSON matching this exact JSON Schema (no markdown or commentary):\n${JSON.stringify(schema)}`;
      } else if (format.type !== 'text') fail('Unsupported output format.');
    }
    if (body.max_output_tokens !== undefined && (!Number.isSafeInteger(body.max_output_tokens) || body.max_output_tokens <= 0)) fail('Invalid output token limit.');
    if (body.temperature !== undefined && (!Number.isFinite(body.temperature) || body.temperature < 0)) fail('Invalid temperature.');
    const schemas = tools => tools.map(t => ({ name: t.alias, description: string(t.description), parameters: t.parameters }));
    return { requestBytes, messages, system, tools: schemas(current), toolHistory: { tools: schemas([...historyTools.values()]), updates: [] }, descriptors: [...new Map([...historyTools.values(), ...current].map(t => [t.alias, t])).values()] };
  }
  return async function gateway(body, signal) {
    const controller = new AbortController();
    const externalAbort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    signal?.addEventListener('abort', externalAbort, { once: true });
    const clean = () => signal?.removeEventListener('abort', externalAbort);
    let translated, prepared, stage = 'translate', diagnosticSent = false, chunkCount = 0, blockCount = 0, replyBytes = 0;
    const requestId = randomUUID(), started = performance.now();
    const metadata = { diagnosticVersion: 2 };
    // Only locally authored keys, enums, booleans and validated numbers cross
    // this boundary. Provider messages/request IDs and content never do.
    function diagnose(outcome, error) {
      if (diagnosticSent) return; diagnosticSent = true;
      const failure = outcome === 'completed' ? { code: 'NONE', reason: 'complete' } : outcome === 'cancelled' ? { code: 'NONE', reason: 'abort' } : safeFailure(error);
      // Separate explicit private capture channel: never merge raw text into diagnostics,
      // engine responses, request payloads, logs or durable scan records.
      if (outcome === 'failed' && !(error instanceof ProtocolError) && typeof onPrivateError === 'function') {
        try {
          const original = own(error, 'failure') ?? error, message = own(original, 'message'), nested = own(own(original, 'error'), 'message');
          const bounded = value => {if(typeof value !== 'string')return;const text=new TextDecoder('utf-8',{ignoreBOM:true}).decode(Buffer.from(value.slice(0,65536)).subarray(0,65536),{stream:true});return {text,chars:value.length,truncated:text.length<value.length};};
          const snapshot = {version:1,requestId,stage,at:new Date().toISOString(),message:bounded(message),nestedMessage:bounded(nested)};
          Promise.resolve(onPrivateError(snapshot)).catch(() => {});
        } catch {}
      }
      try { onDiagnostic({ kind: 'gateway', at: new Date().toISOString(), requestId, stage, outcome, ...failure,
        elapsedMs: Math.min(86400000, Math.max(0, Math.round(performance.now() - started))),
        chunkCount: count(chunkCount), blockCount: count(blockCount), replyBytes: count(replyBytes), ...metadata }); } catch {}
    }
    try {
      translated = translate(body);
      Object.assign(metadata, { requestBytes: translated.requestBytes, inputMessages: translated.messages.length,
        inputTextChars: translated.messages.reduce((n, m) => n + m.content.reduce((sum, p) => sum + (typeof p.text === 'string' ? p.text.length : 0), 0), 0),
        systemChars: translated.system.length, toolCount: translated.tools.length, historyToolCount: translated.toolHistory.tools.length, toolSchemaBytes: bytes(translated.tools),
        stream: body.stream === true, schemaFormat: body.text?.format?.type === 'json_schema',
        requestedMaxTokens: body.max_output_tokens !== undefined, requestedTemperature: body.temperature !== undefined,
        hasReasoningEffort: route.reasoningEffort !== undefined });
      stage = 'prepare';
      if (controller.signal.aborted) throw abortError();
      const config = { ...route, ...(body.max_output_tokens === undefined ? {} : { maxTokens: body.max_output_tokens }), ...(body.temperature === undefined ? {} : { temperature: body.temperature }) };
      prepared = await interrupt(llm.prepareCall(config, controller.signal), controller.signal);
      const maxTokens = Object.getOwnPropertyDescriptor(prepared.config, 'maxTokens')?.value;
      const temperature = Object.getOwnPropertyDescriptor(prepared.config, 'temperature')?.value;
      if (Number.isSafeInteger(maxTokens) && maxTokens > 0) metadata.maxTokens = maxTokens;
      if (Number.isFinite(temperature) && temperature >= 0 && temperature <= 100) metadata.temperature = temperature;
      if (Number.isSafeInteger(selection.contextWindow) && selection.contextWindow > 0) metadata.contextWindow = selection.contextWindow;
      if (prepared.config.provider !== route.provider || prepared.config.model !== route.model || (route.reasoningEffort !== undefined && prepared.config.reasoningEffort !== route.reasoningEffort)) fail('Prepared route does not match selection.');
    } catch (error) {
      diagnose(controller.signal.aborted ? 'cancelled' : 'failed', error);
      clean();
      return json({ error: { type: error instanceof ProtocolError ? 'invalid_request_error' : 'server_error', code: controller.signal.aborted ? 'request_aborted' : error instanceof ProtocolError ? 'unsupported_request' : 'adapter_error', message: error instanceof ProtocolError ? error.message : controller.signal.aborted ? 'Request aborted.' : adapterMessage(error, 'Harness adapter preparation failed.') } }, error instanceof ProtocolError ? 400 : controller.signal.aborted ? 499 : 502);
    }
    const responseId = id('resp');
    const response = { id: responseId, object: 'response', created_at: Math.floor(Date.now() / 1000), model: route.model, status: 'in_progress', output: [], error: null, incomplete_details: null, usage: null };
    // Native adapters own session-affinity headers (including x-opencode-session).
    // Bind once per scan/gateway, never to request IDs or container-supplied metadata.
    const options = { ...prepared.config, provider: route.provider, model: route.model, sessionId, messages: translated.messages, system: translated.system, tools: translated.tools, toolHistory: translated.toolHistory, signal: controller.signal };
    // Prepared config is immutable at dispatch; request controls were bound above.
    async function* events() {
      let sequence = 0;
      let accumulated = 0;
      const emit = (type, data) => ({ type, sequence_number: sequence++, ...data });
      const blocks = new Map();
      let finish, terminalFailure;
      let replayState;
      let iterator;
      try {
        yield emit('response.created', { response: structuredClone(response) });
        stage = 'dispatch';
        iterator = prepared.stream(options)[Symbol.asyncIterator]();
        while (true) {
          stage = 'iterate';
          const next = await interrupt(iterator.next(), controller.signal);
          if (next.done) break;
          const chunk = next.value;
          chunkCount++;
          accumulated += bytes(chunk); replyBytes = accumulated;
          stage = 'assemble';
          if (accumulated > LIMIT) fail('Reply exceeds the local byte limit.');
          if (chunk.type === 'usage') {
            const u = chunk.usage;
            response.usage = { input_tokens: u.inputTokens, output_tokens: u.outputTokens, total_tokens: u.totalTokens ?? u.inputTokens + u.outputTokens, input_tokens_details: { cached_tokens: u.cacheReadTokens ?? 0 }, output_tokens_details: { reasoning_tokens: u.reasoningTokens ?? 0 } };
          } else if (chunk.type === 'finish') {
            finish = chunk.reason.kind;
            if (finish === 'error') { terminalFailure = chunk.reason.failure; stage = 'iterate'; }
            replayState = chunk.replayState;
            break;
          } else if (chunk.type === 'block-start') {
            if (blocks.has(chunk.index) || !['text', 'reasoning', 'tool-call'].includes(chunk.blockType)) fail('Unsupported adapter block.');
            blocks.set(chunk.index, { type: chunk.blockType, text: '', args: '', ended: false }); blockCount = blocks.size;
          } else {
            const block = blocks.get(chunk.index);
            if (!block || block.ended) fail('Invalid adapter block sequence.');
            if (chunk.type === 'text-delta' || chunk.type === 'reasoning-delta') {
              if (block.type !== (chunk.type === 'text-delta' ? 'text' : 'reasoning')) fail('Adapter block type mismatch.');
              block.text += string(chunk.text);
            } else if (chunk.type === 'tool-call-delta') {
              if (block.type !== 'tool-call') fail('Adapter block type mismatch.');
              block.name = chunk.name ?? block.name;
              block.args += string(chunk.argumentsDelta);
            } else if (chunk.type !== 'block-end') fail('Unsupported adapter chunk.');
            if (chunk.type === 'block-end') {
              if (chunk.block.type !== block.type) fail('Adapter block type mismatch.');
              block.ended = true;
              block.final = chunk.block;
            }
            // Text is streamed incrementally. Tool calls wait for a complete block so
            // custom JSON wrappers can be decoded without leaking their syntax.
            if (block.type === 'text' && !block.item) {
              block.outputIndex = response.output.length;
              block.item = { id: localId('msg'), type: 'message', role: 'assistant', status: 'in_progress', content: [{ type: 'output_text', text: '', annotations: [] }] };
              response.output.push(block.item);
              yield emit('response.output_item.added', { output_index: block.outputIndex, item: structuredClone(block.item) });
              yield emit('response.content_part.added', { item_id: block.item.id, output_index: block.outputIndex, content_index: 0, part: structuredClone(block.item.content[0]) });
            }
            if (block.type === 'text' && chunk.type === 'text-delta') {
              block.item.content[0].text += chunk.text;
              yield emit('response.output_text.delta', { item_id: block.item.id, output_index: block.outputIndex, content_index: 0, delta: chunk.text });
            }
            if (chunk.type !== 'block-end') continue;
            if (block.type === 'text') {
              const finalText = string(chunk.block.text);
              if (!finalText.startsWith(block.text)) fail('Adapter text completion differs from deltas.');
              const suffix = finalText.slice(block.text.length);
              if (suffix) {
                block.item.content[0].text = finalText;
                yield emit('response.output_text.delta', { item_id: block.item.id, output_index: block.outputIndex, content_index: 0, delta: suffix });
              }
              block.item.status = 'completed';
              yield emit('response.output_text.done', { item_id: block.item.id, output_index: block.outputIndex, content_index: 0, text: block.item.content[0].text });
              yield emit('response.content_part.done', { item_id: block.item.id, output_index: block.outputIndex, content_index: 0, part: block.item.content[0] });
            } else {
              block.outputIndex = response.output.length;
              if (block.type === 'reasoning') {
                block.item = { id: localId('rs'), type: 'reasoning', summary: [{ type: 'summary_text', text: string(chunk.block.text) }] };
              } else {
                const tool = translated.descriptors.find(t => t.alias === chunk.block.name);
                if (!tool || !translated.tools.some(t => t.name === tool.alias)) fail('Adapter called an unknown tool.');
                const args = string(chunk.block.arguments);
                let input;
                if (tool.type === 'custom') {
                  let parsed;
                  try { parsed = JSON.parse(args); } catch { fail('Invalid custom tool input.'); }
                  if (!parsed || typeof parsed.input !== 'string' || Object.keys(parsed).length !== 1) fail('Invalid custom tool input.');
                  input = parsed.input;
                }
                block.item = { id: localId(tool.type === 'custom' ? 'ctc' : 'fc'), type: tool.type === 'custom' ? 'custom_tool_call' : 'function_call', call_id: localId('call'), name: tool.name, ...(tool.namespace === undefined ? {} : { namespace: tool.namespace }), status: 'in_progress', ...(tool.type === 'custom' ? { input: '' } : { arguments: '' }) };
                // The opaque adapter replay envelope and block IDs stay intact.
                // Native call IDs are mapped back for subsequent tool results.
                block.final = { ...chunk.block };
                yield emit('response.output_item.added', { output_index: block.outputIndex, item: structuredClone(block.item) });
                const field = tool.type === 'custom' ? 'input' : 'arguments';
                const event = tool.type === 'custom' ? 'custom_tool_call_input' : 'function_call_arguments';
                block.item[field] = tool.type === 'custom' ? input : args;
                yield emit(`response.${event}.delta`, { item_id: block.item.id, output_index: block.outputIndex, delta: block.item[field] });
                yield emit(`response.${event}.done`, { item_id: block.item.id, output_index: block.outputIndex, [field]: block.item[field], name: tool.name });
                block.item.status = 'completed';
              }
              response.output.push(block.item);
              if (block.type === 'reasoning') yield emit('response.output_item.added', { output_index: block.outputIndex, item: structuredClone(block.item) });
            }
            yield emit('response.output_item.done', { output_index: block.outputIndex, item: structuredClone(block.item) });
          }
        }
        if (!finish || !['stop', 'tool-calls', 'max-tokens'].includes(finish)) throw new Error('Adapter did not finish successfully.');
        if ([...blocks.values()].some(b => !b.ended)) fail('Adapter left an incomplete block.');
        response.status = finish === 'max-tokens' ? 'incomplete' : 'completed';
        if (finish === 'max-tokens') response.incomplete_details = { reason: 'max_output_tokens' };
        const content = [...blocks.values()].sort((a, b) => a.outputIndex - b.outputIndex).map(b => b.final);
        const message = { id: id('msg'), role: 'assistant', source: { kind: 'model', provider: route.provider, model: route.model, ...(replayState === undefined ? {} : { replayState }) }, content };
        if (replayState !== undefined && !response.output.length) fail('Opaque replay state has no emitted item identity.');
        if (response.output.length) {
          const entry = { responseId, output: response.output, message, tools: translated.descriptors, keys: response.output.flatMap(item => [item.id, ...(item.call_id ? [item.call_id] : [])]) };
          bytes(entry); // Reject non-JSON opaque state before cloning or retaining it.
          remember(structuredClone(entry));
        }
        stage = 'complete'; diagnose('completed');
        yield emit(finish === 'max-tokens' ? 'response.incomplete' : 'response.completed', { response });
      } catch (error) {
        diagnose(controller.signal.aborted || finish === 'aborted' ? 'cancelled' : 'failed', terminalFailure ?? error);
        response.status = 'failed';
        response.error = { code: controller.signal.aborted || finish === 'aborted' ? 'request_aborted' : 'adapter_error', message: controller.signal.aborted || finish === 'aborted' ? 'Request aborted.' : adapterMessage(terminalFailure ?? error, 'Harness adapter generation failed.') };
        yield emit('response.failed', { response });
      } finally {
        diagnose('cancelled');
        controller.abort();
        // Do not await a stuck iterator on cancellation; signal is authoritative.
        try { Promise.resolve(iterator?.return?.()).catch(() => {}); } catch {}
        clean();
      }
    }
    if (!body.stream) {
      let final;
      for await (const event of events()) if (event.response) final = event.response;
      return json(final, final.status === 'failed' ? 502 : 200);
    }
    const iterator = events();
    return new Response(new ReadableStream({
      async pull(stream) {
        try {
          const next = await iterator.next();
          if (next.done) stream.close();
          else stream.enqueue(encoder.encode(`event: ${next.value.type}\ndata: ${JSON.stringify(next.value)}\n\n`));
        } catch { stream.error(new Error('Gateway stream failed.')); controller.abort(); clean(); }
      },
      cancel() { diagnose('cancelled'); controller.abort(); clean(); return iterator.return(); },
    }), { headers: { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' } });
  };
}
