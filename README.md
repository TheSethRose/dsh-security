# dsh-security

An experimental DeepSeek Harness Security panel backed by the published Codex Security engine, using **a supported, configured Harness provider/model through the Host `llm` service and existing adapter authentication**. This is not an OpenAI or other provider endorsement and not a guarantee that a repository is secure.

```text
Authenticated Security panel + explicit human consent
  → workspace-owned Host task and durable report
  → network-isolated Codex Security container
  → native Responses protocol, container loopback + framed stdin/stdout
  → harness-gateway.mjs translation to Host llm.prepareCall / prepared.stream
  → selected configured Harness adapter and its existing authentication
```

The engine package is `@openai/codex-security@0.2.0`; its package name does not determine the inference provider. There is no separate plugin API key or direct DeepSeek endpoint forwarding. The bridge binds the exact selected provider/model and does not silently fall back.

## Features

- Manual standard/deep scans of a registered workspace, with explicit source-disclosure/cost consent.
- One active scan or finding validation per workspace; progress, cancellation, deadline, durable history and interrupted-run status.
- Findings, evidence, threat model, coverage and engine report.
- Finding validation using the same engine and an explicitly selected configured model.
- JSON, CSV and SARIF downloads from completed scans, without model inference.
- An agent-facing `security_scan` tool for status/list/get/cancel/export only. Agents cannot authorize paid scan/validation through that tool.
- Report-only source access: no workspace patching, automatic publication, embedding service or upstream findings upload.

## Requirements

- DeepSeek Harness **0.2.0-rc.2**, Node.js 24, pnpm and Git. Docker must be available in the Harness subprocess execution world (`docker` on its PATH, or an absolute `DSH_SECURITY_DOCKER` executable override), with a running daemon.
- A non-root Harness user; Docker containers run with that user's numeric UID/GID to read private source files without relaxing permissions.
- A registered local Git repository. Linked worktrees whose metadata lives outside the mounted workspace may not work; external directories are not automatically mounted.
- A Linux Docker kernel supporting unprivileged user namespaces and recursive read-only bind mounts. Docker Desktop can supply this kernel on macOS. Restricted Linux AppArmor/user-namespace configurations must be fixed deliberately by the administrator; this plugin does not change kernel settings or fall back to privileged containers.
- A supported provider/model configured in Harness, with its normal adapter authentication. The bridge never reads raw credentials or places them in Docker arguments, the container environment or fresh Codex authentication files. Catalog membership does not guarantee protocol compatibility or detection quality for every model.

## Build and install

From this repository:

```sh
pnpm install --ignore-scripts --frozen-lockfile
pnpm run build:engine
pnpm test
pnpm run test:containers
```

`build:engine` builds the pinned base image and locked npm dependencies, records the actual immutable local Docker image ID in `image.json`, then generates a cache-safe Cordis patch and revision-specific runtime/helper/policy copies. An image ID from somebody else's machine is not an installation artifact: **build the engine locally before activating the plugin**. The revised image and runtime have been rebuilt and verified offline, including a real native scanner/local-tool roundtrip through an injected Harness adapter. No automatic paid scan or install script runs.

Install this directory as a local `link:` bundle using the Harness plugin manager, then enable `dsh-security`. Follow the manager's exact identifiers and normal permission checks. For an update, rebuild and disable/re-enable that bundle; do not run a second Web server. Reload the existing Harness page to load the Security client bundle.

The Security picker uses **`sessionController.modelCatalog()`**, the same authoritative catalog and default selection as the native Harness input picker, including an optional default reasoning effort. There is no adapter-list fallback or independent model allowlist. Before a scan or validation the Host enforces configured-provider/native-catalog membership, resolves model metadata, checks exact provider/model identity and validates any explicit reasoning effort. The activated GUI was verified with the configured catalog and **GPT-6.1-Sol · openai-codex** selectable; consent stayed unchecked and no inference was started. The Security panel uses its own dropdown, not the native input component.

Open **Security**, select the registered workspace and configured provider/model, set standard/deep mode and a 1–120 minute deadline, read the disclosure, check consent and click **Start scan**. Deep mode is capped at two workers, two subagents per worker and six discovery runs. Deadline and request ceilings are **not a dollar budget**.

## Isolation and disclosure

The scanner gets a recursively read-only source mount and read-only image root, with no external network, Docker socket or Host credential. Only its private state directory and tmpfs scratch areas are writable. All outer Linux capabilities are dropped, privilege escalation is disabled, and memory/CPU/PID limits apply.

Native Codex uses Bubblewrap and needs nested user namespaces. The shipped seccomp policy is derived from a pinned Moby default profile, with explicitly documented namespace/mount syscall allowances; it is not `seccomp=unconfined`. Docker's capability checks and locked read-only source mounts remain authoritative. Native engine tools execute **only inside the container**; the bridge translates local tool schemas/calls/results but never executes Harness tools.

The container endpoint accepts only POST `/responses` requests for the bound model. The Host bridge translates native Responses input and streaming output to the prepared Harness adapter; provider network access and authentication belong to that adapter, not the bridge. Hosted web/MCP/computer tools and remote background execution/storage are rejected. The transport caps concurrent requests at four, requests at 100 per operation, request JSON at 16 MiB, each response at 64 MiB and each model request at 180 seconds. The bridge also bounds JSON/replay state at 64 MiB and retains at most 256 cached response groups. Failed boundary or routing checks stop the operation rather than switching providers; raw adapter/provider errors are not passed through to the engine.

Docker creation has a 30-second managed-client timeout and is awaited before cleanup. A daemon-side create can outlive a terminated client: durable, label-verified leases are reconciled at startup and every 30 seconds while enabled, and removal uses immutable container IDs. Uncertain absent `creating` leases remain as tombstones indefinitely; legacy unlabeled containers are never automatically removed. Cleanup/grace can extend beyond the requested scan deadline. This is not automatic scan resumption.

**Consent sends repository content and findings to the selected configured provider and may incur charges.** Read-only mounts do not make source content non-sensitive or make repository code safe to execute. Reports and engine state can contain source excerpts; protect local Harness storage and the private security-scan state directory as sensitive data. See [SECURITY.md](<SECURITY.md>).

## Bridge compatibility and verification limits

- Explicit input history only: `previous_response_id` is unsupported. Opaque adapter replay requires intact, consecutive cached assistant groups; modified, incomplete or evicted replay state fails closed.
- Only automatic tool choice, text input/output and local function/custom tools (including namespaces) are supported. Hosted tools and multimodal requests are outside this bridge.
- JSON Schema output requests become schema instructions; strict provider-native schema enforcement is **not guaranteed**.
- Native engine request/stream retries are disabled, but a prepared Harness adapter may retain its own retry policy. Request ceilings count bridge requests, not necessarily every adapter attempt; the bridge adds no silent provider/model fallback.
- The original minimal authored engine model template replaces the third-party copied prompt catalog. Its engine planning hint is not the selected provider's reasoning configuration; Harness owns that configuration. The runner substitutes the selected model and bounded resolved context-window metadata.

Verification of the migrated runtime: **107 tests passed, zero skipped**, with `DSH_SECURITY_CONTAINER_TESTS=1`. Coverage includes ownership/consent, cancellation/recovery, native catalog/no-fallback checks, isolated transport probes, published-SDK mock scans/exports, native isolation, and a real native scanner receiving Harness SSE, executing a local `pwd` tool inside the container, and replaying its result with opaque adapter state intact. The earlier live GUI and Host verification reported runtime revision `339429f00f8f0e4b`. The UI authorization fix uses an authenticated, per-runtime CSRF bootstrap token instead of requiring browser-generated Origin/Fetch Metadata headers. Regressions cover a real loopback HTTP preflight without either marker, stale/malformed/missing tokens, conflicting markers, agent-result exclusion and mandatory consent. The UI verifies the token through read-only status requests before enabling Start/Validate; its rebuilt bundle requires reload and authenticated live verification. Injected adapters and engine mocks do not prove real-provider compatibility or vulnerability-detection quality; Linux/AppArmor variants have not been independently verified.

**No paid inference or live detection-quality tests have been run.** Standard/deep scan quality, finding validation and known-vulnerability/negative-control benchmark parity require separately authorized inference. There is no patch generation/apply workflow, upstream publication, automatic resumption or reliable dollar-budget enforcement in this release.

## Provenance and publication status

- [Codex Security](https://github.com/openai/codex-security), published npm SDK `0.2.0`, package git SHA `4949af70fcfadff154f6e8fdf100faa5bf2f8169`.
- Native Codex/SDK `0.162.0-alpha.15`, locked in the engine dependency manifest.
- [Moby seccomp baseline](https://github.com/moby/profiles/blob/6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef/seccomp/default.json).

Public repository: [TheSethRose/dsh-security](https://github.com/TheSethRose/dsh-security). Project code is Apache-2.0; third-party components retain their respective licenses. See [NOTICE](<NOTICE>). No licensing claim is made for the removed copied prompts.
