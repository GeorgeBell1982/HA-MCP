# Phase 3A Guarded Apply Core Contracts

Phase 3A is an unregistered, adapter-neutral guarded-application core. It has no MCP tool, registry entry, CLI command, live Home Assistant adapter, grant producer, deployment change, version change, or runtime write enablement. All live-effect ports are injected test doubles or future adapters; the contract default is `writesEnabled: false`.

## Transaction Journal

Transactions use schema version 2 and the exact states:

`intent_prepared`; `apply_committed`; `post_validation_succeeded`; `reload_intent`; `reload_succeeded`; `verification_succeeded`; `rollback_intent`; `rollback_committed`; `rollback_validation_succeeded`; `rollback_reload_intent`; `rollback_reload_succeeded`; `rollback_verification_succeeded`; `manual_recovery_required`.

Terminal outcomes are:

- `verification_succeeded`: verified
- `rollback_verification_succeeded`: rolled_back
- `manual_recovery_required`: blocked

Each durable record binds `transactionId`, `proposalId`, `proposalStorageSha256`, canonical relative `path`, `expectedSha256`, `candidateSha256`, `diffSha256`, `checkpointId`, `checkpointSha256`, `impact`, immutable `reloadTarget`, mutable monotonic `rollbackReloadRequired`, `version`, `priorState`, timestamps, and structured failure. The journal port is compare-and-swap by `transactionId` and `version`; every accepted transition increments `version` once and is durable before the next effect. Exact transaction reads support bounded CAS reconciliation; immutable identity is rechecked before retrying manual recovery, while `rollbackReloadRequired` may only change from false to true on `rollback_intent`. Journal adapters must enforce the shared legal transition adjacency including durable candidate reload `post_validation_succeeded -> reload_intent -> reload_succeeded` for targeted reloads, direct `post_validation_succeeded -> reload_succeeded` for no-reload changes, and rollback reload `rollback_validation_succeeded -> rollback_reload_intent -> rollback_reload_succeeded -> rollback_verification_succeeded` when required. Terminal states have no legal outgoing transition. Version 1 journal envelopes are rejected non-destructively; checkpoint envelopes remain version 1. All exported exact state arrays, transition adjacency arrays, and recovery tables are recursively frozen at runtime so consumers cannot weaken journal legality.

## Approval Grants

Approval grants are injected only. Phase 3A provides no persistence, CLI, or producer for grants. A single-use apply grant must bind `grantId`, `proposalId`, `proposalStorageSha256`, `candidateSha256`, `diffSha256`, `operation=apply`, `risk`, exact `impact`, exact `reloadTarget`, `issuedAt`, and `expiresAt`.

The approval port requires the exact pending proposal identity and fails closed before `issuedAt`, at expiry (`now >= expiresAt`), on replay, wrong binding, proposal storage drift, candidate or diff drift, discarded/expired/nonpending proposals, and cancellation before consumption.

## Apply Ordering

The coordinator order is:

1. Load proposal and run policy before the path lock.
2. Acquire a bounded lock keyed by validated canonical relative path.
3. Reload proposal, recheck exact identity, and rerun policy.
4. Read source and verify the expected digest.
5. Validate candidate locally.
6. Consume the single-use approval grant.
7. Create checkpoint.
8. Durably create `intent_prepared`.
9. Atomically apply candidate.
10. Durably transition `apply_committed`.
11. Run post-apply validation.
12. Durably enter `reload_intent` and dispatch the exact stored reload target only when `reloadTarget` is non-null; no-reload changes transition directly to `reload_succeeded`.
13. Verify and terminally transition `verification_succeeded`.

Policy denies disabled writes, restart-required impact, missing apply or domain reload capability, nonpending/expired/discarded proposal state, invalid impact, and identity drift. Denials happen before effects.

`AtomicApplyPort.replace` reaches the commit point only at same-directory temp write, file sync and close, atomic rename, and parent directory sync. It reports `before_commit`, `committed`, or `commit_unknown`; `commit_unknown` is treated as possibly committed and reconciled by digest. If the live digest is candidate, the coordinator durably transitions to `apply_committed` with commit-unknown evidence and continues normal post-commit handling. If the live digest is expected/checkpoint, it routes through `rollback_intent -> rollback_committed -> rollback_validation_succeeded -> rollback_verification_succeeded` without restoring bytes. Other or missing digests become manual recovery.

## Rollback And Cancellation

Precommit cancellation has no live effect. After the apply commit point, caller cancellation is ignored and the coordinator uses an internal context to finish verification or rollback. Every post-commit failure carries the latest durable record forward, writes `rollback_intent` before restoring the checkpoint, and sets `rollbackReloadRequired` only when candidate reload dispatch may have started. It then writes `rollback_committed`, runs rollback validation, writes `rollback_validation_succeeded`, performs one exact rollback reload through `rollback_reload_intent -> rollback_reload_succeeded` when required, runs rollback verification, and terminally writes `rollback_verification_succeeded`. Immediately after every checkpoint load, the coordinator recomputes SHA-256 and compares it with `checkpointSha256` before any restore, rollback validation, or rollback verification; mismatch writes `manual_recovery_required` from the latest legal state with no restore attempt. Rollback ambiguity or failure writes `manual_recovery_required`. Rollback restore treats returned and thrown `before_commit`, `committed`, and `commit_unknown` classifications explicitly: `committed` completes rollback validation and verification; `before_commit` moves to manual recovery from `rollback_intent`; `commit_unknown` reads the live digest and only claims `rollback_committed` when the digest is expected/checkpoint, otherwise it requires manual recovery. There is no implicit restart.

## Locks

Resource locks validate canonical relative paths, serialize the same path, allow distinct paths, bound waiters, check signal and deadline before enqueue, on wake, and before return, remove aborted/deadline waiters, and release on all exits.

## Startup Recovery

Startup recovery never reapplies the candidate. It returns one `Phase3RecoveryResult` per inspected record with `transactionId`, terminal state, observed digest classification, observed digest value, disposition (`verified`, `rolled_back`, or `manual_attention_required`), and the durable record. It reads the current live digest and follows the durable table:

- `intent_prepared`: expected/checkpoint routes through no-live-effect rollback completion; candidate restores checkpoint; other or missing writes manual recovery.
- `apply_committed`, `post_validation_succeeded`, and `rollback_intent`: candidate restores checkpoint; checkpoint routes through rollback validation and verification without restore; other or missing writes manual recovery.
- `reload_intent` and `reload_succeeded`: candidate restores checkpoint and requires rollback reload; checkpoint routes through rollback validation plus rollback reload when required; other or missing writes manual recovery.
- `rollback_committed`: checkpoint completes rollback validation and rollback reload or verification; candidate, other, or missing writes manual recovery.
- `rollback_validation_succeeded`: checkpoint completes rollback reload when required or rollback verification only; candidate, other, or missing writes manual recovery without moving backward to `rollback_committed`.
- `rollback_reload_intent`: startup recovery requires manual recovery because dispatch completion is uncertain.
- `rollback_reload_succeeded`: checkpoint completes rollback verification only; candidate, other, or missing writes manual recovery.
- `verification_succeeded`: candidate is verified with no effect; expected/checkpoint, other, or missing digests require external manual attention without changing the terminal transaction.
- `rollback_verification_succeeded`: checkpoint is rolled back with no effect; drift requires external manual attention without changing the terminal transaction.
- `manual_recovery_required`: no effect.

`commit_unknown` is not a journal state; it is structured failure evidence and uses the same digest-driven conservative recovery.

## Phase 3B Protected Proposal Input

Phase 3B adds one unregistered read-only adapter from the existing protected Phase 2 proposal store to Phase3ProposalPort. Exact lookup validates a canonical lowercase UUID, reads only the corresponding protected file, applies the existing no-follow, private-file, single-link, stable-identity, strict-schema, canonical-JSON, and storage-digest checks, and never scans or quarantines. Raw file bytes are zeroed after parsing.

The adapter preserves proposal state, maps current Phase 2 `none` and `restart_required` reloadImpact values to a null reload target, binds the Phase 2 storage digest as proposalStorageSha256, and requires public/protected proposal IDs, idempotency keys, candidate digests, and diff digests to agree. Current Phase 2 `domain_reload` proposals without an explicit stored target are rejected; the adapter never infers a target from the path. Candidate and exact-diff base64 are canonical, strict UTF-8, and digest-verified before a fresh candidate buffer is returned; temporary protected buffers are zeroed. Stable errors reveal no protected content.

Phase 3B does not add a journal, checkpoint, source, write, validation, reload, verification, approval producer, CLI, MCP tool, registry entry, configuration flag, package change, mapping change, or runtime import. Live writes remain disabled.

## Phase 3C Durable Transaction Journal

Phase 3C adds an unregistered append-only implementation of Phase3JournalPort. Each immutable version is a private regular file named by canonical transaction UUID and zero-padded version and contains one strict canonical integrity-enveloped record. Histories start at intent_prepared version 0, remain contiguous, preserve immutable identity and createdAt, and follow the shared legal transition graph.

A version is prepared as record.json in a unique same-parent private pending directory. The record is fully written with short-write and EINTR handling, file-synced, closed, the pending directory is synced, and its no-follow descriptor identity and bytes are rechecked before an atomic hard link creates the final version file. The hard link is the no-overwrite commit point. A competing final artifact is never replaced; a valid committed file yields a CAS conflict and an unsafe artifact fails closed. Any failure after the link yields commit-unknown and is reconciled by exact disk refresh. Parent-directory sync confirms the final link, then owned pending cleanup and a second parent sync complete housekeeping.

Initialization and refresh are non-destructive. Committed evidence is never overwritten, removed, renamed, or quarantined. Recognized safe pending directories are bounded, retained, and ignored as uncommitted crash evidence. A post-link crash may leave the pending record and final file as exactly two links to one inode; recovery accepts that final only while exactly one recognized pending record has the same device and inode. Unrelated hard links, unknown or unsafe artifacts, malformed envelopes, history gaps or forks, identity drift, illegal adjacency, and limit violations fail closed and latch the adapter unhealthy. Every public operation refreshes bounded disk state so independent instances observe committed versions. The default native durability implementation is Linux-only; Windows exercises the platform-neutral logic through an injected durability port and fails closed if native durability is requested.

Phase 3C remains an inert source island. It adds no checkpoint, source, atomic-write, validation, reload, verification, approval producer, CLI, MCP tool, registry entry, configuration flag, package change, mapping change, runtime import, or write activation.

## Phase 3D Durable Immutable Checkpoints

Phase 3D adds an unregistered immutable implementation of `Phase3CheckpointPort`. Each checkpoint is one private regular final artifact named by a canonical lowercase checkpoint UUID. The stored canonical JSON envelope binds schema version, a lowercase nonce, checkpoint UUID, canonical Phase 3 relative path, `expectedSha256`, `sourceSha256`, `contentSha256`, canonical standard base64 content, and `storageSha256`. The checkpoint UUID is derived from the nonce plus immutable envelope identity, and `storageSha256` covers the complete canonical core, so ordinary tamper, re-signed tamper under the original filename, filename/envelope UUID mismatch, noncanonical JSON, noncanonical base64, path drift, digest drift, and oversize records fail closed.

`create` validates canonical path, lowercase SHA-256, decoded content at or below `PHASE2_MAX_TEXT_BYTES` with empty content allowed, and `sha256(content) == expectedSha256` before creating any pending entry. It preflights checkpoint count, pending count, record byte size, and projected aggregate record bytes before append. A record is prepared in a unique same-parent private pending directory, fully written with short-write and EINTR handling, file-synced, closed, pending-directory synced, and then re-opened no-follow to verify descriptor identity and exact bytes. The atomic hard-link to the final lowercase UUID filename is the create-only commit point; no final artifact is ever overwritten. Parent sync, owned pending cleanup, and a second parent sync complete housekeeping.

`load(checkpointId)` requires an exact lowercase UUID and validates only the checkpoint artifact's internal envelope binding: bounded no-follow descriptor stat/read/stat/lstat, strict schema, canonical JSON, canonical base64, storage digest, content digest, source/expected/content digest equality, and filename/envelope UUID equality. It returns fresh caller-owned bytes and zeros temporary read buffers. It does not claim restore-time path enforcement; coordinator rollback remains bound by the journal's durable `checkpointId` plus `checkpointSha256`, and the coordinator recomputes checkpoint byte SHA-256 before restore.

Initialization and every operation refresh bounded disk state. Unknown names, unsafe traversal/root/file topology, symlinks, nonregular files, unrelated hard links, malformed/tampered/noncanonical/oversize artifacts, checkpoint count, pending count, aggregate byte, and scan-entry violations fail closed and latch the store unhealthy. Recognized empty, active, or orphan pending directories are retained and ignored as uncommitted crash evidence. A post-link `nlink=2` final is accepted only when exactly one recognized pending record shares the same device and inode. Precommit cancellation and deadlines are checked before staging, during writes, after sync/close, and after pending sync before link. After link, caller cancellation is ignored so durability confirmation and cleanup can finish. Handled precommit failures remove only owned pending evidence and sync the parent; simulated precommit crashes retain pending evidence. Any failure after link returns `checkpoint_commit_unknown` and retains evidence.

The default native durability path explicitly requires Linux. Windows tests exercise the platform-neutral logic through injected logical durability, and native Windows initialization fails closed. Phase 3D remains an inert source island: it adds no source, atomic-write, validation, reload, verification, approval producer, CLI, MCP tool, registry entry, configuration flag, package change, mapping change, runtime import, or write activation.

## Phase 3E Protected Source Adapter

Phase 3E adds an unregistered read-only implementation of `Phase3SourcePort`. `ProtectedPhase3SourceAdapter` injects a `RepositoryCatalogProvider` and a narrow protected-source boundary interface satisfied by `ProtectedIdentityRegistry`: `assertFresh`, `isProtected`, and `readContent`. It does not register a tool, add runtime wiring, add configuration, or enable writes.

`read(path, context)` validates `canonicalPhase3Path` before any freshness, catalog, or read effect. It derives exactly one Phase 2 operation context for the call, with fresh random UUID `requestId` and `operationId` plus the caller's exact `signal` and `deadlineAt`, and passes that same object through protected freshness, catalog, content read, and final freshness checks. The sequence is: protected freshness; repository catalog; exact catalog entry lookup; absent entry returns `resource_not_found`; preknown protected path or inode returns `protected_resource`; protected content read; root identity, file identity, exact byte length, and `PHASE2_MAX_TEXT_BYTES` validation; second protected freshness; exact lowercase SHA-256; fresh caller-owned bytes. Empty bytes are allowed, and source bytes are never decoded as UTF-8 or parsed as YAML.

`readDigest(path)` validates the same canonical path and then creates one internal Phase 2 context with fresh random UUIDs, a fresh non-aborted signal, and `deadlineAt = Date.now() + 60_000`. It follows the same catalog, protection, read, validation, digest, zeroization, and final freshness sequence. It returns `null` only when the exact catalog entry is absent.

Boundary-owned byte buffers are zeroed in `finally` on success, catalog/read race failures, freshness failures, validation failures, cancellation, deadlines, and unknown exceptions. Caller-owned bytes are created only after all checks pass, so caller zeroization cannot affect later reads. Existing `RepositoryBoundaryError` codes are preserved with stable source-safe messages, except an unexpected `resource_not_found` or `protected_resource` from `readContent` after a catalog/precheck acceptance is classified as generic `service_unhealthy`. Unknown exceptions are classified as generic `service_unhealthy`. Errors do not disclose raw content or the requested target path.

Phase 3E remains an inert source island: it adds no atomic-apply adapter, validation adapter, reload adapter, verification adapter, approval producer, CLI command, MCP tool, registry entry, configuration flag, package change, mapping change, runtime import, write activation, or live Home Assistant mutation. Atomic apply is deferred to Phase 3F; validation, reload, verification, approval production, activation, and live write enablement remain later-adapter work.

## Phase 3F Inert Native Atomic Apply

Phase 3F adds an unregistered `NativePhase3AtomicApply` implementation of `Phase3AtomicApplyPort` plus an inert Linux helper source `openat2-replace.c`. It does not change `phase3Contract`, does not register tools, does not add CLI/config/package/Dockerfile/runtime wiring, and does not enable live writes. Package inclusion, libcrypto provisioning, aarch64 native proof, RW `/homeassistant` mapping, activation, and live Home Assistant mutation are explicitly deferred and unverified.

The TypeScript adapter validates canonical Phase 3 relative paths, lowercase SHA-256 digests, content size at or below `PHASE2_MAX_TEXT_BYTES`, `sha256(content) == contentSha256`, active cancellation/deadline context, Linux platform, and absolute normalized root/helper paths before a helper can run. It owns a candidate byte copy for stdin, preserves caller bytes, and zeros the owned copy on success, failure, cancellation, timeout, and protocol errors. It bounds concurrent helper execution and waiter count before spawning, uses a fixed no-shell helper invocation with `cwd=/`, empty environment, and literal arguments `{root, path, expectedSha256, contentSha256, byteLength}`, sends only the owned candidate copy on stdin, bounds stdout to the exact protocol frame, and bounds/discards stderr.

The helper protocol is exactly one line: `phase3-atomic-apply-v1 status=<before_commit|committed|commit_unknown>[ error=<closed_enum>]`. Missing, malformed, trailing, truncated, or unknown-error output fails closed. Spawn failure, pre-spawn cancellation, and pre-spawn deadline are `before_commit`. After helper start, unexpected exit, signal, stdin/EPIPE, timeout, forced kill, or malformed output are `commit_unknown` unless an exact `before_commit` frame proves no commit. The adapter performs no retry. In-flight caller cancellation terminates the helper process group with a finite grace before kill; helper cancellation before exchange reports `before_commit`, while cancellation after exchange is expected to be ignored by the helper so verification and cleanup can complete.

The C helper is Linux-only and source-only in this slice. It declares the OpenSSL 3 `SHA256` symbol and assumes an explicit external `libcrypto.so.3` link for native tests; no custom cryptography is introduced. It accepts strict fixed arguments and exact candidate stdin, rejects truncation/overflow, opens the root as `O_PATH|O_DIRECTORY|O_NOFOLLOW`, opens parent and target with `openat2` `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`, requires a stable regular single-link target without special mode bits or xattrs, checks bounded target size and expected digest, and preserves uid/gid/permission mode.

The helper stages only with `O_TMPFILE`; fallback named creation is prohibited. It fully writes and fsyncs the candidate, links the anonymous file to a high-entropy private same-parent pending name immediately before commit, reopens it no-follow, verifies staged identity/digest, and revalidates root/parent/path/target identity, metadata, and expected digest immediately before the exchange. The sole live commit point is `renameat2(RENAME_EXCHANGE)`. This is atomic replacement, not compare-and-swap. The helper never exchanges back and never performs a second replacement. After exchange, the displaced original remains under the pending name until post-commit verification confirms the live target is the staged candidate and the displaced file is the immediate-prechecked target with the expected digest and metadata; only then it unlinks displaced evidence and performs a second parent fsync before reporting `committed`.

Any uncertainty at or after exchange reports `commit_unknown` and preserves available evidence; displaced evidence is not unlinked on unknown. Handled cancellation before exchange unlinks only the owned pending name when it exists, fsyncs the parent, and reports `before_commit`. `SIGKILL` may leave a recognized pending artifact; the helper performs no autonomous pending cleanup, and future matching artifacts fail closed for manual cleanup. Test-only failure hooks are compile-time gated and cover pre-exchange, exchange, and post-exchange classification without adding runtime wiring.

## Phase 3G Strict YAML Validation Adapter

Phase 3G adds an unregistered `StrictYamlPhase3Validation` implementation of `Phase3ValidationPort`. It is an inert source-only validation adapter: it is not imported by runtime composition, not registered as a tool, not configured, not packaged differently, not mapped into the add-on, and does not enable writes or live Home Assistant mutation.

The adapter accepts only the closed runtime phases `candidate_pre_apply`, `candidate_post_apply`, and `checkpoint_post_rollback`. Invalid runtime phases fail before boundary invocation with `invalid_phase`. Pre-cancelled or expired contexts fail before boundary invocation with the corresponding strict YAML gate code. Each accepted call copies caller bytes into an owned buffer, derives exactly one frozen Phase 2 operation context with fresh random UUID `requestId` and `operationId` plus the caller's exact `signal` and `deadlineAt`, invokes a narrow injected boundary that defaults to `validateStrictYaml`, and zeros the owned input in `finally`. Caller bytes are never modified.

Known `YamlGateError` failures are converted to `Phase3ValidationError` with the original gate-derived code, validation phase, sanitized finite positive line and column, and a stable bounded allowlisted message. `Phase3ValidationErrorCode` is derived from `YamlGateErrorCode` plus `invalid_phase`; the gate code list is not duplicated. Runtime bad byte values become `unsupported_encoding`. Unknown exceptions become `internal_failure` at line 1 column 1 and do not disclose raw content, paths, canaries, causes, or third-party messages.

Phase 3G remains an inert source island. HA API validation, deployment-aware validation, reload adapters, verification adapters, approval production, activation, registration, package/container changes, mapping changes, and live Home Assistant mutation remain deferred and unverified.

## Phase 3H Narrow Domain Reload Adapter

Phase 3H adds the unregistered `NarrowPhase3ReloadAdapter` implementation of `Phase3ReloadPort` and keeps it target-exact. It does not infer domains from repository paths. The caller supplies the durable `{ path, target }` reload request; an injected catalog re-resolves the canonical Phase 3 path and exact operation context and must return the same frozen closed target, or `unavailable`, `ambiguous`, or `unhealthy`. Unavailable, ambiguous, unhealthy, malformed, mismatch, and not-dispatched outcomes are known no-dispatch before rollback reload is required; post-service throws and malformed dispatch results are outcome-unknown.

The injected service boundary accepts only the closed target union and returns an exact frozen outcome of `completed`, `not_dispatched`, or `outcome_unknown`. The adapter imports no generic Home Assistant REST or WebSocket request client, performs no retry or fallback, and exposes no broad reload or restart operation. It validates the path and active context before catalog resolution and rechecks cancellation and deadline immediately before dispatch. Once dispatch starts, the boundary owns the exact context and outcome classification; thrown or malformed dispatch results are conservatively `outcome_unknown`.

`Phase3ReloadError` extends `Phase3CoordinatorError` so durable coordinator failure evidence preserves its closed code. Its public evidence is limited to closed stage, resolution, dispatch, and optional allowlisted target classifications with a fixed message. Requested paths, upstream messages, causes, tokens, and response content are not retained or disclosed.

Phase 3H remains an inert source island. It does not change `phase3Contract`, runtime composition, configuration, registry, package/container content, add-on mappings, write enablement, or live Home Assistant access.

## Phase 3I Durable Reload Recovery Foundation

Phase 3I extends the inert transaction and recovery foundation with an exact durable reload target, candidate `reload_intent -> reload_succeeded` ordering, monotonic `rollbackReloadRequired`, and rollback `rollback_reload_intent -> rollback_reload_succeeded` ordering. The coordinator verifies the candidate only from `reload_succeeded`; it verifies a checkpoint only from `rollback_validation_succeeded` when no rollback reload is required or from `rollback_reload_succeeded` after the exact rollback reload.

Startup recovery never repeats an ambiguous candidate reload. Candidate `reload_intent` and `reload_succeeded` route through rollback with reload required when the target is non-null. Incomplete `rollback_reload_intent` requires manual recovery; `rollback_reload_succeeded` may continue only with the checkpoint digest live. The journal schema, legal adjacency, record-level reload context, recovery table, and root/add-on mirrors are exact and recursively frozen where exported.

Phase 3I remains inert. It adds no adapter activation, runtime composition, configuration, registry, package/container change, mapping change, write enablement, live reload wiring, or live Home Assistant access.

## Phase 3J Narrow Post-Effect Verification Adapter

Phase 3J adds an unregistered `NarrowPhase3VerificationAdapter` implementation of `Phase3VerificationPort`. It accepts candidate verification only from exact `reload_succeeded` records with `rollbackReloadRequired = false` and the durable no-target or target predecessor binding. It accepts checkpoint verification only from exact `rollback_validation_succeeded` records with no rollback reload required or exact `rollback_reload_succeeded` records with a non-null target and rollback reload required. Records are first parsed through the existing strict transaction assertion; Phase 3J changes no coordinator, journal, schema, transition, or observation class.

The adapter injects one exact post-effect source digest port and one narrow trusted verification probe port. For the outcome-selected candidate or checkpoint digest, the order is exactly source digest, probe, source digest with the same operation-context object, two consistency reads, and no retry. Both source reads must return the exact expected lowercase SHA-256. The frozen probe request binds `transactionId`, `path`, `outcome`, `expectedSha256`, `impact`, `reloadTarget`, and `rollbackReloadRequired`.

Probe evidence must be an exact frozen object containing only own immutable enumerable data properties `{ status, transactionId, outcome, expectedSha256 }`. The adapter snapshots descriptors once without property access and rejects accessors, symbols, excess keys, unfrozen values, hostile proxies, malformed evidence, and stale bindings. Closed statuses are `verified`, `rejected`, `unavailable`, and `unhealthy`. Cancellation and deadline are checked before effects and after every fulfilled or rejected boundary call before classifying its return or failure. Stable `Phase3VerificationError` evidence contains only closed code and stage; it retains no cause, requested path, foreign object, upstream message/content, or unexpected observed digest.

Freezing and exact binding establish shape, immutability, and staleness checks; they do not establish authenticity. The injected verification probe is trusted semantically to report the loaded Home Assistant state represented by its bound evidence. Activation remains blocked until a production Home Assistant adapter proves loaded-state observation and reload causality for each supported target. Phase 3J remains an inert exact root/add-on source island with no generic HA REST/WebSocket client, runtime import, configuration, registry, package/container change, mapping change, write enablement, live access, mutation, commit, push, deploy, or release.

## Phase 3K Contextual Protected Post-Effect Source Digest Bridge

Phase 3K makes the inert `ProtectedPhase3SourceAdapter` structurally satisfy both `Phase3SourcePort` and `Phase3PostEffectSourceDigestPort`. The legacy `readDigest(path)` form retains its fresh internal non-aborted signal and 60 second deadline. The contextual `readDigest(path, context)` form validates the canonical path before effects or supplied-context access, then derives exactly one frozen `Phase2OperationContext` with fresh distinct UUIDs and the exact captured caller signal and finite deadline.

Runtime context values are treated as unknown for shape and robustness checks. Null and non-objects, signal values that are not intrinsic-brand-compatible, signal values with any own `aborted` data or accessor descriptor, and non-finite or non-number deadlines fail as sanitized `service_unhealthy`. Signal and deadline properties are snapshotted at most once. Signal validation uses `Reflect.getOwnPropertyDescriptor` plus the intrinsic `AbortSignal.prototype` `aborted` getter without an ordinary untrusted property read; descriptor/proxy traps are caught, and no failure triggers retry or internal-context fallback. Rejecting an own `aborted` descriptor prevents downstream freshness checks from dispatching to a shadow getter.

These JavaScript checks do not authenticate signal provenance. A complete forgery assembled from `AbortSignal.prototype` and copied internal-looking symbols, without an own `aborted` shadow, may be indistinguishable from a coordinator-created signal. `Phase3OperationContext` is therefore an internal trusted coordinator contract: future activation and runtime composition must supply it through a trusted context factory or equivalent provenance boundary. Phase 3K establishes only an intrinsic-brand-compatible, unshadowed signal shape before effects.

Both digest forms use the existing protected source path unchanged: first freshness, exact catalog lookup, protected path/inode precheck, accepted secure read, root/file identity and size validation, lowercase SHA-256, final freshness, and boundary-byte zeroization. Catalog absence alone returns `null`; accepted-read missing/protected races and unknown failures remain fail-closed. Digest calls return no source bytes, perform no retry or cache, and pass the same derived context object to both freshness checks, catalog, and content read.

This bridge proves protected disk/source consistency only within the injected repository boundaries and trusted operation-context contract. It does not prove operation-context or signal authenticity, Home Assistant loaded-state authenticity, or reload causality. Phase 3K remains exact mirrored source/tests/docs only and is absent from runtime composition.

Phase 3K explicitly supersedes Phase 3J's stale deferral of `production probe/source adapters` only to the extent that the source adapter is now structurally satisfied. Trusted runtime context provenance, runtime composition and package reachability, native-live filesystem proof, the production verification probe, Home Assistant loaded-state observation, reload-causality proof, service transport, approval production, registration, activation, and every live mutation remain `BLOCKED` or `UNVERIFIED`. No operational or production-readiness claim is made.
