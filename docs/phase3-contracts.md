# Phase 3A Guarded Apply Core Contracts

Phase 3A is an unregistered, adapter-neutral guarded-application core. It has no MCP tool, registry entry, CLI command, live Home Assistant adapter, grant producer, deployment change, version change, or runtime write enablement. All live-effect ports are injected test doubles or future adapters; the contract default is `writesEnabled: false`.

## Transaction Journal

Transactions use schema version 1 and the exact states:

`intent_prepared`; `apply_committed`; `post_validation_succeeded`; `reload_succeeded`; `verification_succeeded`; `rollback_intent`; `rollback_committed`; `rollback_validation_succeeded`; `rollback_verification_succeeded`; `manual_recovery_required`.

Terminal outcomes are:

- `verification_succeeded`: verified
- `rollback_verification_succeeded`: rolled_back
- `manual_recovery_required`: blocked

Each durable record binds `transactionId`, `proposalId`, `proposalStorageSha256`, canonical relative `path`, `expectedSha256`, `candidateSha256`, `diffSha256`, `checkpointId`, `checkpointSha256`, `impact`, `version`, `priorState`, timestamps, and structured failure. The journal port is compare-and-swap by `transactionId` and `version`; every accepted transition increments `version` once and is durable before the next effect. Exact transaction reads support bounded CAS reconciliation; immutable identity is rechecked before retrying manual recovery, and repeated or unresolvable conflicts surface a distinct fail-closed manual-attention error. Journal adapters must enforce the shared legal transition adjacency: `intent_prepared -> apply_committed|rollback_intent|manual_recovery_required`; `apply_committed -> post_validation_succeeded|rollback_intent|manual_recovery_required`; `post_validation_succeeded -> reload_succeeded|rollback_intent|manual_recovery_required`; `reload_succeeded -> verification_succeeded|rollback_intent|manual_recovery_required`; `rollback_intent -> rollback_committed|manual_recovery_required`; `rollback_committed -> rollback_validation_succeeded|manual_recovery_required`; `rollback_validation_succeeded -> rollback_verification_succeeded|manual_recovery_required`. Terminal states have no legal outgoing transition. All exported exact state arrays, transition adjacency arrays, and recovery tables are recursively frozen at runtime so consumers cannot weaken journal legality.

## Approval Grants

Approval grants are injected only. Phase 3A provides no persistence, CLI, or producer for grants. A single-use apply grant must bind `grantId`, `proposalId`, `proposalStorageSha256`, `candidateSha256`, `diffSha256`, `operation=apply`, `risk`, `issuedAt`, and `expiresAt`.

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
12. Reload narrowly only for `domain_reload`.
13. Verify and terminally transition `verification_succeeded`.

Policy denies disabled writes, restart-required impact, missing apply or domain reload capability, nonpending/expired/discarded proposal state, invalid impact, and identity drift. Denials happen before effects.

`AtomicApplyPort.replace` reaches the commit point only at same-directory temp write, file sync and close, atomic rename, and parent directory sync. It reports `before_commit`, `committed`, or `commit_unknown`; `commit_unknown` is treated as possibly committed and reconciled by digest. If the live digest is candidate, the coordinator durably transitions to `apply_committed` with commit-unknown evidence and continues normal post-commit handling. If the live digest is expected/checkpoint, it routes through `rollback_intent -> rollback_committed -> rollback_validation_succeeded -> rollback_verification_succeeded` without restoring bytes. Other or missing digests become manual recovery.

## Rollback And Cancellation

Precommit cancellation has no live effect. After the apply commit point, caller cancellation is ignored and the coordinator uses an internal context to finish verification or rollback. Every post-commit failure carries the latest durable record forward, writes `rollback_intent` before restoring the checkpoint, then writes `rollback_committed`, runs rollback validation, writes `rollback_validation_succeeded`, runs rollback verification, and terminally writes `rollback_verification_succeeded`. Immediately after every checkpoint load, the coordinator recomputes SHA-256 and compares it with `checkpointSha256` before any restore, rollback validation, or rollback verification; mismatch writes `manual_recovery_required` from the latest legal state with no restore attempt. Rollback ambiguity or failure writes `manual_recovery_required`. Rollback restore treats returned and thrown `before_commit`, `committed`, and `commit_unknown` classifications explicitly: `committed` completes rollback validation and verification; `before_commit` moves to manual recovery from `rollback_intent`; `commit_unknown` reads the live digest and only claims `rollback_committed` when the digest is expected/checkpoint, otherwise it requires manual recovery. There is no implicit restart.

## Locks

Resource locks validate canonical relative paths, serialize the same path, allow distinct paths, bound waiters, check signal and deadline before enqueue, on wake, and before return, remove aborted/deadline waiters, and release on all exits.

## Startup Recovery

Startup recovery never reapplies the candidate. It returns one `Phase3RecoveryResult` per inspected record with `transactionId`, terminal state, observed digest classification, observed digest value, disposition (`verified`, `rolled_back`, or `manual_attention_required`), and the durable record. It reads the current live digest and follows the durable table:

- `intent_prepared`: expected/checkpoint routes through no-live-effect rollback completion; candidate restores checkpoint; other or missing writes manual recovery.
- `apply_committed`, `post_validation_succeeded`, `reload_succeeded`, `rollback_intent`: candidate restores checkpoint; checkpoint routes through rollback validation and verification without restore; other or missing writes manual recovery.
- `rollback_committed`: checkpoint completes rollback validation and verification; candidate, other, or missing writes manual recovery.
- `rollback_validation_succeeded`: checkpoint completes rollback verification only; candidate, other, or missing writes manual recovery without moving backward to `rollback_committed`.
- `verification_succeeded`: candidate is verified with no effect; expected/checkpoint, other, or missing digests require external manual attention without changing the terminal transaction.
- `rollback_verification_succeeded`: checkpoint is rolled back with no effect; drift requires external manual attention without changing the terminal transaction.
- `manual_recovery_required`: no effect.

`commit_unknown` is not a journal state; it is structured failure evidence and uses the same digest-driven conservative recovery.

## Phase 3B Protected Proposal Input

Phase 3B adds one unregistered read-only adapter from the existing protected Phase 2 proposal store to Phase3ProposalPort. Exact lookup validates a canonical lowercase UUID, reads only the corresponding protected file, applies the existing no-follow, private-file, single-link, stable-identity, strict-schema, canonical-JSON, and storage-digest checks, and never scans or quarantines. Raw file bytes are zeroed after parsing.

The adapter preserves proposal state, maps reloadImpact to impact, binds the Phase 2 storage digest as proposalStorageSha256, and requires public/protected proposal IDs, idempotency keys, candidate digests, and diff digests to agree. Candidate and exact-diff base64 are canonical, strict UTF-8, and digest-verified before a fresh candidate buffer is returned; temporary protected buffers are zeroed. Stable errors reveal no protected content.

Phase 3B does not add a journal, checkpoint, source, write, validation, reload, verification, approval producer, CLI, MCP tool, registry entry, configuration flag, package change, mapping change, or runtime import. Live writes remain disabled.
