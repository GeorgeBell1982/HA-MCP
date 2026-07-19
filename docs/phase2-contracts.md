# Phase 2 repository contract

Status: frozen for implementation; tools are not registered.

Phase 2 adds bounded repository reads and proposal metadata. It does not modify the live Home Assistant configuration. The authoritative configuration root is /homeassistant; writable proposal and audit state belongs under protected add-on /data.

## Public tool inventory

| Tool                       | Input                                                                            |
| -------------------------- | -------------------------------------------------------------------------------- |
| ha_list_config_files       | opaque cursor and bounded limit                                                  |
| ha_read_config_file        | normalized repository-relative path                                              |
| ha_search_config           | bounded query, cursor, and limit                                                 |
| ha_list_config_resources   | automation, script, helper, scene, or blueprint plus page                        |
| ha_get_config_resource     | resource type and identifier                                                     |
| ha_get_git_status          | no arguments                                                                     |
| ha_get_git_diff            | fixed worktree/index/both scope and optional bounded paths                       |
| ha_list_proposals          | opaque cursor and bounded limit                                                  |
| ha_get_pending_diff        | proposal UUID                                                                    |
| ha_propose_config_change   | idempotency UUID, existing YAML path, expected SHA-256, whole candidate document |
| ha_discard_proposed_change | proposal UUID                                                                    |

Inputs are strict. Paths use /, are NFC-normalized, relative, traversal-free, and exclude control characters, colon, empty segments, symlinks, hard-link aliases of protected files, and any identity the repository boundary cannot establish safely. Content limits are UTF-8 byte limits, not JavaScript character counts. Git tools accept no revisions or caller-supplied options.

All outputs use the bounded { ok, requestId, data|error, warnings, evidence, nextCursor? } envelope. Output schemas are strict and source evidence identifies /homeassistant, confined Git metadata, or protected proposal state. Existing Phase 1 tool names and schemas remain unchanged. Storage-mode dashboards remain capability_unavailable unless a supported Home Assistant API is verified.

## Proposal boundary

A proposal targets one existing .yaml or .yml document and supplies its complete replacement bytes plus the expected source digest. It cannot create, delete, rename, apply, reload, restart, commit, or push. Proposal identity is path + expected SHA-256 + candidate SHA-256. Reusing a key with the same identity returns the original proposal, including terminal or expired state; concurrent identical retries serialize to one proposal. Reusing a key with a different identity returns proposal_conflict.

Public proposal data contains identifiers, hashes, state, a redacted bounded diff, risk, validation plan, reload impact, timestamps, and evidence. Exact candidate and exact diff bytes are protected payloads: canonical base64 with a 512 KiB decoded limit, fatal UTF-8 validation, and SHA-256 verification against the decoded bytes. They are versioned, bound to proposal/idempotency IDs, never returned, and persisted only by the G1 protected durable proposal store.

## Frozen YAML gate

The gate pins `yaml@2.9.0` and uses incremental public `Parser` + `Composer` APIs with YAML 1.2 core, strict and unique-key checks, merge disabled, known YAML 1.1 tags disabled, warnings treated as failures, and bounded stable diagnostics. The caller's no-larger-than-512-KiB bytes are copied synchronously before the first await, hashed, fatal-UTF-8 decoded, and parsed only from that snapshot. The snapshot is wiped in `finally` where JavaScript permits. Original bytes are never mutated or reserialized. BOM, NUL, bare CR, mixed LF/CRLF, `%YAML`/`%TAG` directives, parser errors, composer errors/warnings, stream errors/warnings, and more than one document are rejected. Zero-byte and whitespace/comment-only streams have no document; an explicit `---` empty document is accepted.

The only custom tags are scalar `!include`, `!include_dir_list`, `!include_dir_merge_list`, `!include_dir_named`, `!include_dir_merge_named`, `!secret`, and `!input`. Raw reference input is limited to 100 values, 512 UTF-8 bytes per value, and 32 KiB aggregate. Include/input metadata contains the bounded value; secret metadata contains only SHA-256 and byte length. Successful frozen metadata is at most 32 KiB and contains no AST, document content, parser diagnostic, or secret name.

Keys must be untagged, unanchored scalar string, finite number, boolean, or null values. Duplicate identity is type plus canonical primitive (`-0` normalizes to `0`), so quoted string `"1"` remains distinct from numeric `1` while lexical equivalents are duplicates. Complex/alias/collection/tagged/anchored/nonfinite keys and explicit `<<` are rejected.

Document depth is zero and contents depth one; Scalar, Collection, Alias, and Pair each count once, with pair key/value and collection items at depth +1. Syntax is limited to depth 64 and 100,000 structural nodes. A separate expansion traversal counts every reached node/pair through every alias up to 100,000. Alias references and per-anchor fanout are each limited to 100; duplicate anchors, unresolved aliases, and identity-stack cycles fail closed. Parser input chunks are at most 4096 UTF-16 code units without splitting surrogate pairs, with cancellation and projected-monotonic deadline checks before/after chunks and after `setImmediate` yields. Structural, expanded, alias-fanout, and reference work shares a poll counter checked at least every 256 work units, with checks after each validation phase, metadata sizing, and immediately before success. Any unexpected parser/library exception after the byte snapshot is replaced by stable `internal_failure` without its message, source, context, or cause; the snapshot is still wiped in `finally`. A bounded scalar may still buffer the full 512 KiB, so no hard-real-time cancellation claim is made.

## Audit, cancellation, and recovery

Every protected read or proposal effect follows:

1. Persist a redacted version-2 attempt record.
2. Perform the read or effect.
3. Persist a redacted version-2 outcome record.
4. Return the response.

Audit attempts permit only pre-read identifiers and hashes available from the request; proposal attempts therefore exclude diff SHA-256. A successful, committed-unconfirmed, or reconciled proposal-create outcome requires proposal ID plus candidate and diff digests; the same discard outcomes additionally require discarded state. Audit records otherwise permit only tool, request/operation identifiers, risk, path/proposal identifiers, hashes, result, and stable error code. They exclude query text, snippets, configuration content, diffs, secret values, and exception context.

Failure to persist a required audit record latches the service unhealthy. Startup reconciliation resolves incomplete operations. Atomic rename is the persistence commit point; after it, cancellation cannot report a rollback that did not happen, and bookkeeping must finish or be reconciled. Deadlines and AbortSignal are internal operation context and are never caller-controlled tool arguments.

## Slice B boundary status

The unregistered security boundary is implemented with a Linux openat2 helper protocol, fail-closed Windows/unsupported behavior, protected device/inode identity registry, exact-value readiness latch, recursive exact-plus-heuristic redaction, cancellation/deadline propagation, bounded helper concurrency/output, and staged identity commits. The helper source is not yet a packaged runtime capability.

Linux compilation, final/parent link swaps, cross-mount/root replacement, same-size active mutation, child kill, unsupported-kernel behavior, and candidate-image permissions/protocol remain UNVERIFIED until the Slice G clean candidate-image gate. Therefore repository tools and the homeassistant_config mount remain absent.

## Slice C YAML gate status

The strict metadata-only YAML gate and exhaustive generated boundary fixtures are implemented in root source and the exact add-on mirror. It is not wired to a tool or repository reader. Registration, `/homeassistant` mounting, versioning, release, deployment, and live validation remain absent.

## Slice D repository-read status

Slice D implements an unregistered list/read/search service over a deterministic bounded YAML catalog. Linux discovery is a fixed-argument native openat2 helper with no shell or inherited environment, strict versioned binary output, bounded concurrency/deadline/cancellation, a pinned O_PATH root plus separate openat2-readable root traversal/recheck descriptors, conservative exclusions, strict zero-reserved fields, complete directory/file metadata in one global UTF-8 order, and two exactly matching validated passes. Windows, a missing helper, an unsupported kernel, malformed output, or ambiguous filesystem state fails closed; there is no realpath/lstat fallback.

The index accepts at most 2,000 files and 16 MiB, reads one file at a time, pre-excludes protected canonical paths, verifies identity and size, hashes exact bytes, and wipes owned buffers. The snapshot digest uses domain-separated, length-framed path, device, inode, and exact content SHA-256 records plus the included-file count. Literal search uses KMP over UTF-16 code units and a shared 200,000-unit budget covering preprocessing comparisons, scan comparisons, lines, and surviving matches, with polling at least every 256 units. Ordering uses UTF-8 bytes. List returns exact SHA-256 metadata; read returns the complete bounded file after nontruncating exact-plus-heuristic redaction; literal case-sensitive search matches raw lines, redacts full lines, drops hidden matches, and clips on scalar and UTF-8 boundaries.

Cursors are canonical unpadded base64url of exactly 136 characters: a fixed 70-byte operation/offset/query-digest/snapshot payload authenticated by a 32-byte HMAC. They bind operation, normalized query, snapshot, offset, and key. Malformed, unauthenticated, cross-operation, wrong-query, rotated-key, and closed-key cursors are invalid_input; an authenticated cursor with a changed snapshot or out-of-bound offset is stale_source. Neither classification latches the protected registry unhealthy.

Protected metadata binds canonical path, device/inode identity, and SHA-256. Paths are denied before reads and identities deny aliases after secure reads. Freshness is checked before indexing and before output; replacement, same-inode edit, deletion, or alias drift wipes temporary bytes and permanently latches unhealthy. This is observed fail-closed consistency, not an atomic snapshot.

Linux helper compile/runtime and active-race behavior remain UNVERIFIED on this Windows host until Slice G. Tools remain unregistered; no mount, registry wiring, version bump, release, deployment, or live access is part of Slice D.

## Slice E resource projection contract

Slice E adds an unregistered, fixed typed YAML projection path over the strict Slice C parser. The public metadata validator is unchanged. Projection occurs only after all existing syntax, tag, key, alias, depth, node, encoding, document, warning, and cancellation checks and exposes only deep-frozen bounded map/sequence/scalar shape needed for domain/resource identity, include placeholders, blueprint name/domain, provenance, and !secret source byte ranges. It exposes no document, AST/CST, arbitrary callback, general diagnostics, source text, or secret name.

Ordinary resources expand from configuration.yaml through the five Home Assistant include forms using the authoritative catalog, beneath-root relative normalization, protected path and identity denial, complete directory metadata, a once-built charged recursive lowercase-.yaml directory index in UTF-8 order, tag-specific empty/list/named/merge semantics (explicit []/{} merge inputs are no-ops; no-document merge inputs fail), occurrence charging, and path-stack cycle detection. Resource extraction covers root/label/package automation and scenes, scripts, and the exact helper-domain set. Blueprint projection is independent under the three authoritative blueprint domain directories and does not require configuration.yaml.

The operation limits are 2,000 unique parsed files, 20,000 include edges, depth 64, 200,000 projection/expansion work units, 200,000 retained IR nodes, 20,000 resources, 4 MiB retained strings, 16 MiB aggregate unique source bytes, and IDs of at most 256 Unicode scalars/512 UTF-8 bytes. Directory indexing, byte-offset construction, projection freezing, every root/package/domain/resource/blueprint extraction traversal (including skipped entries and identity-field scans), secret-range traversal, ordering, and snapshot work share bounded polling at most every 256 units. Secure reads validate catalog root, file identity, size, and exact digest; owned bytes are held one file at a time and wiped. Protected freshness is checked before graph work and after held output.

Resource summaries contain type, ID, provenance path, and exact unredacted source SHA-256. Resource get masks every projected !secret scalar source range before complete-file exact-plus-heuristic redaction, so secret names cannot appear. Resource IDs are NFC/control-free and bounded. A fresh successful projection with no exact ID returns resource_not_found; malformed reachable input fails instead.

Sorted deep-frozen public-summary arrays by resource type and an exact private type/ID lookup are constructed during the charged snapshot traversal; list returns only a bounded frozen slice and get uses the exact lookup. Resource-list cursors use operation byte 3 without changing list/search bytes 1/2 or the fixed 102-byte/136-character format. Their query slot is a domain-separated resource-type digest, and the snapshot binds projection-rule version, root identity, sorted source path/identity/SHA, ordered include edges, and sorted resource identity/provenance. Slice E remains unregistered with no add-on mount or deployment wiring. Linux native runtime validation remains UNVERIFIED until Slice G.

## Slice F confined Git read contract

Slice F adds an internal-only status and YAML diff service behind a mandatory packaged Linux broker. The broker receives only fixed enumerated operations and uses an absolute Git executable, a pinned repository root and direct `.git` directory opened beneath root without links, magic links, or cross-device traversal. Linked, bare, common-directory, submodule, gitlink, alternate-object, promisor/partial-clone, config-include, execution/filter, network, and indirection states fail closed. Windows and unpackaged runtimes return `capability_unavailable`; there is no direct Node Git fallback.

Broker execution uses pinned `/proc/self/fd` paths, pre/post root and Git identity checks, no-new-privileges, read-only Landlock, seccomp network/unrelated-exec denial, resource limits, process-group cleanup, exact non-inherited environment, fixed literal arguments, disabled prompts/locks/pagers/hooks/filters/fsmonitor/attributes/excludes/config includes/lazy fetch, and sandbox-authoritative write denial. The invocation supplies exactly one absolute `--runtime-loader` and at most 16 absolute `--runtime-input` libraries. Every closure entry is opened `O_PATH|O_CLOEXEC|O_NOFOLLOW`, must be a unique regular-file identity, and receives only its required Landlock right: Git and loader read/execute, libraries read-file. Broad directories, links, nonregular or duplicate entries, omitted loader, and incomplete runtime closure fail closed. Source and fake-protocol validation land in Slice F; real Linux policy, hostile Git runtime, and active-race validation remain Slice G `UNVERIFIED`.

Status is strict porcelain-v2 NUL framing, fatal UTF-8/NFC/control-free normalized paths, no rename/unmerged/submodule records, UTF-8 sorted, and capped at 500. It exposes only branch plus path/XY; protected paths may appear but never content, hashes, or identities. Diff preflights explicit paths against the authoritative current YAML catalog and protected identities before any blob request. Unscoped mode intersects eligible status with the catalog and reports unsupported omissions only through a generic warning.

Diff uses fixed plumbing metadata/object operations, never `git diff`. Only regular stage-zero blobs are accepted. The internal canonical LF line engine renders HEAD-to-index and index-to-current patches in deterministic path order, with staged before worktree, three context lines, no-final-newline markers, and a 200,000-unit budget. Each unique side is bounded, strict-YAML validated once, `!secret` spans masked, and completely exact-plus-heuristic redacted before comparison. Aggregate raw input, complete redacted patch, and public display are independently bounded; display truncation happens only after redaction on whole lines. The SHA-256 binds the complete canonical redacted patch, including content omitted only from the display.

Snapshots bind repository/Git identities, object format, HEAD/index state, eligible current identities/hashes, scope/filter, and every consumed object/content digest. Drift discards output; protected drift latches unhealthy. Work polls cancellation/deadline at most every 256 units and owned buffers are wiped. The service remains unregistered with no mount, packaging, version, release, deployment, or live repository access.

## Implementation gates

Registration remains blocked until the following are independently reviewed and validated:

- Linux beneath-root, no-symlink filesystem confinement with fail-closed Windows behavior.
- Canonical protected-file identity and exact plus heuristic secret redaction.
- A YAML safety gate covering tags, duplicates, multi-document input, aliases, bounds, encoding, and byte preservation.
- Hardened Git execution with confined metadata, sanitized environment/config, fixed arguments, timeouts, and output limits.
- Durable /data audit/proposal storage with permissions, fsync/rename/dirsync, digests, quarantine, expiry, conflict, crash, and failure-injection tests.
- The explicit read-only homeassistant_config mount only after all security layers pass.
- Focused, full, clean-room, and independent-review evidence.

G1 status: the internal protected proposal store, Phase 2 audit, mutation journal/reconciliation, authenticated cursors, and logical cross-platform failure tests are present. G2 still owns Linux permission/link/atomicity/directory-sync/process-crash validation plus any later registration or mount integration.
No Phase 2 add-on mount, version bump, release, deployment, or live configuration access is authorized by this contract slice.
