# Security contract

Phase 1 is read-only. The add-on requests only `homeassistant_api`, has no `/config`
mapping, and the MCP inventory contains no mutation, restart, delete, generic service,
shell, file, or Git capability.

Direct MCP is off by default and requires ECDSA P-256 TLS with an IP/DNS SAN matching
the external endpoint, a paired client, exact `Host`, no browser `Origin`, and no forwarding headers. The
ingress listener is separate, binds the add-on container wildcard, has no published
host port, and is reachable only across authenticated HA ingress. Each client has a random 128-bit ID
and 256-bit secret; only salted scrypt hashes persist. Revocation and rotation are
per-client. MCP sessions are owned by the authenticating client and limited per
client; another client receives no session existence oracle.

The container uses an internal wildcard only in add-on mode because Supervisor port
forwarding cannot reach container loopback; the host port defaults unpublished and
local mode rejects wildcard binds. Headers and declared bodies are bounded, chunked
POSTs are rejected, and per-client/global sessions, request rate, idle lifetime, and
absolute lifetime are limited. Shutdown and client revocation/rotation clean sessions.

The bridge takes credentials only from a protected file and requires both the copied
certificate as a startup trust anchor and an independently verified SHA-256 DER
certificate fingerprint. Public, Cloudflare, reverse-proxy, and plaintext non-loopback
operation are unsupported.

The Supervisor token is runtime-injected and used only against the fixed Core proxy.
REST redirects are rejected and safe reads have bounded retries/timeouts. WebSocket
authentication, requests, disconnect rejection, timeouts, and bounded reconnect are
implemented without putting credentials in URLs. Audit JSONL is mandatory, redacted,
synced before results return, and failure closes tool calls.

## Phase 2 repository boundary

Slice B defines the repository security boundary but does not register repository tools or add a configuration mount. Add-on access remains unavailable until Slice G compiles, packages, permission-checks, protocol-checks, and exercises the native helper in the candidate image before enabling the official read-only homeassistant_config mapping at /homeassistant.

On Linux, content reads require the fixed-argument native openat2 helper with beneath-root, no-symlink, no-magic-link, and no-cross-mount resolution. It accepts only normalized relative paths and existing regular files, bounds output, rejects NUL and invalid UTF-8, pins root device/inode identity, and rejects files whose device, inode, size, modification time, or change time moves during the read. There is no realpath/lstat fallback. Missing helper, unsupported kernel/protocol, malformed or oversized output, child failure, or invalid packaging fails closed.

Windows intentionally reports capability unavailable; it does not claim active-race safety. Development roots are injectable only into the unregistered boundary and tests. The add-on production root remains /homeassistant.

secrets.yaml and configured protected sources are opened internally through the same helper. Their device/inode identities deny direct and hard-link-alias content access. Registration is bounded, rejects ambiguous identities, and latches unhealthy on failure. Exact values come only from the later bounded YAML secret provider; until that provider succeeds, repository content remains unavailable. Exact plus heuristic redaction covers nested response, error, snippet, diff, diagnostic, and Git-shaped strings. Secret bytes are zeroed on internal ownership release where JavaScript permits, but the project does not claim OS-locked memory.

## Phase 2 strict YAML boundary

Slice C adds an unregistered metadata-only gate pinned to `yaml@2.9.0`. It snapshots at most 512 KiB before yielding, uses fatal UTF-8 and strict line/document/directive preflight, feeds Parser + Composer in bounded surrogate-safe chunks, and rejects every parser token error plus document/stream error or warning. The gate never converts the document to JavaScript, resolves a secret/include, returns an AST/content/diagnostic, or reserializes caller bytes.

Custom tags, reference bytes/count, output metadata, structural and expanded nodes, syntax depth, aliases, and anchor fanout are independently bounded. Secret tag names become only SHA-256 plus byte length. Duplicate/complex/tagged/anchored/nonfinite keys, merge keys, duplicate or unresolved anchors, and identity cycles fail closed. Cancellation and deadlines are cooperative around chunks and at least every 256 structural, expanded, alias, or reference work units, with validation-phase and pre-success checks. Unexpected parser/library failures are converted to stable `internal_failure` without third-party diagnostic context while the snapshot is wiped in `finally`. The YAML lexer may buffer the complete bounded 512 KiB scalar, so this is not a hard-real-time or locked-memory claim. Repository access remains unavailable until the later provider, audit/proposal, Git, packaging, mount, clean-image, and registration gates pass.

## Phase 2 repository reads

Slice D adds an unregistered bounded catalog and list/read/search service. Catalog discovery is Linux-only through a fixed native openat2 helper, with no shell, fixed arguments and working directory, empty environment, strict zero-reserved binary framing with complete globally ordered directory/file metadata, output/deadline/concurrency limits, a pinned O_PATH root plus separate openat2-readable traversal/recheck descriptors, no-follow enumeration, beneath-root/no-symlink/no-magic-link/no-cross-mount opens, accumulated root-relative paths, directory/root revalidation, and two identical validated passes. Failure or uncertainty closes the capability; Windows has no fallback.

Protected denial uses canonical paths and device/inode identities, while freshness also binds exact SHA-256. Checks occur before indexing and before output. Drift latches unhealthy for the process lifetime. Indexing pre-excludes protected paths, validates the catalog root plus each file identity and size, processes one file at a time, and wipes owned buffers. Reads use complete-file exact-plus-heuristic redaction up to 512 KiB instead of legacy diagnostic truncation. Snapshot digests use domain-separated canonical length framing for each path, device, inode, and exact content digest. Malformed or unauthenticated cursors are invalid_input; authenticated snapshot or offset drift is stale_source, and neither latches protected-file health. Search uses linear KMP over UTF-16 code units and one 200,000-unit preprocessing/comparison/line/match budget with cancellation polling at most every 256 units; it returns a case-sensitive literal match only when it survives full-line redaction. Owned query-hash bytes are wiped before protected-query rejection or output.

This detects observed drift and fails closed but is not an atomic snapshot. Linux helper compilation and active-race validation remain UNVERIFIED until Slice G; tools and the /homeassistant mount remain absent.

## Phase 2 confined Git reads

Slice F treats Git configuration, metadata, paths, object identifiers, objects, subprocess output, and repository races as hostile. Node never invokes Git directly: a packaged Linux broker must pin the root and direct `.git` directory with beneath/no-link/no-magic-link/no-cross-device constraints, validate identities before and after, and execute only enumerated fixed plumbing operations through pinned descriptors. Unsupported repository topology, config inclusion, hooks/filters/fsmonitor, alternates, partial clone/lazy fetch, credentials, proxies, SSH/askpass, global/system config, environment inheritance, network, unrelated execution, writes, or missing confinement fails closed. Windows and unpackaged execution remain unavailable. The broker requires exactly one absolute runtime-loader argument plus at most 16 absolute runtime-library arguments. It opens every closure entry with `O_PATH|O_CLOEXEC|O_NOFOLLOW`, requires unique regular-file identities, grants execute permission only to the pinned Git executable and loader, and grants libraries read-file permission only; broad directories, links, nonregular files, duplicates, and incomplete closure fail closed.

Status discloses only branch and path/XY, with strict path encoding and record bounds. Diff content is limited to current securely catalogued nonprotected YAML. Protected explicit paths are denied before object access; unscoped unsupported paths produce no names. HEAD/index/current bytes are independently bounded, strict-YAML validated once, secret spans masked, and completely redacted before deterministic internal comparison. Patch truncation occurs only after redaction; its digest binds the complete redacted form. Snapshot and freshness checks bind all filesystem, Git, object, and current-content inputs, and cancellation/deadline polling plus process-group termination prevents abandoned broker work. Real Linux sandbox enforcement and race validation remain Slice G `UNVERIFIED`.

## Phase 2 typed resource projection

Slice E permits only the fixed selective IR and resource/blueprint projectors described in the acceptance ledger. It never releases parser objects, arbitrary scalar content, source text, parser diagnostics, or secret names. Include resolution is authoritative-catalog-only, relative to the containing file, normalized beneath root, no-follow through the secure reader, protected-path/identity denied before content use, globally ordered through a charged once-built recursive lowercase-.yaml directory index, cycle checked, capped to 16 MiB aggregate unique source bytes, and bounded across unique parses and every expansion occurrence. Explicit empty []/{} merge inputs are safe no-ops; absent documents remain invalid for merge forms. YAML byte-offset and projection-freeze work, every high-cardinality root/package/domain/resource/blueprint extraction scan, secret-range collection, ordering, and snapshot construction share the operation budget and poll cooperatively. Sorted immutable public-summary arrays by type and an exact private resource-key index are built during the already-charged snapshot traversal, so list performs only a bounded frozen slice and get performs an exact lookup.

Resource source output is produced only after all retained !secret scalar byte ranges are masked, followed by complete-file exact and heuristic redaction. Exact unredacted SHA-256 may be returned, but raw secret names and values may not. Identity/digest/freshness checks surround graph work and output. Errors expose stable codes without YAML or filesystem context. The service remains unregistered and cannot access a live configuration mount.
