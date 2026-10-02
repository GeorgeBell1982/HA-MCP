Linux-only candidate validation assets live here and are never copied into the add-on image.

Run the Git candidate matrix from the Linux candidate container with only exact real
closure files (never loader or library symlinks):

```sh
pnpm validate:linux:git \
  --broker /app/native/git-broker \
  --git /usr/bin/git \
  --runtime-loader /lib/ld-musl-x86_64.so.1 \
  --runtime-input /usr/lib/libpcre2-8.so.0.14.0 \
  --runtime-input /usr/lib/libz.so.1.3.1 \
  --output /tmp/g2-git-results.ndjson
```

The amd64 command is development evidence only. Native aarch64 execution remains a
mandatory separate gate. The harness emits a required-row manifest, one NDJSON row
per mandatory case, and a summary; it exits nonzero if a row is missing or fails.

Run the native-runner provenance gate only after the G2-001 human approval for the
specific aarch64 runner and evidence collection:

```sh
pnpm validate:native:aarch64 \
  --runner-identity 'runner-attestation:sha256:<externally-recorded-digest>' \
  --output /tmp/g2-native-aarch64-provenance.ndjson
```

The runner identity is recorded as self-attested. A passing in-guest harness rejects
non-aarch64 state, detected QEMU/TCG or arm64 binfmt translation, and a non-arm64
Docker server, but it cannot prove that the whole machine is not emulated. G2-016
and G2-020 remain blocked until external immutable runner provenance accompanies
the native output and the separately frozen arm64 candidate-image evidence.

Run the candidate-image matrix from the host with Docker access. The caller must
pass the exact no-follow runtime closure for the image architecture:

```sh
pnpm validate:candidate:image \
  --image ha-engineering-mcp:g2-amd64-candidate \
  --expected-image-id sha256:e71aec0b2b6d8b76bbeb751b1b0623325509d9665f62c6ebff885f995ae4dc03 \
  --expected-architecture amd64 \
  --expect-no-labels true \
  --runtime-loader /lib/ld-musl-x86_64.so.1 \
  --runtime-input /usr/lib/libpcre2-8.so.0.14.0 \
  --runtime-input /usr/lib/libz.so.1.3.1 \
  --expected-sha256 /app/native/git-broker=sha256:01823637f02c49e685f84a2b371870945299e772b6dc37dbf9194b2f34f051f8 \
  --expected-sha256 /app/native/openat2-list=sha256:6fe9587146b927b6f84c53a3d61efd87e6143c9ee95268b9c997d464260bab51 \
  --expected-sha256 /app/native/openat2-read=sha256:59faab9a79575409e59b3672cb1ecb50a9f3b3a7d0db85f1065d499a3c7c425f \
  --expected-sha256 /usr/bin/git=sha256:5b5cbd6facf5d86226063d69fe57064bc5ad79bdccee2af0ac787646c564a880 \
  --expected-sha256 /lib/ld-musl-x86_64.so.1=sha256:7d221f4e17e8f7ebfc208d6e621bb7fc71bc99081bed47409d77048d9a69dbd5 \
  --expected-sha256 /usr/lib/libpcre2-8.so.0.14.0=sha256:0eae946d1f2746b6c64cc8beb9230360dc935e8552f89b765c7e697bff232345 \
  --expected-sha256 /usr/lib/libz.so.1.3.1=sha256:09b1bbd6ffe274039cefaca595f55cec0af65fe90d9e285e5d57ff7ed96948d2 \
  --expected-startup-status 127 \
  --expected-startup-signal null \
  --expected-startup-timed-out false \
  --output /tmp/g2-candidate-image-results.ndjson
```

Run the persistence reliability matrix from a Linux container as root with a
dedicated tmpfs no larger than 128 MiB:

    pnpm validate:linux:persistence -- --cc cc --tmpfs-root /run/ha-g2-persistence --output /tmp/g2-persistence-results.ndjson

The tmpfs row deliberately fills and then cleans only the supplied bounded tmpfs.
The harness compiles its inert fault shim and syscall probe at runtime; neither is
copied into the add-on image.

Run the isolated Phase 3 workflow proof of concept only as an unprivileged Linux
user with equal real and effective UIDs, Node 22 through 24, `cc`, `readelf`, and
`libcrypto.so.3` available:

```sh
pnpm validate:linux:phase3-poc -- --ack-disposable-phase3-poc
```

The acknowledgement is exact and the POC accepts no paths or retention option. It
builds the normal repository `dist`, then creates private disposable state directly
under canonical `/tmp` or `/var/tmp`, compiles and pins the three checked-in native
helpers, and exercises success, rollback, and process-death recovery through the
real inert Phase 3 components. The only fakes are the trusted verification probe,
the reload catalog/service recorder, and the schema-limited domain-reload proposal
fixture. It makes no Home Assistant, Supervisor, or network call.

Evidence is manifest-first ordered JSONL with one mandatory cleanup row and exactly
one summary. The SIGKILL row proves process death after a committed native helper
result; it is not power-loss, production, or Home Assistant evidence. A topology,
mount, identity, pending-artifact, substitution, or helper-absence uncertainty
causes `cleanup_unproved`, preserves the workspace, and prevents a passing summary.
Path cleanup cannot defeat a hostile same-UID transient swap-and-restore attack, so
this disposable POC makes no production claim.

The real HA workflow supports both pinned Core `2026.9.4` architectures. Default
execution remains the amd64 development fixture. Native ARM execution requires a
Linux/arm64 Node process, an arm64 Docker daemon, the pinned official ARM Core
image already present, and an explicitly supplied immutable arm64 builder ID:

```sh
node scripts/linux/phase3-ha-boundary-smoke.mjs --ack-disposable-ha-boundary-smoke --full-workflow --native-arm64-builder sha256:<64-lowercase-hex-image-id>
```

Prepare the disposable builder with Node, GCC/musl/Linux headers, libcrypto and
`/build/native`, with dependencies at `/build/node_modules` and no existing
`/app/node_modules`. The runner's working directory must contain built `dist`,
the harness scripts, three native C sources and `addon/phase3-operator.sh`.
The runner needs Docker access and access to the fixture's published loopback port.
A containerized runner may use host networking and a Docker socket solely for
the nonce-owned fixtures; this grants daemon control and must be restricted to
the reviewed harness. Child workers receive no socket or live mounts/credentials.
The three named fixture containers are capped at two CPUs, 1536 MiB/no additional
swap and 256 PIDs each. All 24 acceptance rows and affirmative cleanup are required.
Terminal confirmation is automated disposable evidence, not a human approval of
production changes. Architecture checks do not replace external host provenance.
