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
