Linux-only candidate validation assets live here and are never copied into the add-on image.

Run the Git candidate matrix from the Linux candidate container with only exact real
closure files (never loader or library symlinks):

```sh
pnpm validate:linux:git --
  --broker /app/native/git-broker
  --git /usr/bin/git
  --runtime-loader /lib/ld-musl-x86_64.so.1
  --runtime-input /usr/lib/libpcre2-8.so.0.14.0
  --runtime-input /usr/lib/libz.so.1.3.2
  --output /tmp/g2-git-results.ndjson
```

The amd64 command is development evidence only. Native aarch64 execution remains a
mandatory separate gate. The harness emits a required-row manifest, one NDJSON row
per mandatory case, and a summary; it exits nonzero if a row is missing or fails.

Run the persistence reliability matrix from a Linux container as root with a
dedicated tmpfs no larger than 128 MiB:

    pnpm validate:linux:persistence -- --cc cc --tmpfs-root /run/ha-g2-persistence --output /tmp/g2-persistence-results.ndjson

The tmpfs row deliberately fills and then cleans only the supplied bounded tmpfs.
The harness compiles its inert fault shim and syscall probe at runtime; neither is
copied into the add-on image.
