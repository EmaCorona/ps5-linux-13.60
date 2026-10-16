# Documentation

Everything here is written as **evidence**: the command, the raw output, the reading, and what it
does or does not prove. A claim in this repository should be re-checkable from these files rather
than taken on trust.

## Where the current status lives

**One source for the current status:** the root [`README.md`](../README.md) support table and its
*Known limitations* list. The files below are the **investigation record** — they are kept as they
were written, day by day, and a statement in them describes the state at the time of writing, not
necessarily today. When a chronology file and the root README disagree, the root README is the
current statement and the chronology is history.

The three blockers that currently define the 13.60 work, in one line each:

1. the armed global `#DB` hook can route unrelated traps into a chain built for another context;
2. the payload process is not observed to survive standby/resume, so the post-resume takeover
   cannot assume userland continuity;
3. `HV_VMMCALL_HANDLER_PA` for 13.60 is unknown; the guest-side `VMMCALL` wrapper is a different
   entity and must not be substituted for it.

| document | what it is | read it when |
| --- | --- | --- |
| [`BASELINE_1360.md`](BASELINE_1360.md) | frozen initial state of this branch: revision, toolchain, CI coverage, verifier results **before** any change | you need to know what the starting point was, or reproduce a before/after |
| [`TOOLCHAIN.md`](TOOLCHAIN.md) | the two build inputs, the shim chain that decides which compiler actually runs, and the pins (SDK, pLabs5-SDK commit + checksum, base image) | you are changing the build, or a build differs between machines |
| [`BUILD.md`](BUILD.md) | every make target, every build flag, and how a flag change invalidates objects | you run a build or wonder why a flag "did nothing" |
| [`OFFSETS-REGISTRY.md`](OFFSETS-REGISTRY.md) | the typed registry: namespace, evidence class and provenance per offset field, and the checks that enforce them | you are about to use an address, or doubt one |
| [`BOOT-REQUIREMENTS-1360.md`](BOOT-REQUIREMENTS-1360.md) | per unresolved field, the call site and what its absence actually blocks | a zero looks like a blocker, or you are about to fill one |
| [`LIVE-READ-POLICY.md`](LIVE-READ-POLICY.md) | what a live payload may read, where the decision lives, and why `.text` on 13.60 is refused unconditionally | you are touching a live-read tool, or reading an old "next step" |
| [`SOURCE-MAP.md`](SOURCE-MAP.md) | what is live code, what is vendored, what is generated, what is history — and which artifacts are known dead | you are new to the tree, or a file looks canonical but might not be |
| [`THIRD-PARTY.md`](THIRD-PARTY.md) | licence inventory: project, vendored Byepervisor files, the adapted ps5-linux-loader boot path, and the open questions | you are redistributing, or wondering why two AGPL notices differ |
| [`1360-khook-design.md`](1360-khook-design.md) | the armed `#DB` hook: invariants, state model, foreign-trap handling, and the static gate before the next console session | you are about to arm the hook |
| [`1360-post-resume-contract.md`](1360-post-resume-contract.md) | who owns control before/during/after standby, and why nothing may depend on a live payload process | you are touching the resume path or planning a sleep test |
| [`1360-port-status.md`](1360-port-status.md) | chronological record of the 13.60 work: what was tried, what the console did, what was concluded | you want the full history, including the dead ends |
| [`1360-offsets-from-dump.md`](1360-offsets-from-dump.md) | how the 13.60 offsets were derived from a verified kernel capture and validated against the live console | you doubt a value in `off_1360.c` |
| [`1360-khook-death.md`](1360-khook-death.md) | why the armed khook kills this console: signature, single-variable bisection, mechanism | you are touching the escape or the khook |
| [`1360-hv-pas-offline-verdict.md`](1360-hv-pas-offline-verdict.md) | the negative result for the 13.60 hypervisor physical addresses: what was examined and why no value can be claimed | you are tempted to fill `HV_VMMCALL_HANDLER_PA` / `HV_CODE_CAVE_PA` / `HV_HANDLE_VMEXIT_PA` |
| [`analyst-recap-1360.md`](analyst-recap-1360.md) | handoff summary: routes tested, values derived, raw evidence, open questions | you are picking the project up cold |
| [`upstream-ps5-linux-loader-README.md`](upstream-ps5-linux-loader-README.md) | the upstream project's README, kept as a verbatim reference copy | you need the upstream installation flow |

## Conventions used in these files

- Values are **ktext-relative** unless stated otherwise, and are quoted to the precision they were
  measured at.
- Measurements name the firmware (`13.60.0007`), the console kind (regular / pro) and the tool that
  produced them.
- A negative result is recorded as one: "closed" or "refuted" is more useful than silence.
- Where a claim is an inference rather than a measurement, it says so.
- Classifications used for offset fields (`KNOWN_STATIC`, `KNOWN_HARDWARE_VALIDATED`, `UNKNOWN`,
  `NOT_REQUIRED_FOR_1360_PATH`) are defined in the header of [`../source/offsets/off_1360.c`](../source/offsets/off_1360.c).

## Checking the offline claims

The verifiers and their host test suite are described in [`../tests/README.md`](../tests/README.md).
They run without the PS5 SDK and without a console.

`tools/check_payload_static.py` checks a **built** payload — ELF identity, the manifest version, that
phase B is compiled out, that the generated blobs are the ones embedded, and that the takeover blob's
firmware is one we have provenance for. The CI build job runs it and publishes its report next to the
artifact.
