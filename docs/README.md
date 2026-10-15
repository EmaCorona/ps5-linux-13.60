# Documentation

Everything here is written as **evidence**: the command, the raw output, the reading, and what it
does or does not prove. A claim in this repository should be re-checkable from these files rather
than taken on trust.

| document | what it is | read it when |
| --- | --- | --- |
| [`1360-port-status.md`](1360-port-status.md) | chronological record of the 13.60 work: what was tried, what the console did, what was concluded | you want the full history, including the dead ends |
| [`1360-offsets-from-dump.md`](1360-offsets-from-dump.md) | how the 13.60 offsets were derived from a verified kernel capture and validated against the live console | you doubt a value in `off_1360.c` |
| [`1360-khook-death.md`](1360-khook-death.md) | why the armed khook kills this console: signature, single-variable bisection, mechanism | you are touching the escape or the khook |
| [`analyst-recap-1360.md`](analyst-recap-1360.md) | handoff summary: routes tested, values derived, raw evidence, open questions | you are picking the project up cold |
| [`upstream-ps5-linux-loader-README.md`](upstream-ps5-linux-loader-README.md) | the upstream project's README, kept for reference | you need the upstream installation flow |

## Conventions used in these files

- Values are **ktext-relative** unless stated otherwise, and are quoted to the precision they were
  measured at.
- Measurements name the firmware (`13.60.0007`), the console kind (regular / pro) and the tool that
  produced them.
- A negative result is recorded as one: "closed" or "refuted" is more useful than silence.
- Where a claim is an inference rather than a measurement, it says so.
