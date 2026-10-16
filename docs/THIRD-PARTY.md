# Third-party components and licences

What this repository distributes, where it came from, and under which terms. The rule is that an
imported file keeps **its own** notice: notices are never rewritten to look uniform.

## This project

| item | value | where |
| --- | --- | --- |
| project licence | **AGPL-3.0-only** | [`../LICENSE`](../LICENSE) (AGPL v3 text), stated in [`../README.md`](../README.md) |
| SPDX headers in first-party sources | `AGPL-3.0-only` where present | e.g. `tools/pl5-offsets.c` |

## Components derived from other projects

| component | origin | upstream licence | what we did |
| --- | --- | --- | --- |
| `source/byepervisor/khook.c`, `include/byepervisor/khook.h` | [Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn) | notices in the files say **AGPL-3.0-or-later** | vendored; the original header is kept verbatim |
| `source/byepervisor/kdlsym.{c,h}` | same | **AGPL-3.0-or-later** (file notice) | vendored and adapted; notice kept |
| `source/byepervisor/paging.{c,h}` | same | **AGPL-3.0-or-later** (file notice) | vendored and adapted; notice kept |
| boot path (`source/boot/`, `source/shellcode/`, boot-related headers) | [ps5-linux-loader](https://github.com/ps5-linux/ps5-linux-loader) | **GPL-3.0** (GitHub reports `GPL-3.0` for that repository) | adapted to the Byepervisor high-firmware vector |
| `docs/upstream-ps5-linux-loader-README.md` | ps5-linux-loader | **GPL-3.0** | verbatim reference copy of the upstream README |

## The AGPL-3.0-only / AGPL-3.0-or-later difference is intentional

The project declares **only**; the vendored Byepervisor files declare **or-later**, as their upstream
authors wrote them. Both are recorded here rather than harmonised:

- rewriting "or-later" to "only" in a vendored file would narrow a licence the authors granted us;
- rewriting the project's "only" to "or-later" would widen what we grant downstream.

`GPL-3.0` for the boot path and `AGPL-3.0` for this project are compatible in the direction that
matters here (AGPL-3.0 satisfies GPL-3.0's terms for the combined work, and the AGPL's network clause
is the stricter one). Whether every individual upstream file's terms are correctly represented is a
question for the project owner, not something this file decides.

## Residual unknowns (recorded, not resolved)

| question | state |
| --- | --- |
| Byepervisor-Reborn's repository-level licence | GitHub's licence API returns **404** for that repository (no detectable licence file), while the vendored file headers state AGPL-3.0-or-later. The file notices are the evidence we have; the upstream repository has none to point at. If the upstream project publishes one later, this table should be updated. |
| provenance of `docs/upstream-ps5-linux-loader-README.md` | it is a copy of the upstream README as of the copy date; the copy date is not recorded in the file itself. Its content is not maintained here. |
| individual authorship of adapted boot-path files | the files carry the project's SPDX line; where a function is a direct adaptation of upstream code this is noted in the file's comment, but there is no per-function attribution list. |

## How this is kept honest

- `docs/SOURCE-MAP.md` marks which files are vendored, so a change to one is recognisable as a
  change to upstream-derived code.
- The vendored headers are not edited for style; adapting them means adding a note, not removing
  their original text.
- Nothing in this repository claims a licence on behalf of an upstream project.
