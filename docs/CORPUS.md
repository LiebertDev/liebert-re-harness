# Working with samples

This repository contains **no third-party binaries**, and pull requests that add
them will be declined. This page explains why, and how a write-up refers to a
sample instead.

## Why no binaries

Three reasons, in order of how often they bite:

1. **We have no right to redistribute most of them.** A crackme is someone's
   work, released on their terms and often from their own page; a commercial
   binary is nobody's to re-host. Referencing a file by hash leaves the author's
   distribution terms as the only ones that apply to it.
2. **A repository that accumulates binaries becomes unusable.** Clones get large,
   history gets permanent, and a file committed once is committed forever.
3. **Scanners.** A repository full of packed executables and driver samples gets
   flagged, quarantined, and sometimes taken down — on your machine, in CI, and on
   the hosting side. Contributors then cannot clone it.

## How a write-up identifies its sample

Every analysis document starts with a provenance block, so a reader can verify
they are looking at exactly the file the author looked at:

```yaml
sample:
  name:        <file name as distributed>
  sha256:      <64 hex digits of the file you analysed>
  size:        <bytes>
  source:      <URL where the author published it>
  author:      <original author>
  license:     as stated by the author on that page
  retrieved:   <YYYY-MM-DD>
```

A block is filled from the real file, never from an example. (An earlier version of
this page carried a placeholder whose hash was that of an empty file; it would have
matched a zero-byte download and nothing else.)

## Samples this project has used

These are **citations, not distribution.** The binaries are not in this repository
and this project holds no right to redistribute them; the author's terms are the
only terms that apply. Fetch them from the author's own distribution.

### IOLI crackme set v1.2 (public crackmes)

- author: **pof**. `samples/ioli/README.txt` is headed "IOLI CRACKME v1.2 by pof";
  its goal line is "Crack the executable files to accept any password".
- source: that README gives no URL or licence for the set itself (its only links are
  to tools). The original page is therefore **not recorded here**; do not treat any
  address as the verified origin. Add it when the author's own page is confirmed.
- license: not stated in the README; treat as the author's terms, not redistributable here.
- retrieved: not recorded. The local tarball file was written 2026-10-05.
- hashes below were computed from the local copies under `samples/ioli/`.

| file (under `samples/`) | sha256 | size (bytes) |
|---|---|---|
| `ioli/bin-win32/crackme0x00.exe` | `3f590f6c1eaa59952a6dc201f370f8dda48003d6fabdabd53277a9872737ce6a` | 24440 |
| `ioli/bin-win32/crackme0x01.exe` | `4c5940421bfb5e649d5801789088dbc3109658f4481e8d2a5f0b0429ce3a215d` | 24264 |
| `ioli/bin-win32/crackme0x02.exe` | `adc5e56538368cf7813741c802a128a247191276cf8cfff9ada0aa06d83a7bfa` | 24264 |
| `ioli/bin-win32/crackme0x03.exe` | `4d9095e312d3a05cdbec167aba25468c183966f0db46c40e31a19a99720e5851` | 24318 |
| `ioli/bin-win32/crackme0x04.exe` | `7b98258260d69da393708d846dc59b4769dda38a49f92a9bf42c302b97299220` | 24650 |
| `ioli/bin-win32/crackme0x05.exe` | `d3aa82993024762f4d5740c1647230ac692714a581173dd85d96b6eff41f955a` | 24668 |
| `ioli/bin-win32/crackme0x06.exe` | `b9cf677350aadc5119806d807c91d9297d604345862e869160bd3e1c29aac3b6` | 24863 |
| `ioli/bin-win32/crackme0x07.exe` | `8b5f564017e5ca8a5652c3fa41072057adab514d5550f76b73d0ef4c6fba3290` | 12288 |
| `ioli/bin-win32/crackme0x08.exe` | `6d7f11fa470fa23f08bcd1856d9d90a401e6707c95feede57923b221fe7f6b77` | 25411 |
| `ioli/bin-win32/crackme0x09.exe` | `915da9cefe4d4729621c5893cd279d796d4f531b55f992cc0296c6ba7c51d1c4` | 12288 |
| `ioli/bin-linux/crackme0x00` | `3aed9a3821134a2ab1d69cb455e5e9d80bb651a1c97af04cdba4f3bb0adaa37b` | 7537 |
| `ioli/bin-linux/crackme0x01` | `081c706bb2ec4b3556409990abe5d443f25be39bcc79dc9303d52e55a52c846e` | 7499 |
| `ioli/bin-linux/crackme0x02` | `90ec4d354b34bbb4369aa1c5023d4773b84f7ce5ed32e2504d8dc81beae444d9` | 7499 |
| `ioli/bin-linux/crackme0x03` | `8700fb75d437186af3ba1b1042d9ccec7eec71c1d0e3464ac16b74f0e3835d19` | 7580 |
| `ioli/bin-linux/crackme0x04` | `e76a675caadef4d148866d063000eb0252528792d658cb270bcd1ea287f17261` | 7633 |
| `ioli/bin-linux/crackme0x05` | `65c61e5dfd016ef273b2735aba13078c40172f5787d981bffa43438a493670a3` | 7656 |
| `ioli/bin-linux/crackme0x06` | `4608b28e4df8b0e9769b454702d105cc07441c326554d5c37c996b0b517e4a7f` | 7717 |
| `ioli/bin-linux/crackme0x07` | `eff7dff758b8b0234f2a1d5d413df7bb1ea30834e79d8cea1a4f0a2cd20a25f6` | 5860 |
| `ioli/bin-linux/crackme0x08` | `b92b792ad1804692f01d6f281969aa479182f072bee7d2c2cb24ef2ddcca259e` | 7757 |
| `ioli/bin-linux/crackme0x09` | `29a8336b5c3695edfbaccf338cfcc7d9874c2ca455a7c2547268508254cc5145` | 5860 |
| `ioli/bin-pocketPC/crackme0x00.arm.exe` | `86dc4b8f9043d568c2ba8fb84a73ed1fbf88a6a7166669a4d7f951064cff8a66` | 11655 |
| `ioli/bin-pocketPC/crackme0x01.arm.exe` | `bfa49f27996fc29b1e73f1aec8a798b502b8e07b14744b77a542f2c7740baa3f` | 11480 |
| `ioli/bin-pocketPC/crackme0x02.arm.exe` | `18ef1696cb2f9453dad74055025b9b9e33909ae451a12865f0803ef523dfc122` | 11480 |
| `ioli/bin-pocketPC/crackme0x03.arm.exe` | `604c15e83019d404d7c82f7b990a64d3dcab73c8c5bd4292e2ebc20bfeb68060` | 11534 |
| `ioli/bin-pocketPC/crackme0x04.arm.exe` | `47d6e03a6c414849eea23a993cecad338aa22a6c6f38cb37f2fc9fa7bb4fd04d` | 11691 |
| `ioli/bin-pocketPC/crackme0x05.arm.exe` | `e8b9faa46896e2955d2750e64570d55ea3e793059c466cf3c2296ff8c4bb1057` | 11709 |
| `ioli/bin-pocketPC/crackme0x06.arm.exe` | `985c20411bcfc013ee9dac96f713a6508c3e39faf46e4efd77cc86a002ab6626` | 12927 |
| `ioli/bin-pocketPC/crackme0x07.arm.exe` | `3ec64e8437f1d2079bd9ba46dd8833c82ad2979189beb45e26aeb029a12b98fd` | 5632 |
| `ioli/bin-pocketPC/crackme0x08.arm.exe` | `0fc1a5dd5bd3875476d226f5b10064a032e0771af75a1e9e2d74ada797678b9c` | 12963 |
| `ioli/bin-pocketPC/crackme0x09.arm.exe` | `014e9ee9a2e933aed0939da6debd5728dee7408cb7a40fda777f0f4b019d222b` | 5632 |
| `ioli/IOLI-crackme.tar.gz` | `b5c3ab7ba5450d0eb7c7f625a79caa5a42b25ff18dec3aa8c0ffbd39091d4745` | 90937 |

### Not recorded: `samples/kernel_adhoc/*.sys`

The provenance block is for a third-party sample whose author or publisher states
terms. The `.sys` files there (`beep`, `fltmgr`, `ksecdd`, `mup`, `null`, `rdbss`,
`tcpip`) are Windows operating-system drivers: they have no challenge author, no
publication page and no licence page to cite, and they differ per Windows build, so a
hash would identify one installed build and nothing more. They are local ad-hoc
inputs for kernel-level work (`CASE_POLICY.md` section 5), not corpus entries, and
no entries are invented for them. They are still never committed (`samples/` is
gitignored).

If the hash of your copy does not match, **stop and say so** rather than assuming
the write-up applies. Different builds of the same challenge are common, and
almost every address in an analysis is build-specific. A mismatch is a finding,
not an inconvenience — several of this project's own dead ends were exactly that.

## Where to put samples locally

Put them in `samples/` or `corpus/`. Both are in `.gitignore`, along with the
usual executable extensions, specifically so that a file fetched for local work
cannot be committed by accident. Do not "fix" that by force-adding.

## Fixtures for tests

Tests must not depend on a file the contributor has to download. Build fixtures
programmatically instead — emit the smallest PE, ELF, or archive that exercises
the code path, from a helper in the test suite. This keeps the suite runnable on
a clean checkout, makes the fixture's intent readable in the diff, and lets a
reviewer see precisely which malformed field a parser test is about.

When a real sample is genuinely irreplaceable for a regression test, commit a
**minimised, redacted excerpt** — the specific structure under test, not the
whole file — and document in the test what was cut and why.

## Challenge authors' rules

Crackmes usually come with rules: no patching, keygen only, a required proof of
solution. **Those rules define what counts as solving it.** A patched binary is
not a solution to a keygen-only challenge, and presenting it as one is not a
contribution we will merge. Credit the author, link the original page, and if the
author asks that solutions not be published, respect that — link your write-up
somewhere else, or write about the technique without handing over the answer.
