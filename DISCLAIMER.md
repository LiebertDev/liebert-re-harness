# Legal notice and responsible-use policy

Review this notice before using the repository.

## What this project is

Liebert Reverse Engineering Harness is software-analysis tooling: it parses executable files,
reconstructs their structure, disassembles and decodes parts of them, and
records what it measured together with the evidence for each claim. It is built
for people who analyse software they are permitted to analyse — security
researchers, capture-the-flag and crackme participants, malware analysts,
incident responders, developers auditing their own dependencies, and students
learning how binaries work.

Tooling of this kind is inherently dual-use. The same disassembler that helps an
engineer understand a crash also helps someone understand code they were never
authorised to touch. We publish it because the defensive and educational value is
real and because the techniques involved are long since public, and we ask users
to stay on the right side of that line.

## No warranty

This software is provided **"AS IS", without warranty or condition of any kind**,
express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose, title, and non-infringement.
See Section 7 of the [Apache License, Version 2.0](LICENSE) for the governing
text.

Binary analysis is imprecise by nature. Results can be incomplete or simply
wrong: obfuscated, packed, or self-modifying code routinely defeats static
reasoning, an emulator only approximates a real machine, and a heuristic that is
right on a thousand files can be wrong on yours. **Do not treat any output of
this toolkit as authoritative.** Verify anything that matters by an independent
method before you act on it, and never rely on it as the sole basis for a
security, safety, legal, or financial decision.

## Limitation of liability — you are responsible for what you do with this

To the maximum extent permitted by applicable law, **the authors, copyright
holders, and contributors accept no liability whatsoever** for any claim, damage,
loss, or other liability arising from or connected to this software or its use,
whether in contract, tort, or otherwise. This includes, without limitation, any
direct, indirect, incidental, special, exemplary, punitive, or consequential
damages; data loss or corruption; system instability or hardware damage; service
interruption; lost profits or goodwill; and any third-party claim. See Section 8
of the [LICENSE](LICENSE).

**We expressly disclaim responsibility for any unlawful, unauthorised, or
unethical use of this software.** You alone are accountable for your own conduct.
By using this project you confirm that:

1. You have the **legal right and the owner's authorisation** to analyse every
   file, system, or service you point this toolkit at. Ownership of a copy is not
   always authorisation, and authorisation for one system never extends to
   another.
2. You are solely responsible for complying with all laws and agreements that
   apply to you. Depending on your jurisdiction these may include computer-misuse
   and unauthorised-access statutes, copyright law and its anti-circumvention
   provisions (for example the DMCA in the United States or the EU Copyright
   Directive and its national implementations), trade-secret law, export-control
   rules, data-protection law, and the terms of service or licence agreements of
   the software you are examining. **Legal exemptions for research and
   interoperability exist in some jurisdictions and not in others, and they are
   narrower than people usually assume.** If your work might approach that line,
   get qualified legal advice for your situation — this document is not legal
   advice.
3. You accept **all** risk of running this software, including risk to the
   machine you run it on. Some analysis techniques are intrusive by design.
   Handle untrusted or hostile files in an isolated virtual machine or another
   disposable environment, never on a system you or anyone else depends on.
4. You will not use this project to harm other people — including breaking into
   systems you were not invited into, exfiltrating or exposing other people's
   data, degrading a service others rely on, or gaining an unfair advantage over
   other users of a shared system.

## Out of scope for this repository

Some contributions will be declined regardless of technical quality, because
publishing them would make this project a worse thing to exist. Specifically, we
do not accept:

- **Ready-to-use circumvention of licensing, activation, DRM, or anti-cheat
  protection** in real, currently distributed products. That includes patches,
  key generators, loaders, emulated licence servers, and step-by-step
  instructions for a named commercial product. Purpose-built crackme and CTF
  challenges written to be solved are welcome and are the intended home for this
  kind of work.
- **Findings, offsets, structures, or write-ups about a specific third party's
  protection mechanism** that have not been disclosed to that vendor and
  published by them or with their agreement. Coordinated disclosure comes first;
  a repository is not a disclosure channel.
- **Working exploits or weaponised payloads** aimed at software that is currently
  deployed and unpatched, and anything whose primary purpose is evading
  detection, defeating telemetry, or hiding from a defender.
- **Malware**, including droppers, loaders, and packers presented as utilities,
  and any sample that runs its payload rather than merely being parsed.
- **Third-party binaries or proprietary code** that we have no right to
  redistribute, and any credential, licence key, or token.
- **Automated mass scanning or targeting** of systems that are not yours.

If a contribution sits close to one of these lines, open an issue and describe
the intent before you write the code. We would much rather have that
conversation early than reject finished work.

## Reporting a problem

Security issues in this toolkit itself: see [SECURITY.md](SECURITY.md) — please
do not open a public issue for those.

If you believe something in this repository infringes your rights or should not
have been published, contact the maintainers through the channel listed in
[SECURITY.md](SECURITY.md) and say what and why. We will look at it promptly and
remove content where the objection is well founded; we would rather correct a
mistake than defend it.
