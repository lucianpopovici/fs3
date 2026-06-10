# CLAUDE.md — package signing / DSM trust level

**Problem:** the SPK is unsigned. On install, DSM warns that the
publisher can't be verified, and the user must lower the trust level
(Package Center → Settings → Trust Level → "Any publisher") before DSM
will install it.

**Why it matters here specifically:** it's a friction-and-trust issue,
not a correctness one. For personal use it's a one-time checkbox. If the
package were ever distributed to others, the scary warning hurts
adoption and trains users to lower security settings — which is itself
bad hygiene.

## Current state

`packaging/synology/build-spk.sh` produces a plain tar SPK with `INFO`,
`package.tgz`, scripts, conf, icons. No signature. `INFO` includes a
`checksum` of `package.tgz` (integrity, not authenticity).

## Reality check

Synology **deprecated the old third-party keyring/code-sign mechanism**
for SPKs (confirmed in the DSM 7 developer guide: "we have deprecated the
codesign mechanism of spk"). So the historical "sign with your GPG key
and have users add your keyring" path is largely gone for side-loaded
packages. The practical landscape now:

1. **Packages from Synology's own catalog** are trusted automatically.
2. **SynoCommunity packages** are trusted if the user adds the
   SynoCommunity package source (which ships its keyring).
3. **Side-loaded SPKs** (manual install) trigger the trust-level prompt
   regardless — there isn't a clean self-signing path that removes the
   warning for an arbitrary third party anymore.

## Approach — pick the realistic one

1. **Accept it and document it (recommended for personal use).** A short
   README/wizard note: "DSM will warn the publisher is unverified; set
   Package Center → Settings → Trust Level to allow it. This is normal
   for self-built packages." One-time, honest, done. This is almost
   certainly the right answer for a homelab tool.

2. **Distribute via SynoCommunity (if wider distribution is ever the
   goal).** Package fs3 through the SynoCommunity `spksrc` framework and
   submit it; users who've added the SynoCommunity source then get it
   trusted. This is real work (conform to spksrc's cross-compile build
   system, their packaging conventions, review process) and only worth
   it if there's a distribution goal. The project's own framing is
   "homelab tool," so this is likely out of scope.

3. **Keep the `checksum` in INFO** (already present) so at least
   integrity is verifiable even though authenticity isn't.

## Hookpoints

- `README.md` and `packaging/synology/WIZARD_UIFILES/install_uifile` /
  `ui/index.cgi` — the trust-level note (option 1).
- `build-spk.sh` — already emits the checksum; nothing to add for
  option 1.
- A separate `spksrc`-based build tree — only for option 2, and largely
  outside this repo's build system.

## How to test

- Option 1: install on DSM, confirm the trust-level note matches what
  DSM actually prompts (the wording/menu path can shift between DSM
  versions — verify against the installed DSM).

## What "done" looks like

- For personal use: a clear, accurate note telling the user exactly which
  setting to change and that it's expected. Nothing more.
- For distribution (only if pursued): fs3 available through a package
  source whose keyring DSM trusts.

## Traps

- **Don't promise a self-signing path that removes the warning** — it
  doesn't exist for arbitrary side-loaded SPKs on current DSM. Claiming
  otherwise sends the next session chasing a deprecated mechanism.
- **Don't tell users to permanently run at the lowest trust level
  casually** without noting the tradeoff. The honest framing: lower it
  to install this, understand it also permits other unsigned packages.
- **Verify the exact menu path** against the DSM version in use — Synology
  moves these settings between releases.
