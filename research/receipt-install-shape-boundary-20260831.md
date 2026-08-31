# Receipt availability across install shapes

_Investigation, 2026-08-31. Status: relaxation **rejected** by security review;
the project-local requirement stands. Recorded so a future attempt starts from
the review's findings rather than repeating them._

## Problem

Bearer-handle exact-slice retrieval of large Bash output is ContextGuard's most
differentiated feature. Native agent compaction is lossy by design; retrieving
*these exact bytes* from a local store is something a summariser cannot do.

It is unavailable on almost every way ContextGuard is installed.

`discover_adapter()` requires the running policy file to be a regular descendant
of the guarded project root at
`<project>/node_modules/@ictechgy/context-guard/…`. Every other shape returns
`receipt_source_or_plugin_only` and falls back to legacy trimming:

| Install shape | Receipt available |
| --- | --- |
| `npm install --save-exact` into the project | yes |
| `npm install -g` | no |
| `npx` | no |
| Homebrew (`ictechgy/tap/context-guard`) | no |
| Claude Code marketplace plugin | no |
| source checkout | no |

The README documents the requirement, so this is not a hidden defect. But the
plugin path is the front door — the README's own TL;DR sends Claude Code users
to `/plugin install` — and that path cannot reach the feature at all.

Two smaller findings on the same surface:

- `receipt_source_or_plugin_only` appears **only** in the policy source. It is
  in no test and no document. The rejection path is unverified, and a user who
  hits it gets an opaque reason code with no remedy — the same class of problem
  as the `active_3e` incident that motivated the zero-command-authority work.
- Because the fallback is silent and successful, a user cannot tell whether they
  are getting exact-slice retrieval or legacy trimming.

## What the current boundary actually buys

An earlier revision of this document claimed the project-local requirement
supplies only *consent*, not containment, and proposed replacing co-location
with a project-owned consent file naming an exact Receipt version. **Security
review rejected that reading, and the proposal with it.** The reasoning is
recorded here because the correct design has to start from it.

### Why "consent, not containment" was wrong

`EXPECTED_RECEIPT_PACKAGE_FILES_SHA256_BY_VERSION` lives in the *running*
installation. Under the rejected proposal the candidate package, the digest
table that verifies it, and the interpreter that runs it are all the same
artifact. That is self-attestation:

> A compromised update channel — tap, npm account, or marketplace — ships a
> table mapping `0.4.0` to a new digest together with a `0.4.0`-labelled package
> matching it. Every proposed check passes. The version string the project
> consented to never changed, and every consenting project flips to
> attacker-controlled Receipt code on the next launch.

Co-location does not have that failure. The bytes under `node_modules` are
anchored by the registry `integrity` value in the project's lockfile — a root of
trust **outside** the running code. A channel compromise does not reach a
project that has not reinstalled. That is containment, and the earlier reading
missed it.

Co-location also pins the *whole pipeline* per project, not just the Receipt
subpackage. Capture, sanitization, redaction and handle issuance are what
actually shape the bytes that reach the store; a version-naming file pins none
of them.

### The clone-propagation attack

A consent file is a repository artifact. A maintainer commits it; a victim
clones the repository, opens it, and Receipt activates — capturing the
*victim's* Bash output into a local store whose bearer handles enter the
transcript. The party that consented is not the party that bears the risk.

`npm install` does not have this property: cloning installs nothing, and
installing is a deliberate, visible, per-user act that produces a lockfile diff.
A committed dotfile travels without any act by the person it binds. It is also
one quiet write for an agent to author or rewrite, and — since setup would write
it — the tool could end up consenting on the user's behalf.

The mechanism is a version pin. It is not consent, and it should not be named
consent.

### Requirements a correct design must meet

Not attempted here; recorded so the next attempt starts in the right place.

1. **Consent must name content, not a label.** The expected package digest
   belongs in the project-owned record, so a floating table cannot redefine a
   version underneath it.
2. **A user-level acknowledgement keyed to project identity**, in the
   workspace-trust style, so a cloned repository cannot activate capture for a
   user who never approved that project.
3. **State what is pinned** — the Receipt subpackage alone, or the whole
   pipeline — and accept that failure mode knowingly. Vendored-and-moving-together
   means every upgrade fail-closes consenting projects into legacy trimming until
   a human bumps the record, which predictably breeds an `--update-consent`
   convenience flag that restores the float.
4. **Ephemeral install shapes stay excluded.** The rejected proposal would have
   made `npx` Receipt-capable for the first time; the npx cache is
   user-writable, ephemeral, and floats. A typosquatted invocation would derive
   its own location, verify against its own table, and honour the recorded
   version faithfully.
5. **Resolve before rejecting symlinks.** Homebrew prefixes, npm bin shims and
   npx caches are symlink-heavy. Applying a no-symlinked-component rule before
   full resolution rejects legitimate installations — an availability bug.
6. **Re-verify relative to use.** Homebrew and `npm update -g` can replace files
   after a discovery-time check; a per-session verification is a TOCTOU on the
   whole check.
7. **Journal what actually ran.** Record the verifying installation's resolved
   path, version and digest into the state directory at activation, so there is
   a forensic record of which code handled a project's captured output.

Until those are designed, the project-local requirement stands.

## Ship first, independently of the above

These stand whether or not the boundary is ever relaxed. The earlier revision
called them risk-free; review disagreed, and the corrected framing is below.

1. **Test the rejection path.** `receipt_source_or_plugin_only` appears only in
   the policy source — in no test and no document. This *does* carry a security
   argument, contrary to the earlier claim: an untested fail-closed path rots,
   and an inverted condition would ship invisibly. Pin the global-shaped,
   plugin-shaped and source-checkout layouts, and pin *why* each fails, so a
   refactor that fails for the wrong reason does not pass.

2. **Report which mode is active** — deferred to its own change, because
   `doctor` lives in `context_guard_commands.py` and `setup_wizard.py`, both
   Gate-B component paths, so it requires a re-blessing generation. Two review
   findings constrain that work:

   - **`doctor` must call the same discovery entry point** as the runtime. A
     reimplemented detector that drifts produces a false "available", and users
     treat `doctor` as ground truth. A contract test must assert equivalence.
   - **Remedy text is agent-readable.** In Claude Code the agent consumes tool
     output, so "install `@ictechgy/context-guard@x.y.z` into the project" is an
     instruction an eager or injected agent may simply execute — performing the
     very authorization act that matters as a side effect of a diagnostic.
     Remedies must be written for the human, and kept out of agent-visible
     output or gated behind an interactive confirmation.

   A first-activation notice belongs with it: a user who believed nothing was
   retained should be told the first time capture starts.

## Verification

- Existing project-local discovery tests must pass unchanged.
- New: consent file absent → non-project package rejected.
- New: consent version mismatched with the discovered package → rejected.
- New: consent version without an audited digest → rejected.
- New: package path containing a symlinked component → rejected.
- New: a package inside the project reached through the consent path → rejected
  (the modes stay disjoint).
- New: the three rejection shapes above pin `receipt_source_or_plugin_only`.
- `doctor` reports availability and reason; a contract test asserts the message
  names a remedy.

## The open question, answered

The earlier revision asked whether "the project names the version" is equivalent
in trust to "the project installs the version". It is not. Installing anchors the
bytes to the lockfile's registry integrity — a root of trust outside the running
code — and it requires a deliberate per-user act that cloning does not perform.
Naming a version supplies neither.
