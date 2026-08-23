# Security Policy

Airlock is a security tool, so a vulnerability in it can quietly remove the
protection someone is relying on. We take reports seriously and want to make
them easy.

## Supported versions

Airlock is pre-1.0 and moving quickly. Only the latest released version on PyPI
(and `main`) receives security fixes. Please reproduce against the latest
version before reporting.

## Reporting a vulnerability

**Report privately through GitHub Security Advisories — do not open a public
issue for a security bug.**

1. Go to <https://github.com/airlock-agent/airlock/security/advisories>.
2. Click **Report a vulnerability**.
3. Describe the issue with enough detail to reproduce it: version, OS, Python
   version, policy/profile in use, and a minimal set of steps or a proof of
   concept.

This channel is private between you and the maintainers until a fix is ready.
If you cannot use GitHub Advisories, open a public issue titled "security
contact request" (with **no** vulnerability details) and we will arrange a
private channel.

## What to expect

- **Acknowledgement:** within 3 business days.
- **Triage and initial assessment:** within 7 business days.
- **Fix / disclosure:** we aim to release a fix and a coordinated advisory
  within 90 days, and usually much sooner. We will keep you updated and credit
  you in the advisory unless you ask us not to.

## Scope

In scope — anything that lets a call bypass the gate, corrupts or forges the
audit log, defeats the tamper-evidence, escalates privilege beyond the active
policy, or makes `init`/`uninstall` damage a user's configuration.

Out of scope — the documented limits in the README (Airlock does not stop prompt
injection itself, egress is argument-level, an agent with a shell can start a
server outside the proxy). These are known boundaries, not vulnerabilities; a
report that *widens* one of them into a concrete bypass is in scope.

Thank you for helping keep Airlock's users safe.
