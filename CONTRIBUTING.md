# Contributing to Airlock

Thanks for helping. Airlock is a security tool, so the bar for changes is a
little higher than usual — a regression here quietly removes protection someone
is relying on.

## Ground rules

- **Security issues do not go here.** Report them privately — see
  [`SECURITY.md`](SECURITY.md). Do not open a public issue or PR that describes a
  live bypass before it is fixed.
- **Every change ships with a test.** New behaviour gets a new check; a bug fix
  gets a regression test that fails before your change and passes after.
- **Be honest about coverage.** If Airlock doesn't fully do something, the README
  says so. Don't add a claim the code can't back up (see `THREATMODEL.md` and the
  "What is actually covered" table).

## Development

```bash
git clone https://github.com/airlock-agent/airlock && cd airlock
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[sign]"
python3 tests/run_all.py        # the whole suite; must be green before a PR
```

- Python 3.11+. The only runtime dependency is PyYAML (`cryptography` is optional,
  for `ed25519` signing).
- Tests are plain Python under `tests/`, run by `tests/run_all.py`. Add new suites
  to the `SUITES` list there.
- Tests must never touch the developer's desktop — the harness forces
  `AIRLOCK_NOTIFY=0` and a non-GUI ask backend. Keep it that way.

## Pull requests

1. Branch from `main`.
2. Keep the change focused; explain *what failed before* in the description.
3. Run `python3 tests/run_all.py` and `airlock scan .` (the repo's own docs trip
   indicators by design — that's expected).
4. Match the surrounding style: small functions, comments that explain *why*, and
   the failure a line prevents.

## Reporting non-security bugs

Open an issue with: your OS, Python version, the profile in use, and the smallest
steps that reproduce it. `airlock doctor` output helps.
