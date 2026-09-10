"""The benign read-only allowlist (`is_benign_command`) must never turn a call
that can chain, substitute, redirect, write a file, read an arbitrary path, run
code, or mutate host state into a silent `allow`. These cases were found by an
adversarial pass; they are locked in so a future edit to the predicate cannot
quietly reopen them. A blocked/asked verdict here is safe; an ALLOW is a bypass.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _harness import Suite

from airlock.policy import is_benign_command as ok

# Must be refused (predicate False) — every one is a real or attempted bypass.
DENY = [
    # chaining / substitution / redirection / pipe
    "git status; rm -rf /", "git status && cat /etc/shadow", "ls | bash",
    "ls $(cat /etc/passwd)", "ls `whoami`", "ls > /etc/cron.d/x", "echo x >> /a",
    # env-prefix / path-shadowing binaries
    "LD_PRELOAD=/tmp/e.so ls", "GIT_PAGER=touch ls", "./ls", "/tmp/ls", "../ls",
    # git flags that write / read-arbitrary / exec / reconfigure
    "git diff --no-index /etc/passwd /dev/null", "git diff --output=/tmp/x HEAD",
    "git diff --output /tmp/x", "git log --ext-diff", "git -c core.pager=x status",
    "git --git-dir=/other/.git status", "git diff --exec-path=/tmp",
    # arbitrary paths through otherwise-inert binaries
    "ls -R /home", "ls /etc", "df /etc", "cat /etc/shadow", "grep x /etc/passwd",
    "find / -name id_rsa",
    # host-state mutation via allowlisted binaries
    "date -s 2020-01-01", "date --set=2020-01-01", "hostname evil",
    "date --file=/etc/passwd", "date -f /etc/passwd", "date --file=secrets.txt",
    # attached short-option path (no space, no '='): -f/etc/passwd reads the file
    "date -f/etc/passwd", "date -f~/.aws/credentials", "ls -I/etc", "df -B/root",
    # code execution / read primitives
    "pytest -q", "python -c 'import os'", "make",
    # quote / whitespace evasion (shell strips quotes; \\v isn't an IFS split)
    'ls "/etc"', "ls '/etc'", "ls\x0b-la", "ls\x0c-la",
    # git is NOT auto-allowed: a repo's own .git/config runs code on the safest
    # verb (core.fsmonitor on `git status`, diff.external on `git diff`), so even
    # these must go to a human, not the allowlist.
    "git status", "git status -s", "git diff", "git diff --stat",
    "git log --oneline", "git show HEAD", "git branch", "git rev-parse HEAD",
    "git blame README.md",
]

# Must stay allowed (predicate True) — common inert commands; a regression here
# only costs a prompt, but we assert them so the allowlist keeps earning its keep.
ALLOW = [
    "ls", "ls -la", "ls -R", "pwd", "whoami", "id", "groups", "date", "date +%Y",
    "uname -a", "df -h", "free -m", "nproc", "uptime", "hostname",
]


def main():
    s = Suite("BENIGN ALLOWLIST (is_benign_command)")
    for cmd in DENY:
        s.check(f"refuse: {cmd!r}", ok(cmd) is False)
    for cmd in ALLOW:
        s.check(f"allow: {cmd!r}", ok(cmd) is True)
    return s.report()


if __name__ == "__main__":
    raise SystemExit(main())
