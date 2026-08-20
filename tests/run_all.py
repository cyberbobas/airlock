"""Run every Airlock test suite. Exit non-zero if any suite fails."""
import pathlib, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SUITES = ["test_e2e.py", "test_contract.py", "test_ask.py", "test_redteam.py",
          "test_scan.py", "test_policy.py",
          "test_proxy_robustness.py", "test_product.py", "test_regressions.py", "test_deep.py", "test_audit.py",
          "test_properties.py", "test_stream.py", "test_algebra.py"]


def main() -> int:
    results = []
    for name in SUITES:
        p = ROOT / "tests" / name
        if not p.exists():
            continue
        t0 = time.time()
        r = subprocess.run([sys.executable, str(p)],
                           env={**__import__("os").environ, "PYTHONPATH": str(ROOT)},
                           capture_output=True, text=True)
        results.append((name, r.returncode == 0, time.time() - t0))
        sys.stdout.write(r.stdout)
        if r.returncode != 0:
            sys.stdout.write(r.stderr)
    print("\n" + "=" * 66)
    ok = True
    total = 0.0
    for name, passed, dt in results:
        total += dt
        print(f"  {'PASS' if passed else 'FAIL'}  {name:22} {dt:5.1f}s")
        ok = ok and passed
    print("=" * 66)
    print(f"  {'ALL SUITES PASS' if ok else 'SUITE FAILURES'}  "
          f"({sum(1 for _, p, _ in results if p)}/{len(results)}) in {total:.1f}s\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
