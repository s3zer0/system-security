"""Ad-hoc script to exercise the run_security_analysis helper."""

from __future__ import annotations

from app.core.analysis_engine import run_security_analysis


def main() -> None:
    result = run_security_analysis("test_target/pyyaml-vuln.tar")
    fetch_priority = result.get("fetch_priority")
    print("Fetch priority summary:", fetch_priority)


if __name__ == "__main__":
    main()
