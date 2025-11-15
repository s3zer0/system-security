"""Ad-hoc script to exercise the run_security_analysis helper."""

from __future__ import annotations

from app.core.analysis_engine import run_security_analysis


def main() -> None:
    payload = run_security_analysis("test_target/pyyaml-vuln.tar")
    result = payload.get("result", {})
    overview = result.get("overview", {})
    patch_priority = result.get("patch_priority", {})
    modules = patch_priority.get("modules_by_priority", [])

    print("Risk level:", overview.get("risk_level"))
    print("Modules by priority count:", len(modules))


if __name__ == "__main__":
    main()
