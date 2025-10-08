"""Entry point for orchestrating the system-security project.

이 스크립트는 저장소의 README에서 설명한 전체 파이프라인을 재현한다.
주요 단계는 다음과 같다:

1. 샘플 컨테이너 이미지를 대상으로 한 Trivy 취약점 보고서를 확보한다.
2. Trivy 결과에서 라이브러리·버전·CVE·API 매핑 정보를 생성한다.
3. LLM 없이도 동작하는 결정론적 CVE→API 상관 분석을 수행한다.

외부 도구(Trivy CLI, 패키지 설치, LLM 클라이언트 등)를 사용할 수 없는
환경이라면, 저장소에 포함된 샘플 자산을 이용해 동일한 흐름을 계속 실행한다.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


@dataclass
class StageResult:
    """Container for metadata about each pipeline stage."""

    status: str
    details: str
    output_path: Path


class PipelineRunner:
    """Coordinate the simplified end-to-end workflow for the project."""

    def __init__(self) -> None:
        # 저장소 루트 및 출력 디렉터리 설정
        self.repo_root = Path(__file__).resolve().parent
        self.db_dir = self.repo_root / "DB"
        self.output_dir = self.db_dir / "auto_run"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("pipeline")
        if not logging.getLogger().handlers:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s [%(levelname)s] %(message)s",
            )
        self.logger.setLevel(logging.INFO)

        self.stage_results: Dict[str, StageResult] = {}

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _load_json(self, path: Path) -> dict:
        # JSON 파일을 읽어 파이썬 dict로 반환
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def _save_json(self, data: dict, path: Path) -> None:
        # JSON 데이터를 지정 경로에 저장
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)

    def _create_minimal_trivy_payload(self) -> dict:
        # Trivy 결과가 없는 경우에 대비한 최소 구조 생성
        now = datetime.utcnow().isoformat() + "Z"
        return {
            "scan_info": {
                "target": "synthetic-image.tar",
                "scan_date": now,
                "os_info": {"Family": "unknown", "Name": "unknown"},
            },
            "vulnerability_summary": {
                "total_vulnerabilities": 0,
                "by_severity": {},
                "by_package_type": {},
            },
            "vulnerabilities": [],
        }

    def _derive_simple_mapping(self, trivy_data: dict) -> Dict[str, Dict[str, List[str]]]:
        # Trivy JSON에서 Python 관련 패키지의 CVE 맵을 간단히 구성
        mapping: Dict[str, Dict[str, List[str]]] = {}
        for vuln in trivy_data.get("vulnerabilities", []):
            pkg = vuln.get("package_name")
            ver = vuln.get("installed_version")
            cve = vuln.get("id")
            pkg_type = (vuln.get("package_type") or "").lower()
            if not (pkg and ver and cve):
                continue
            if "python" not in pkg_type:
                continue
            mapping.setdefault(pkg, {}).setdefault(ver, []).append(cve)
        return mapping

    # ------------------------------------------------------------------
    # Stage 1 – Obtain Trivy vulnerability output
    # ------------------------------------------------------------------
    def ensure_trivy_results(self) -> Path:
        # Trivy CLI 실행을 시도하고, 실패 시 샘플 혹은 합성 데이터를 사용
        output_path = self.output_dir / "trivy_analysis_result.json"
        sample_path = self.db_dir / "trivy_analysis_result.json"

        try:
            trivy_module = importlib.import_module("trivy_extracter.trivy_module.trivy_func")
            scan_vulnerabilities = getattr(trivy_module, "scan_vulnerabilities")
            image_archive = self.repo_root / "test_target" / "pyyaml-vuln.tar"
            trivy_binary = shutil.which("trivy")

            if trivy_binary and image_archive.exists():
                self.logger.info("Running Trivy scan via %s", trivy_binary)
                scan_vulnerabilities(str(image_archive), str(output_path), full_scan=True)
                self.stage_results["trivy"] = StageResult(
                    status="scan",
                    details="Trivy executed against bundled container image.",
                    output_path=output_path,
                )
                return output_path
            else:
                missing: List[str] = []
                if not trivy_binary:
                    missing.append("Trivy CLI")
                if not image_archive.exists():
                    missing.append("sample image archive")
                raise RuntimeError(
                    "Unavailable dependencies: " + ", ".join(missing) if missing else "Unknown prerequisite missing"
                )
        except Exception as exc:  # noqa: BLE001 - broad fallback by design
            self.logger.warning("Falling back to stored Trivy results: %s", exc)
            if sample_path.exists():
                sample_data = self._load_json(sample_path)
                sample_data.setdefault("meta", {})["source"] = "fallback-copy"
                self._save_json(sample_data, output_path)
                self.stage_results["trivy"] = StageResult(
                    status="fallback",
                    details=f"Copied sample report from {sample_path.relative_to(self.repo_root)}.",
                    output_path=output_path,
                )
                return output_path

            synthetic = self._create_minimal_trivy_payload()
            self._save_json(synthetic, output_path)
            self.stage_results["trivy"] = StageResult(
                status="synthetic",
                details="Generated minimal synthetic Trivy payload (no vulnerabilities).",
                output_path=output_path,
            )
            return output_path

    # ------------------------------------------------------------------
    # Stage 2 – Build CVE↔API mapping skeleton
    # ------------------------------------------------------------------
    def ensure_api_mapping(self, trivy_json_path: Path) -> Path:
        # Trivy 결과를 기반으로 CVE-API 매핑을 생성하고, 기존 참조 데이터와 병합
        trivy_data = self._load_json(trivy_json_path)
        output_path = self.output_dir / "lib2cve2api.json"
        sample_path = self.db_dir / "lib2cve2api.json"

        try:
            trivy_parser = importlib.import_module("python_api_extracter.extracter.trivy_parser")
            cve_mapping = trivy_parser.map_cves_by_package(trivy_data)
            self.logger.info("Derived CVE mapping using python_api_extracter.trivy_parser")
        except Exception as exc:  # noqa: BLE001 - fallback when module unavailable
            self.logger.warning("Falling back to lightweight CVE mapping: %s", exc)
            cve_mapping = self._derive_simple_mapping(trivy_data)

        reference_mapping: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
        if sample_path.exists():
            try:
                reference_mapping = self._load_json(sample_path)
            except json.JSONDecodeError:
                self.logger.warning("Sample API mapping is not valid JSON; ignoring.")

        combined = self._build_combined_mapping(cve_mapping, reference_mapping)
        self._save_json(combined, output_path)
        self.stage_results["api"] = StageResult(
            status="generated",
            details="Combined CVE mapping with bundled API catalogue (offline friendly).",
            output_path=output_path,
        )
        return output_path

    def _build_combined_mapping(
        self,
        cve_mapping: Dict[str, Dict[str, List[str]]],
        reference_mapping: Dict[str, Dict[str, Dict[str, List[str]]]],
    ) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
        # 추출된 CVE 정보와 참조 API 데이터를 결합해 완전한 구조 생성
        combined: Dict[str, Dict[str, Dict[str, List[str]]]] = {}

        for package, versions in cve_mapping.items():
            combined[package] = {}
            for version, cves in versions.items():
                reference_apis: Dict[str, List[str]] = {}
                if package in reference_mapping and version in reference_mapping[package]:
                    reference_apis = reference_mapping[package][version].get("apis", {})

                combined[package][version] = {
                    "cves": sorted(set(cves)),
                    "apis": reference_apis,
                }

        # Include packages that only exist in the reference mapping to retain context.
        for package, versions in reference_mapping.items():
            combined.setdefault(package, {})
            for version, payload in versions.items():
                combined[package].setdefault(
                    version,
                    {
                        "cves": payload.get("cves", []),
                        "apis": payload.get("apis", {}),
                    },
                )
        return combined

    # ------------------------------------------------------------------
    # Stage 3 – Offline CVE→API correlation (LLM-free)
    # ------------------------------------------------------------------
    def run_offline_mapper(self, trivy_json_path: Path, api_json_path: Path) -> Tuple[Path, Path]:
        # LLM 없이 키워드 기반으로 CVE 설명과 API 목록을 연결
        trivy_data = self._load_json(trivy_json_path)
        api_data = self._load_json(api_json_path)

        results_path = self.output_dir / "offline_llm_results.json"
        summary_path = self.output_dir / "offline_summary.json"

        mapping_results = self._offline_mapping(trivy_data, api_data)
        summary = self._build_summary(mapping_results)

        self._save_json(mapping_results, results_path)
        self._save_json(summary, summary_path)

        self._write_text_summary(summary, self.output_dir / "offline_summary.txt")

        self.stage_results["mapper"] = StageResult(
            status="offline",
            details="Generated deterministic CVE→API correlations using keyword heuristics.",
            output_path=results_path,
        )
        return results_path, summary_path

    def _offline_mapping(
        self,
        trivy_data: dict,
        api_data: Dict[str, Dict[str, Dict[str, List[str]]]],
    ) -> Dict[str, Dict[str, Dict[str, dict]]]:
        # 패키지·버전·CVE 별로 후보 API와 근거 메시지를 작성
        vuln_index: Dict[Tuple[str, str, str], dict] = {}
        for vuln in trivy_data.get("vulnerabilities", []):
            key = (
                vuln.get("package_name"),
                vuln.get("installed_version"),
                vuln.get("id"),
            )
            vuln_index[key] = {
                "description": vuln.get("description", ""),
                "severity": vuln.get("severity", "UNKNOWN"),
            }

        results: Dict[str, Dict[str, Dict[str, dict]]] = {}
        for package, versions in api_data.items():
            results[package] = {}
            for version, payload in versions.items():
                cve_ids = payload.get("cves", [])
                apis = payload.get("apis", {})
                mapping = {}

                for cve_id in cve_ids:
                    vuln_meta = vuln_index.get((package, version, cve_id), {})
                    description = vuln_meta.get("description", "")
                    severity = vuln_meta.get("severity", "UNKNOWN")
                    selected_apis, reason = self._select_apis_for_cve(description, apis, severity)
                    mapping[cve_id] = {
                        "apis": selected_apis,
                        "reason": reason,
                    }

                results[package][version] = {
                    "cves": cve_ids,
                    "mapping_result": mapping,
                }

        return results

    def _select_apis_for_cve(
        self,
        description: str,
        api_dict: Dict[str, List[str]],
        severity: str,
    ) -> Tuple[List[str], str]:
        # CVE 설명에 포함된 키워드를 기준으로 API 후보를 선택
        if not api_dict:
            return [], "No API catalogue available for this package version."

        desc_lower = description.lower()
        heuristics: List[Tuple[str, Tuple[str, ...]]] = [
            ("session", ("session", "cookie")),
            ("cookie", ("cookie",)),
            ("yaml", ("yaml", "load", "dump")),
            ("load", ("load", "unsafe")),
            ("deserialize", ("load", "unsafe")),
            ("unsafe", ("unsafe",)),
            ("multipart", ("multipart", "form", "parse")),
            ("form", ("form",)),
            ("proxy", ("proxy", "cache")),
            ("cache", ("cache",)),
            ("request", ("request", "http")),
            ("debug", ("debug", "trace")),
        ]

        selected: List[str] = []
        reasons: List[str] = []

        for keyword, hints in heuristics:
            if keyword in desc_lower:
                matches = self._match_apis(api_dict, hints)
                if matches:
                    selected.extend(matches)
                    reasons.append(
                        f"Keyword '{keyword}' highlighted {len(matches)} API candidate(s)."
                    )

        # Deduplicate while preserving order
        seen = set()
        ordered_matches = []
        for api in selected:
            if api not in seen:
                seen.add(api)
                ordered_matches.append(api)

        if ordered_matches:
            reason = " ".join(reasons)
            if severity:
                reason += f" Severity reported as {severity}."
            return ordered_matches[:10], reason

        fallback = self._default_api_sample(api_dict)
        if fallback:
            return fallback, (
                "No heuristic keyword matched the CVE description; provided representative APIs "
                "to assist manual triage."
            )
        return [], "No API candidates available after heuristic evaluation."

    def _match_apis(self, api_dict: Dict[str, List[str]], hints: Iterable[str]) -> List[str]:
        # 모듈과 함수명을 모두 소문자로 비교해 키워드와 일치하는 API를 반환
        matches: List[str] = []
        lower_hints = tuple(h.lower() for h in hints)
        for module, functions in api_dict.items():
            for func in functions:
                qualified = self._qualify_api_name(module, func)
                name = qualified.lower()
                if any(hint in name for hint in lower_hints):
                    matches.append(qualified)
        return matches

    def _default_api_sample(self, api_dict: Dict[str, List[str]]) -> List[str]:
        # 키워드가 없을 때 대표로 제시할 API 3개를 선택
        sample: List[str] = []
        for module, functions in api_dict.items():
            for func in functions:
                sample.append(self._qualify_api_name(module, func))
                if len(sample) >= 3:
                    return sample
        return sample

    def _qualify_api_name(self, module: str, func: str) -> str:
        # 모듈과 함수명을 조합해 전체 경로 형태의 이름으로 변환
        if not module:
            return func
        if not func:
            return module
        if func.startswith(module):
            return func
        if "." in func:
            return f"{module}.{func}"
        return f"{module}.{func}"

    def _build_summary(self, results: Dict[str, Dict[str, Dict[str, dict]]]) -> dict:
        # 최종 매핑 결과를 요약해 메타데이터로 정리
        total_packages = len(results)
        total_versions = sum(len(versions) for versions in results.values())
        total_cves = 0
        mapped_cves = 0

        for versions in results.values():
            for payload in versions.values():
                cves = payload.get("cves", [])
                total_cves += len(cves)
                mapping = payload.get("mapping_result", {})
                mapped_cves += sum(1 for data in mapping.values() if data.get("apis"))

        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_packages": total_packages,
            "total_versions": total_versions,
            "total_cves": total_cves,
            "cves_with_api_candidates": mapped_cves,
        }

    def _write_text_summary(self, summary: dict, path: Path) -> None:
        # 텍스트 요약 파일을 생성해 사람이 읽기 쉽도록 출력
        lines = [
            "Offline CVE→API Mapping Summary",
            "=" * 40,
            f"Generated at      : {summary.get('generated_at', 'unknown')}",
            f"Packages analysed : {summary.get('total_packages', 0)}",
            f"Versions covered  : {summary.get('total_versions', 0)}",
            f"Total CVEs        : {summary.get('total_cves', 0)}",
            f"CVEs with matches : {summary.get('cves_with_api_candidates', 0)}",
            "",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Stage 4 – Execute available tests
    # ------------------------------------------------------------------
    def run_available_tests(self) -> List[dict]:
        # Flask/PyYAML 데모 테스트를 실행하거나 조건에 따라 건너뛴다
        reports: List[dict] = []
        test_dir = self.repo_root / "test_target" / "tests"
        required_modules = ("flask", "yaml")

        if not test_dir.exists():
            reports.append(
                {
                    "name": "unittest:test_target",
                    "status": "skipped",
                    "reason": "Test directory not found.",
                }
            )
            self.stage_results["tests"] = StageResult(
                status="skipped",
                details="No unittest directory detected.",
                output_path=test_dir,
            )
            return reports

        missing = [mod for mod in required_modules if importlib.util.find_spec(mod) is None]
        if missing:
            reason = f"Missing runtime dependencies: {', '.join(missing)}"
            self.logger.warning("Skipping unittest suite: %s", reason)
            reports.append(
                {
                    "name": "unittest:test_target",
                    "status": "skipped",
                    "reason": reason,
                }
            )
            self.stage_results["tests"] = StageResult(
                status="skipped",
                details=reason,
                output_path=test_dir,
            )
            return reports

        cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
        self.logger.info("Running unit tests via: %s", " ".join(cmd))
        completed = subprocess.run(  # noqa: PLR2004
            cmd,
            capture_output=True,
            text=True,
            cwd=str(test_dir.parent),
        )
        status = "passed" if completed.returncode == 0 else "failed"
        reports.append(
            {
                "name": "unittest:test_target",
                "status": status,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        )
        if completed.returncode != 0:
            self.logger.error("Unit tests failed (stdout and stderr retained in report).")
        self.stage_results["tests"] = StageResult(
            status=status,
            details="Unit tests executed from test_target/tests.",
            output_path=test_dir,
        )
        return reports

    # ------------------------------------------------------------------
    # Orchestration helpers
    # ------------------------------------------------------------------
    def _write_test_reports(self, test_reports: List[dict]) -> Path:
        """테스트 실행 결과를 JSON 파일로 저장"""

        report_path = self.output_dir / "test_reports.json"
        payload = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "python": sys.version,
            "reports": test_reports,
        }
        self._save_json(payload, report_path)
        return report_path

    def print_summary(
        self,
        trivy_path: Path,
        api_path: Path,
        results_path: Path,
        summary_path: Path,
        test_reports: List[dict],
        test_report_path: Path,
    ) -> None:
        # 각 단계의 상태와 생성된 산출물을 콘솔에 보기 좋게 출력
        print("\nPipeline execution summary")
        print("=" * 32)
        for stage, result in self.stage_results.items():
            rel_output = result.output_path.relative_to(self.repo_root)
            print(f"- {stage.capitalize():<8} : {result.status:>9}  →  {rel_output}")
            print(f"             {result.details}")

        print("\nGenerated artefacts")
        print("=" * 32)
        for label, path in (
            ("Trivy JSON", trivy_path),
            ("API mapping", api_path),
            ("LLM results", results_path),
            ("Summary", summary_path),
            ("Tests", test_report_path),
        ):
            print(f"- {label:<12}: {path.relative_to(self.repo_root)}")

        print("\nTest execution report")
        print("=" * 32)
        if not test_reports:
            print("No tests were discovered.")
        for report in test_reports:
            line = f"- {report['name']}: {report['status']}"
            if "reason" in report:
                line += f" ({report['reason']})"
            print(line)

    def run(self) -> None:
        trivy_path = self.ensure_trivy_results()
        api_path = self.ensure_api_mapping(trivy_path)
        results_path, summary_path = self.run_offline_mapper(trivy_path, api_path)
        test_reports = self.run_available_tests()
        test_report_path = self._write_test_reports(test_reports)
        if "tests" in self.stage_results:
            self.stage_results["tests"].output_path = test_report_path
        self.print_summary(
            trivy_path,
            api_path,
            results_path,
            summary_path,
            test_reports,
            test_report_path,
        )


def main() -> None:
    runner = PipelineRunner()
    runner.run()


if __name__ == "__main__":
    main()
