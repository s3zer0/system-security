"""Wrapper utilities that expose the legacy pipeline to FastAPI."""

from __future__ import annotations

import logging
import os
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from dotenv import load_dotenv

from common import ASTResult, ensure_dir, read_json, setup_logging, write_json
from search_source.modules.extractor import extract_app_layer
from trivy_extracter.trivy_module import trivy_func
from python_api_extracter.extracter import api_extracter
from ast_visualizer.utils import ast_to_png


BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_DIR = BASE_DIR / "DB"

logger = logging.getLogger("pipeline")
if not logging.getLogger().handlers:
    setup_logging(level=logging.INFO, fmt="[%(levelname)s] %(message)s")


@dataclass
class PipelineContext:
    image_tar: Path
    sources_dir: Path
    app_path: Optional[str]
    include_filter: Optional[str]
    auto_detect: bool
    force: bool


@dataclass
class PipelineConfig:
    """Configuration shared by the CLI and FastAPI entrypoints."""

    image_path: Path
    db_dir: Path
    sources_dir: Optional[Path] = None
    app_path: Optional[str] = None
    include_filter: Optional[str] = None
    full_scan: bool = True
    enhance_trivy: bool = False
    run_security_analysis: bool = False
    emit_graph: bool = False
    force: bool = False
    enable_perplexity: bool = False
    perplexity_api_key: Optional[str] = None
    analysis_id: Optional[str] = None
    original_filename: Optional[str] = None


def path_exists_and_non_empty(path: Path) -> bool:
    """Return True when the given path exists and contains data."""

    if path.is_dir():
        return any(path.iterdir())
    return path.exists()


def collect_python_files(root: Path) -> List[Path]:
    """Recursively gather Python files for AST analysis."""

    return [path for path in root.rglob("*.py") if path.is_file()]


def step_source_extraction(ctx: PipelineContext) -> None:
    """Extract application sources from the container image."""

    if ctx.sources_dir.exists() and not ctx.force:
        logger.info("Skipping: %s exists", ctx.sources_dir)
        return

    extract_app_layer(
        image_tar_path=str(ctx.image_tar),
        output_dir=str(ctx.sources_dir),
        app_path=ctx.app_path,
        auto_detect=ctx.auto_detect,
        include_filter=ctx.include_filter,
    )


def step_trivy_scan(
    image_tar: Path,
    trivy_output: Path,
    full_scan: bool,
    enhance: bool,
    force: bool,
) -> None:
    """Invoke Trivy against the supplied container image."""

    if trivy_output.exists() and not force:
        logger.info("Skipping Trivy scan: %s already exists", trivy_output)
        return

    ensure_dir(trivy_output.parent)
    logger.info("Running Trivy scan (full_scan=%s)  ->  %s", full_scan, trivy_output)
    trivy_func.scan_vulnerabilities(
        input_archive=str(image_tar),
        output_file=str(trivy_output),
        full_scan=full_scan,
    )

    if enhance:
        try:
            from trivy_extracter.main import enhance_descriptions
        except ImportError as exc:  # pragma: no cover - optional dependency
            logger.warning("Unable to import enhance_descriptions: %s", exc)
            return

        enhanced_output = trivy_output.with_name(trivy_output.stem + "_enhanced.json")
        logger.info("Enhancing Trivy descriptions  ->  %s", enhanced_output)
        enhance_descriptions(str(trivy_output), str(enhanced_output))


def step_python_api_mapping(
    trivy_output: Path,
    mapping_output: Path,
    force: bool,
) -> None:
    """Build the library -> CVE -> API mapping from Trivy output."""

    if mapping_output.exists() and not force:
        logger.info("Skipping API mapping: %s already exists", mapping_output)
        return

    logger.info("Building library -> CVE -> API mapping  ->  %s", mapping_output)
    trivy_data = read_json(trivy_output)
    combined = api_extracter.build_cve_api_mapping(trivy_data)
    write_json(mapping_output, combined)


def step_ast_analysis(
    source_dir: Path,
    output_prefix: Path,
    trivy_output: Optional[Path],
    skip_graph: bool,
    run_security: bool,
    force: bool,
) -> Tuple[Path, Optional[Path]]:
    """Run AST call graph and optional security analysis."""

    json_output = output_prefix.with_name(output_prefix.name + "_result.json")
    security_json: Optional[Path] = output_prefix.with_name(
        output_prefix.name + "_security_analysis.json"
    )

    security_exists = security_json.exists()
    needs_security_rerun = run_security and not security_exists

    if json_output.exists() and not force and not needs_security_rerun:
        logger.info("Skipping AST analysis: %s already exists", json_output)
        return json_output, security_json if security_exists else None

    if needs_security_rerun:
        logger.info(
            "Security analysis requested but missing; rerunning AST/security analysis."
        )

    if not source_dir.exists():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    py_files = collect_python_files(source_dir)
    if not py_files:
        raise RuntimeError(f"No Python files found under {source_dir}")

    logger.info(
        "Running AST analysis on %d files  ->  %s", len(py_files), json_output
    )

    base_dir = source_dir.resolve()
    targets = ast_to_png.parse_target_calls([])
    external, internal, unused = ast_to_png.visualize_call_flow(
        [str(p) for p in py_files],
        str(base_dir),
        str(output_prefix),
        targets,
        force_detection=True,
        no_graph=skip_graph,
    )

    result = ASTResult(external=external, internal=internal, unused=unused)
    write_json(json_output, result.to_dict())

    security_output_path = None
    if run_security:
        try:
            from ast_visualizer.utils.security_analyzer import SecurityAnalyzer
        except ImportError as exc:  # pragma: no cover - optional dependency
            logger.warning("Security analysis disabled (missing dependency): %s", exc)
        else:
            trivy_data = read_json(trivy_output) if trivy_output else None
            analyzer = SecurityAnalyzer()
            analysis = analyzer.analyze_security_posture(
                external_apis=external,
                internal_apis=internal,
                unused_apis=unused,
                vulnerability_data=trivy_data,
            )
            write_json(security_json, analysis)
            security_output_path = security_json

    return json_output, security_output_path


def step_cve_api_mapper(
    trivy_output: Path,
    mapping_output: Path,
    results_dir: Path,
    raw_dir: Path,
    gpt5_output: Path,
    force: bool,
) -> None:
    """Run the GPT-5 powered CVE -> API mapping job."""

    if gpt5_output.exists() and not force:
        logger.info("Skipping CVE -> API mapping: %s already exists", gpt5_output)
        return

    results_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)

    try:
        from cve_api_mapper.mapper.cve_api_mapper import CveApiMapper
    except ImportError as exc:
        raise RuntimeError(
            "Failed to import CveApiMapper. Ensure optional dependencies are installed."
        ) from exc

    logger.info("Running CVE -> API mapper (GPT-5)  ->  %s", gpt5_output)
    mapper = CveApiMapper(models_to_test=["gpt-5"])
    mapper.run_analysis(
        trivy_input_file=str(trivy_output),
        api_input_file=str(mapping_output),
        output_dir=str(results_dir),
        llm_raw_output_dir=str(raw_dir),
    )

    source_file = results_dir / "gpt-5_results.json"
    if not source_file.exists():
        raise FileNotFoundError(
            f"Expected GPT-5 results at {source_file}, but the mapper did not produce it."
        )

    shutil.copyfile(source_file, gpt5_output)


def _write_skipped_priority_file(output_json: Path, reason: str) -> None:
    """Write a placeholder JSON file when AI priority analysis is skipped."""
    ensure_dir(output_json.parent)
    skipped_data = {
        "skipped": True,
        "reason": reason,
        "modules_by_priority": [],
    }
    write_json(output_json, skipped_data)
    logger.info("Written skipped priority file: %s", output_json)


def step_fetch_priority(
    ast_json: Path,
    gpt5_json: Path,
    mapping_json: Path,
    trivy_json: Path,
    output_json: Path,
    force: bool,
    enable_perplexity: bool,
    perplexity_api_key: Optional[str],
) -> Optional[Dict[str, Any]]:
    """
    Evaluate patch priorities and emit fetch_priority.json.

    Returns:
        Dict containing priority data on success, None if API key is missing or API call fails.
    """

    # If output exists and we're not forcing, try to load it
    if output_json.exists() and not force:
        logger.info("Skipping fetch priority: %s already exists", output_json)
        existing_data = _read_json_if_exists(output_json)
        return existing_data if existing_data else {}

    # Check for API key early - soft dependency
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning(
            "Skipping AI priority analysis: ANTHROPIC_API_KEY not set. "
            "Pipeline will continue with scanner and AST data only."
        )
        _write_skipped_priority_file(
            output_json, "ANTHROPIC_API_KEY not set - AI analysis disabled"
        )
        return None

    # Wrap entire logic in try/except to handle API failures gracefully
    try:
        from fetch_priority.module import PatchPriorityEvaluator
    except ImportError as exc:
        logger.warning(
            "Skipping AI priority analysis: Failed to import PatchPriorityEvaluator (%s). "
            "Pipeline will continue with scanner and AST data only.",
            exc,
        )
        _write_skipped_priority_file(
            output_json, f"Failed to import PatchPriorityEvaluator: {exc}"
        )
        return None

    if enable_perplexity and not perplexity_api_key:
        logger.warning(
            "Perplexity search requested but no API key supplied; set PERPLEXITY_API_KEY before running."
        )

    try:
        ensure_dir(output_json.parent)
        logger.info("Evaluating patch priorities  ->  %s", output_json)
        evaluator = PatchPriorityEvaluator(
            api_key=api_key,
            perplexity_api_key=perplexity_api_key,
            enable_perplexity=enable_perplexity,
        )
        evaluator.run_analysis(
            ast_file=str(ast_json),
            gpt5_results_file=str(gpt5_json),
            lib2cve2api_file=str(mapping_json),
            trivy_file=str(trivy_json),
            output_file=str(output_json),
        )

        # Load and return the result
        result_data = _read_json_if_exists(output_json)
        return result_data if result_data else {}

    except Exception as exc:
        logger.error(
            "AI priority analysis failed: %s: %s. Pipeline will continue with scanner and AST data only.",
            type(exc).__name__,
            str(exc),
        )
        _write_skipped_priority_file(
            output_json, f"AI analysis failed: {type(exc).__name__}: {str(exc)}"
        )
        return None


def _read_json_if_exists(path: Path) -> Optional[Any]:
    if not path.exists():
        return None

    try:
        return read_json(path)
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.warning("Failed to read %s: %s", path, exc)
        return None


def _is_path_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _extract_version(value: Optional[str]) -> Optional[str]:
    if not value:
        return None

    match = re.search(r"\d+(?:\.\d+)+", value)
    return match.group(0) if match else None


def _infer_primary_language(sources_dir: Path) -> str:
    for _ in sources_dir.rglob("*.py"):
        return "Python"
    return "Unknown"


def _build_vulnerability_summary(trivy_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    if trivy_data:
        trivy_summary = trivy_data.get("vulnerability_summary") or {}
        severity_map = trivy_summary.get("by_severity") or {}
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            summary[key.lower()] = int(severity_map.get(key, 0))

        if not any(summary.values()) and trivy_data.get("vulnerabilities"):
            for item in trivy_data["vulnerabilities"]:
                severity = (item.get("severity") or item.get("Severity") or "").upper()
                if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    summary[severity.lower()] += 1

    summary["overall_risk"] = _determine_risk_level(summary)
    return summary


def _determine_risk_level(summary: Dict[str, Any]) -> str:
    if summary.get("critical", 0) > 0:
        return "CRITICAL"
    if summary.get("high", 0) > 0:
        return "HIGH"
    if summary.get("medium", 0) > 0:
        return "MEDIUM"
    if summary.get("low", 0) > 0:
        return "LOW"
    return "LOW"


def _build_overview(summary: Dict[str, Any], language: str) -> str:
    critical = summary.get("critical", 0)
    high = summary.get("high", 0)
    medium = summary.get("medium", 0)
    risk = summary.get("overall_risk", "LOW")
    total = critical + high + medium + summary.get("low", 0)
    return (
        f"{language} 이미지 분석 결과, Critical {critical}, High {high}, Medium {medium} 등 총 "
        f"{total}건의 취약점이 탐지되었습니다. (위험도: {risk})"
    )


def _build_vulnerabilities(trivy_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not trivy_data:
        return []

    vulns: List[Dict[str, Any]] = []
    for item in trivy_data.get("vulnerabilities", []) or []:
        cve_id = item.get("id") or item.get("VulnerabilityID")
        if not cve_id:
            continue
        vulns.append(
            {
                "cve_id": cve_id,
                "package": item.get("package_name") or item.get("PkgName") or "unknown",
                "version": item.get("installed_version")
                or item.get("InstalledVersion")
                or "unknown",
                "severity": (item.get("severity") or item.get("Severity") or "LOW").upper(),
                "description": item.get("description")
                or item.get("Description")
                or "N/A",
                "direct_call": False,  # TODO: integrate AST usage info
                "call_example": None,
            }
        )

    return vulns
def _build_library_api_mappings(
    mapping_data: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    if not mapping_data:
        return []

    entries: List[Dict[str, Any]] = []
    for package, versions in mapping_data.items():
        if not isinstance(versions, dict):
            continue
        for version, payload in versions.items():
            if not isinstance(payload, dict):
                continue
            cves = payload.get("cves") or []
            if isinstance(cves, dict):
                cves = list(cves.keys())
            cve_list = [c for c in cves if isinstance(c, str)]

            apis = payload.get("apis")
            if isinstance(apis, dict) and apis:
                for module_name, api_list in apis.items():
                    api_entries = api_list if isinstance(api_list, list) else [api_list]
                    for api_name in api_entries or ["unknown"]:
                        entries.append(
                            {
                                "package": package,
                                "version": version,
                                "module": module_name or "unknown",
                                "api": api_name or "unknown",
                                "related_cves": cve_list,
                            }
                        )
            elif isinstance(apis, list) and apis:
                for api_name in apis:
                    entries.append(
                        {
                            "package": package,
                            "version": version,
                            "module": "unknown",
                            "api": api_name or "unknown",
                            "related_cves": cve_list,
                        }
                    )
            else:
                entries.append(
                    {
                        "package": package,
                        "version": version,
                        "module": "unknown",
                        "api": "unknown",
                        "related_cves": cve_list,
                    }
                )
    return entries


def _build_patch_priority_list(
    fetch_priority_data: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    modules = (fetch_priority_data or {}).get("modules_by_priority") or []
    recommendations: List[Dict[str, Any]] = []

    for idx, module in enumerate(modules, start=1):
        package = module.get("package_name") or "unknown"
        version = module.get("current_version") or "unknown"
        patching = module.get("patching") if isinstance(module.get("patching"), dict) else {}
        recommended_version = _extract_version(patching.get("target_version")) or _extract_version(
            patching.get("upgrade_command")
        )
        score_raw = module.get("risk_score") or 0
        try:
            score = int(float(score_raw))
        except (TypeError, ValueError):
            score = 0
        note = module.get("overall_recommendation") or "업데이트를 권장합니다."
        priority_level = (module.get("priority_level") or "").lower()
        text_blob = f"{priority_level} {note}".lower()
        urgency = (
            "IMMEDIATE"
            if any(
                keyword in text_blob
                for keyword in ["즉시", "긴급", "immediate", "critical"]
            )
            else "PLANNED"
        )

        if recommended_version and recommended_version.lower() == "unknown":
            recommended_version = None

        recommendations.append(
            {
                "set_no": idx,
                "package": package,
                "current_version": version,
                "recommended_version": recommended_version,
                "score": max(0, min(score, 100)),
                "urgency": urgency,
                "note": note,
            }
        )

    return recommendations


def _build_meta_block(
    *,
    analysis_id: str,
    created_at: str,
    image_path: Path,
    risk_level: str,
    original_filename: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "analysis_id": analysis_id,
        "file_name": image_path.name,
        "original_filename": original_filename or image_path.name,
        "image_path": str(image_path),
        "created_at": created_at,
        "risk_level": risk_level,
    }


def _get_status_file_path(analysis_dir: Path) -> Path:
    """Return the path to the status.json file for a given analysis directory."""
    return analysis_dir / "status.json"


def create_analysis_status(
    analysis_id: str,
    analysis_dir: Path,
    status: Literal["PENDING", "PROCESSING", "COMPLETED", "FAILED"] = "PENDING",
    error_message: Optional[str] = None,
) -> None:
    """Create or update the status file for an analysis."""
    now = datetime.now(timezone.utc)
    status_file = _get_status_file_path(analysis_dir)

    # Try to read existing status to preserve created_at
    existing_status = None
    if status_file.exists():
        try:
            existing_status = read_json(status_file)
        except Exception:
            pass

    created_at = existing_status.get("created_at") if existing_status else now.isoformat()

    status_data = {
        "analysis_id": analysis_id,
        "status": status,
        "created_at": created_at,
        "updated_at": now.isoformat(),
        "error_message": error_message,
    }

    write_json(status_file, status_data)


def get_analysis_status(analysis_dir: Path) -> Optional[Dict[str, Any]]:
    """Read the current status of an analysis."""
    status_file = _get_status_file_path(analysis_dir)
    if not status_file.exists():
        return None
    try:
        return read_json(status_file)
    except Exception as exc:
        logger.warning("Failed to read status file %s: %s", status_file, exc)
        return None


def _build_pipeline_response(
    *,
    analysis_id: str,
    created_at: str,
    image_path: Path,
    db_dir: Path,
    sources_dir: Path,
    trivy_output: Path,
    mapping_output: Path,
    ast_json: Path,
    ast_security_json: Optional[Path],
    gpt5_json: Path,
    fetch_priority_json: Path,
    ast_output_prefix: Path,
    cve_results_dir: Path,
    cve_raw_dir: Path,
    original_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """Assemble structured result/meta payloads from pipeline artefacts."""

    trivy_data = _read_json_if_exists(trivy_output) or {}
    mapping_data = _read_json_if_exists(mapping_output) or {}
    ast_security_data = (
        _read_json_if_exists(ast_security_json) if ast_security_json else None
    )
    gpt5_data = _read_json_if_exists(gpt5_json)
    fetch_priority_data = _read_json_if_exists(fetch_priority_json) or {}

    language = _infer_primary_language(sources_dir)
    vuln_summary = _build_vulnerability_summary(trivy_data)
    overview_text = _build_overview(vuln_summary, language)
    patch_priority = _build_patch_priority_list(fetch_priority_data)

    meta_block = _build_meta_block(
        analysis_id=analysis_id,
        created_at=created_at,
        image_path=image_path,
        risk_level=vuln_summary.get("overall_risk", "LOW"),
        original_filename=original_filename,
    )

    result_block = {
        "language": language,
        "overview": overview_text,
        "vulnerabilities_summary": vuln_summary,
        "vulnerabilities": _build_vulnerabilities(trivy_data),
        "libraries_and_apis": _build_library_api_mappings(mapping_data),
        "patch_priority": patch_priority,
        "logs": [],
    }

    raw_reports = {
        "trivy": trivy_data,
        "library_cve_api_mapping": mapping_data,
        "ast_analysis": _read_json_if_exists(ast_json),
        "ast_security_analysis": ast_security_data,
        "cve_api_mapper": gpt5_data,
        "fetch_priority": fetch_priority_data,
    }

    artifacts = {
        "analysis_dir": str(db_dir),
        "trivy_report": str(trivy_output),
        "lib_cve_api_mapping": str(mapping_output),
        "ast_result": str(ast_json),
        "ast_security": str(ast_security_json) if ast_security_json else None,
        "gpt5_results": str(gpt5_json),
        "fetch_priority": str(fetch_priority_json),
        "ast_graph_prefix": str(ast_output_prefix),
        "cve_mapper_results_dir": str(cve_results_dir),
        "cve_mapper_raw_dir": str(cve_raw_dir),
    }

    return {
        "result": result_block,
        "meta": meta_block,
        "raw_reports": raw_reports,
        "artifacts": artifacts,
    }


def run_pipeline(config: PipelineConfig) -> Dict[str, Any]:
    """Execute the entire pipeline and return a consolidated result."""

    load_dotenv()

    image_path = config.image_path.resolve()
    db_dir = config.db_dir.resolve()
    db_dir.mkdir(parents=True, exist_ok=True)
    sources_dir = (
        config.sources_dir.resolve()
        if config.sources_dir
        else (db_dir / "output").resolve()
    )
    analysis_id = config.analysis_id or db_dir.name
    created_at = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    # Update status to PROCESSING
    create_analysis_status(analysis_id, db_dir, status="PROCESSING")

    trivy_output = (db_dir / "trivy_analysis_result.json").resolve()
    mapping_output = (db_dir / "lib2cve2api.json").resolve()
    ast_output_prefix = (db_dir / "ast_visualize").resolve()
    gpt5_output = (db_dir / "gpt5_results.json").resolve()
    fetch_priority_output = (db_dir / "fetch_priority.json").resolve()

    results_dir = (db_dir / "cve_api_mapper_results").resolve()
    raw_dir = (db_dir / "cve_api_mapper_raw").resolve()

    perplexity_api_key = config.perplexity_api_key or os.getenv("PERPLEXITY_API_KEY")
    enable_perplexity = config.enable_perplexity or bool(perplexity_api_key)
    if enable_perplexity:
        logger.info("Perplexity case search enabled using PERPLEXITY_API_KEY.")
    else:
        logger.info("Perplexity case search disabled (set PERPLEXITY_API_KEY to enable).")

    if not _is_path_within(image_path, db_dir):
        stored_image_path = db_dir / image_path.name
        try:
            ensure_dir(stored_image_path.parent)
            shutil.copy2(image_path, stored_image_path)
            image_path = stored_image_path
        except FileNotFoundError:
            logger.warning("Input image %s not found; proceeding with original path.", image_path)

    ctx = PipelineContext(
        image_tar=image_path,
        sources_dir=sources_dir,
        app_path=config.app_path,
        include_filter=config.include_filter,
        auto_detect=config.app_path is None,
        force=config.force,
    )

    ast_json: Optional[Path] = None
    ast_security_json: Optional[Path] = None

    step_source_extraction(ctx)
    step_trivy_scan(
        image_tar=image_path,
        trivy_output=trivy_output,
        full_scan=config.full_scan,
        enhance=config.enhance_trivy,
        force=config.force,
    )
    step_python_api_mapping(
        trivy_output=trivy_output,
        mapping_output=mapping_output,
        force=config.force,
    )
    ast_json, ast_security_json = step_ast_analysis(
        source_dir=sources_dir,
        output_prefix=ast_output_prefix,
        trivy_output=trivy_output if config.run_security_analysis else None,
        skip_graph=not config.emit_graph,
        run_security=config.run_security_analysis,
        force=config.force,
    )
    step_cve_api_mapper(
        trivy_output=trivy_output,
        mapping_output=mapping_output,
        results_dir=results_dir,
        raw_dir=raw_dir,
        gpt5_output=gpt5_output,
        force=config.force,
    )
    # AI priority analysis - returns None on failure (missing key, API error)
    # Pipeline continues gracefully; _build_pipeline_response will handle missing data
    priority_data = step_fetch_priority(
        ast_json=ast_json,
        gpt5_json=gpt5_output,
        mapping_json=mapping_output,
        trivy_json=trivy_output,
        output_json=fetch_priority_output,
        force=config.force,
        enable_perplexity=enable_perplexity,
        perplexity_api_key=perplexity_api_key,
    )
    if priority_data is None:
        logger.info(
            "AI priority analysis skipped or failed. Final report will include scanner/AST data only."
        )

    response = _build_pipeline_response(
        analysis_id=analysis_id,
        created_at=created_at,
        image_path=image_path,
        db_dir=db_dir,
        sources_dir=sources_dir,
        trivy_output=trivy_output,
        mapping_output=mapping_output,
        ast_json=ast_json,
        ast_security_json=ast_security_json,
        gpt5_json=gpt5_output,
        fetch_priority_json=fetch_priority_output,
        ast_output_prefix=ast_output_prefix,
        cve_results_dir=results_dir,
        cve_raw_dir=raw_dir,
        original_filename=config.original_filename,
    )

    write_json(db_dir / "Result.json", response["result"])
    write_json(db_dir / "meta.json", response["meta"])

    # Update status to COMPLETED
    create_analysis_status(analysis_id, db_dir, status="COMPLETED")

    return response


def run_security_analysis(image_path: str) -> Dict[str, Any]:
    """FastAPI-friendly helper returning both artefact paths and parsed data."""

    base_dir = DEFAULT_DB_DIR.resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    analysis_id = uuid.uuid4().hex
    analysis_root = (base_dir / analysis_id).resolve()
    analysis_root.mkdir(parents=True, exist_ok=True)

    config = PipelineConfig(
        image_path=Path(image_path).resolve(),
        db_dir=analysis_root,
        analysis_id=analysis_id,
    )
    return run_pipeline(config)


def process_analysis_background(
    analysis_id: str,
    file_path: str,
    original_filename: Optional[str] = None,
) -> None:
    """
    Background task wrapper for running security analysis asynchronously.

    This function:
    - Executes the analysis pipeline
    - Updates status to COMPLETED on success
    - Updates status to FAILED on error and logs the exception

    Args:
        analysis_id: The unique identifier for this analysis
        file_path: Path to the uploaded image archive
        original_filename: The original filename from the user upload
    """
    analysis_dir = DEFAULT_DB_DIR / analysis_id

    try:
        logger.info("Starting background analysis for %s", analysis_id)

        # Run the analysis pipeline
        config = PipelineConfig(
            image_path=Path(file_path).resolve(),
            db_dir=analysis_dir,
            analysis_id=analysis_id,
            original_filename=original_filename,
        )
        run_pipeline(config)

        logger.info("Background analysis completed successfully for %s", analysis_id)

    except Exception as exc:
        # Log the error
        logger.exception("Background analysis failed for %s: %s", analysis_id, exc)

        # Update status to FAILED with error message
        error_message = f"{type(exc).__name__}: {str(exc)}"
        create_analysis_status(
            analysis_id=analysis_id,
            analysis_dir=analysis_dir,
            status="FAILED",
            error_message=error_message,
        )


__all__ = [
    "PipelineConfig",
    "run_pipeline",
    "run_security_analysis",
    "process_analysis_background",
    "create_analysis_status",
    "get_analysis_status",
]
