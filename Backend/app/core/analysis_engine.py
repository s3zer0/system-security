"""Wrapper utilities that expose the legacy pipeline to FastAPI."""

from __future__ import annotations

import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


def step_fetch_priority(
    ast_json: Path,
    gpt5_json: Path,
    mapping_json: Path,
    trivy_json: Path,
    output_json: Path,
    force: bool,
    enable_perplexity: bool,
    perplexity_api_key: Optional[str],
) -> None:
    """Evaluate patch priorities and emit fetch_priority.json."""

    if output_json.exists() and not force:
        logger.info("Skipping fetch priority: %s already exists", output_json)
        return

    try:
        from fetch_priority.module import PatchPriorityEvaluator
    except ImportError as exc:
        raise RuntimeError("Failed to import PatchPriorityEvaluator.") from exc

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY is required for fetch_priority. Set it in the environment."
        )

    if enable_perplexity and not perplexity_api_key:
        logger.warning(
            "Perplexity search requested but no API key supplied; set PERPLEXITY_API_KEY before running."
        )

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


def _read_json_if_exists(path: Path) -> Optional[Any]:
    if not path.exists():
        return None

    try:
        return read_json(path)
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.warning("Failed to read %s: %s", path, exc)
        return None


def _infer_primary_language(sources_dir: Path) -> str:
    for _ in sources_dir.rglob("*.py"):
        return "Python"
    return "Unknown"


def _build_vulnerability_summary(trivy_data: Optional[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    if not trivy_data:
        return summary

    trivy_summary = trivy_data.get("vulnerability_summary") or {}
    severity_map = trivy_summary.get("by_severity") or {}
    for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        summary[key.lower()] = int(severity_map.get(key, 0))

    total = trivy_summary.get("total_vulnerabilities")
    if total is None and trivy_data.get("vulnerabilities"):
        total = len(trivy_data["vulnerabilities"])
    summary["total"] = int(total or sum(summary.values()))
    return summary


def _determine_risk_level(summary: Dict[str, int]) -> str:
    if summary["critical"] > 0:
        return "CRITICAL"
    if summary["high"] > 0:
        return "HIGH"
    if summary["medium"] > 0:
        return "MEDIUM"
    if summary["low"] > 0:
        return "LOW"
    return "INFO"


def _build_overview(summary: Dict[str, int]) -> Dict[str, str]:
    risk_level = _determine_risk_level(summary)
    total = summary["total"]
    critical = summary["critical"]
    high = summary["high"]
    overview_text = (
        f"Detected {total} vulnerabilities ({critical} critical / {high} high)."
    )
    return {"summary": overview_text, "risk_level": risk_level}


def _build_vulnerabilities(trivy_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not trivy_data:
        return []

    vulns: List[Dict[str, Any]] = []
    for item in trivy_data.get("vulnerabilities", []) or []:
        cve_id = item.get("id") or item.get("VulnerabilityID")
        if not cve_id:
            continue
        entry = {
            "cve_id": cve_id,
            "package_name": item.get("package_name") or item.get("PkgName"),
            "installed_version": item.get("installed_version")
            or item.get("InstalledVersion"),
            "severity": item.get("severity") or item.get("Severity"),
            "title": item.get("title") or item.get("Title"),
            "description": item.get("description") or item.get("Description"),
            "fixed_version": item.get("fixed_version")
            or item.get("FixedVersion"),
            "cvss": item.get("cvss") or item.get("CVSS"),
            "references": item.get("references") or item.get("References") or [],
            "primary_url": item.get("primary_url") or item.get("PrimaryURL"),
            "package_type": item.get("package_type") or item.get("PkgType"),
        }
        vulns.append(entry)

    return vulns


def _build_library_api_mappings(
    mapping_data: Optional[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    if not mapping_data:
        return []

    entries: List[Dict[str, Any]] = []
    for library, versions in mapping_data.items():
        if not isinstance(versions, dict):
            continue
        for version, payload in versions.items():
            if not isinstance(payload, dict):
                continue
            cves = payload.get("cves") or []
            if isinstance(cves, dict):
                cves = list(cves.keys())
            apis = payload.get("apis") or {}
            if isinstance(apis, list):
                apis = {"apis": apis}
            entries.append(
                {
                    "library": library,
                    "version": version,
                    "cves": cves,
                    "apis": apis,
                }
            )
    return entries


def _build_patch_priority_block(
    fetch_priority_data: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    data = fetch_priority_data or {}
    modules = data.get("modules_by_priority") or []
    summary_data = data.get("summary") or {}
    patching_roadmap = data.get("patching_roadmap") or {}

    summary = {
        "total_modules": summary_data.get("total_modules", len(modules)),
        "total_vulnerabilities": summary_data.get("total_vulnerabilities", 0),
        "critical_modules": summary_data.get("critical_modules", 0),
        "high_priority_modules": summary_data.get("high_priority_modules", 0),
        "medium_priority_modules": summary_data.get("medium_priority_modules", 0),
        "low_priority_modules": summary_data.get("low_priority_modules", 0),
        "external_exposed_modules": summary_data.get("external_exposed_modules"),
    }

    return {
        "modules_by_priority": modules,
        "summary": summary,
        "patching_roadmap": patching_roadmap,
        "overall_assessment": data.get("overall_assessment"),
        "metadata": data.get("metadata"),
    }


def _build_ast_analysis_block(
    ast_data: Optional[Dict[str, Any]]
) -> Optional[Dict[str, List[str]]]:
    if not ast_data:
        return None

    return {
        "external": ast_data.get("external", []),
        "internal": ast_data.get("internal", []),
        "unused": ast_data.get("unused", []),
    }


def _build_artifacts_block(
    *,
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
) -> Dict[str, Any]:
    return {
        "db_dir": str(db_dir),
        "sources_dir": str(sources_dir),
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


def _build_meta_block(
    *,
    analysis_id: str,
    created_at: str,
    image_path: Path,
    language: str,
    risk_level: str,
    vuln_summary: Dict[str, int],
    modules: List[Any],
    ast_analysis: Optional[Dict[str, List[str]]],
) -> Dict[str, Any]:
    stats = {
        "total_vulnerabilities": vuln_summary["total"],
        "critical": vuln_summary["critical"],
        "high": vuln_summary["high"],
        "medium": vuln_summary["medium"],
        "low": vuln_summary["low"],
        "modules_analyzed": len(modules),
        "external_apis": len(ast_analysis["external"]) if ast_analysis else 0,
        "internal_apis": len(ast_analysis["internal"]) if ast_analysis else 0,
    }

    return {
        "analysis_id": analysis_id,
        "image_name": image_path.name,
        "image_path": str(image_path),
        "created_at": created_at,
        "language": language,
        "risk_level": risk_level,
        "stats": stats,
    }


def _build_pipeline_response(
    *,
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
) -> Dict[str, Any]:
    """Assemble structured result/meta payloads from pipeline artefacts."""

    trivy_data = _read_json_if_exists(trivy_output) or {}
    mapping_data = _read_json_if_exists(mapping_output) or {}
    ast_data = _read_json_if_exists(ast_json)
    ast_security_data = (
        _read_json_if_exists(ast_security_json) if ast_security_json else None
    )
    gpt5_data = _read_json_if_exists(gpt5_json)
    fetch_priority_data = _read_json_if_exists(fetch_priority_json) or {}

    language = _infer_primary_language(sources_dir)
    vuln_summary = _build_vulnerability_summary(trivy_data)
    patch_block = _build_patch_priority_block(fetch_priority_data)
    ast_block = _build_ast_analysis_block(ast_data)
    overview = _build_overview(vuln_summary)
    artifacts = _build_artifacts_block(
        db_dir=db_dir,
        sources_dir=sources_dir,
        trivy_output=trivy_output,
        mapping_output=mapping_output,
        ast_json=ast_json,
        ast_security_json=ast_security_json,
        gpt5_json=gpt5_json,
        fetch_priority_json=fetch_priority_json,
        ast_output_prefix=ast_output_prefix,
        cve_results_dir=cve_results_dir,
        cve_raw_dir=cve_raw_dir,
    )

    analysis_id = uuid.uuid4().hex
    created_at = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    meta_block = _build_meta_block(
        analysis_id=analysis_id,
        created_at=created_at,
        image_path=image_path,
        language=language,
        risk_level=overview["risk_level"],
        vuln_summary=vuln_summary,
        modules=patch_block.get("modules_by_priority", []),
        ast_analysis=ast_block,
    )

    result_block = {
        "language": language,
        "overview": overview,
        "vulnerabilities_summary": vuln_summary,
        "vulnerabilities": _build_vulnerabilities(trivy_data),
        "libraries_and_apis": _build_library_api_mappings(mapping_data),
        "patch_priority": patch_block,
        "ast_analysis": ast_block,
        "artifacts": artifacts,
    }

    raw_reports = {
        "trivy": trivy_data,
        "library_cve_api_mapping": mapping_data,
        "ast_security_analysis": ast_security_data,
        "cve_api_mapper": gpt5_data,
        "fetch_priority": fetch_priority_data,
    }

    return {
        "result": result_block,
        "meta": meta_block,
        "raw_reports": raw_reports,
    }


def run_pipeline(config: PipelineConfig) -> Dict[str, Any]:
    """Execute the entire pipeline and return a consolidated result."""

    load_dotenv()

    image_path = config.image_path.resolve()
    db_dir = config.db_dir.resolve()
    db_dir.mkdir(parents=True, exist_ok=True)
    sources_dir = (config.sources_dir or (db_dir / "output")).resolve()

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
    step_fetch_priority(
        ast_json=ast_json,
        gpt5_json=gpt5_output,
        mapping_json=mapping_output,
        trivy_json=trivy_output,
        output_json=fetch_priority_output,
        force=config.force,
        enable_perplexity=enable_perplexity,
        perplexity_api_key=perplexity_api_key,
    )

    return _build_pipeline_response(
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
    )


def run_security_analysis(image_path: str) -> Dict[str, Any]:
    """FastAPI-friendly helper returning both artefact paths and parsed data."""

    config = PipelineConfig(image_path=Path(image_path), db_dir=DEFAULT_DB_DIR)
    return run_pipeline(config)


__all__ = [
    "PipelineConfig",
    "run_pipeline",
    "run_security_analysis",
]
