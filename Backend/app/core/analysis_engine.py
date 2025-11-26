"""Orchestrator for the analysis pipeline following single responsibility principle."""

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

from common import ensure_dir, read_json, setup_logging, write_json
from .exceptions import (
    AnalysisError,
    SourceExtractionError,
    ScannerError,
    ParserError,
    ASTAnalysisError,
    EnrichmentError,
)
from .killchain_detector import detect_killchains
from .services import (
    SourceExtractionService,
    ScannerService,
    ParserService,
    ASTAnalysisService,
    EnrichmentService,
)


BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_DIR = BASE_DIR / "DB"

logger = logging.getLogger("pipeline")
if not logging.getLogger().handlers:
    setup_logging(level=logging.INFO, fmt="[%(levelname)s] %(message)s")


# Module-level constants for package name aliasing
# Maps import names to their PyPI package names
IMPORT_TO_PACKAGE_ALIASES: Dict[str, List[str]] = {
    "yaml": ["pyyaml"],
    "pil": ["pillow"],
    "cv2": ["opencv-python", "opencv-python-headless"],
    "sklearn": ["scikit-learn"],
    "bs4": ["beautifulsoup4"],
}


def _is_valid_api_string(api_call: Any) -> bool:
    """
    Validate that an API call string is valid for processing.

    Args:
        api_call: The API call to validate

    Returns:
        True if the API call is a non-empty string, False otherwise
    """
    # Check if it's a string type
    if not isinstance(api_call, str):
        return False

    # Check if it's not empty or whitespace-only
    if not api_call or not api_call.strip():
        return False

    return True


def _normalize_package_name(package_name: str) -> set[str]:
    """
    Normalize package name to match import names.
    Strategies:
    1. Exact match (lowercased)
    2. Remove 'python-' prefix
    3. Namespace packages (dots): 'ruamel.yaml' -> 'ruamel'
    4. Standardize underscores: 'my_package' -> 'my-package'
    5. Hyphenated names (First & Last):
       - 'google-cloud-storage' -> 'google' (First)
       - 'apache-airflow' -> 'airflow' (Last)
       - Avoid middle parts to reduce false positives.
    """
    if not package_name:
        return set()

    normalized = package_name.lower()
    variants = {normalized}

    # Strategy 2: Handle python- prefix
    if normalized.startswith("python-"):
        no_prefix = normalized[7:]
        variants.add(no_prefix)
        # Prefix 제거된 버전으로도 아래 로직들이 동작하도록 추가
        normalized = no_prefix

    # Strategy 3: Handle delimiters (dots) - Namespace packages
    if "." in normalized:
        variants.add(normalized.split(".")[0])

    # Strategy 4: Handle underscores (Standardization)
    if "_" in normalized:
        variants.add(normalized.replace("_", "-"))

    # Strategy 5: Handle hyphens (First & Last segment strategy)
    # This balances catching namespace packages (google-cloud -> google)
    # and vendor packages (apache-airflow -> airflow)
    if "-" in normalized:
        parts = normalized.split("-")
        # First part (e.g., 'google' from 'google-cloud-storage')
        if parts[0]:
            variants.add(parts[0])
        # Last part (e.g., 'airflow' from 'apache-airflow')
        # Only if different from first part
        if len(parts) > 1 and parts[-1]:
            variants.add(parts[-1])

    return variants


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


def _extract_used_modules(ast_data: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Extract module names and their usage locations from AST analysis output.

    Parses the AST visualizer output and extracts all module names that are
    imported or used in the codebase, along with WHERE they are used (file paths).
    This enables Call Evidence tracking for reachability analysis.

    Args:
        ast_data: AST analysis result containing external/internal/unused API lists
                  Can optionally include file path information in the structure

    Returns:
        Dictionary mapping module names to list of file paths where they're used
        Example: {"yaml": ["app.py", "utils.py"], "pyyaml": ["app.py"]}

    Examples:
        >>> ast_data = {"external": ["yaml.load", "flask.app.route"]}
        >>> _extract_used_modules(ast_data)
        {'yaml': ['Unknown location'], 'pyyaml': ['Unknown location'],
         'flask': ['Unknown location']}
    """
    if not ast_data:
        return {}

    # Use a dict to track module -> list of file paths
    module_locations: Dict[str, List[str]] = {}

    def _add_module_location(module_name: str, location: str) -> None:
        """Helper to add a module and its location."""
        if module_name not in module_locations:
            module_locations[module_name] = []
        if location not in module_locations[module_name]:
            module_locations[module_name].append(location)

    # Try to extract file path information if available in AST data
    # The AST visualizer may provide this in various formats
    default_location = "Unknown location"
    file_context = ast_data.get("file_path") or ast_data.get("source_file") or default_location

    # Extract from external APIs (most relevant for dependencies)
    external_apis = ast_data.get("external", [])
    if isinstance(external_apis, list):
        for item in external_apis:
            # Handle both string format and dict format
            if isinstance(item, dict):
                api_call = item.get("name") or item.get("api")
                # Priority order: relative_path, file_path, file, location, fallback
                location = (
                    item.get("relative_path")
                    or item.get("file_path")
                    or item.get("file")
                    or item.get("location")
                    or file_context
                )
            elif _is_valid_api_string(item):
                api_call = item
                location = file_context
            else:
                continue

            if not _is_valid_api_string(api_call):
                continue

            # Extract the root module name (e.g., "yaml.load" -> "yaml")
            parts = api_call.split(".")

            # Guard: Ensure we have parts and the first part is non-empty
            if not parts or not parts[0]:
                continue

            module_name = parts[0].lower()
            _add_module_location(module_name, location)

            # Add package name aliases using the constant
            if module_name in IMPORT_TO_PACKAGE_ALIASES:
                for alias in IMPORT_TO_PACKAGE_ALIASES[module_name]:
                    _add_module_location(alias, location)

    # Also check internal APIs for completeness
    internal_apis = ast_data.get("internal", [])
    if isinstance(internal_apis, list):
        for item in internal_apis:
            # Handle both string format and dict format
            if isinstance(item, dict):
                api_call = item.get("name") or item.get("api")
                # Priority order: relative_path, file_path, file, location, fallback
                location = (
                    item.get("relative_path")
                    or item.get("file_path")
                    or item.get("file")
                    or item.get("location")
                    or file_context
                )
            elif _is_valid_api_string(item):
                api_call = item
                location = file_context
            else:
                continue

            if not _is_valid_api_string(api_call):
                continue

            parts = api_call.split(".")

            # Guard: Ensure we have parts and the first part is non-empty
            if not parts or not parts[0]:
                continue

            original_name = parts[0]
            module_name = original_name.lower()

            # Guard: Skip if original_name is somehow empty after validation
            if not original_name:
                continue

            # Only add if it looks like an imported module (capitalized or common patterns)
            if original_name[0].isupper() or module_name in ("os", "sys", "json", "re"):
                _add_module_location(module_name, location)

                # Add aliases for known packages
                if module_name in IMPORT_TO_PACKAGE_ALIASES:
                    for alias in IMPORT_TO_PACKAGE_ALIASES[module_name]:
                        _add_module_location(alias, location)

    return module_locations


def _build_vulnerabilities(
    trivy_data: Optional[Dict[str, Any]],
    used_modules: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    """
    Build vulnerability list from Trivy results with reachability analysis and call evidence.

    Args:
        trivy_data: Trivy scan results containing vulnerability information
        used_modules: Dictionary mapping module names to file paths where they're used
                      (from AST analysis via _extract_used_modules)

    Returns:
        List of vulnerability dictionaries with reachability information and call evidence

    Examples:
        >>> trivy_data = {"vulnerabilities": [{"id": "CVE-1", "package_name": "ruamel.yaml"}]}
        >>> used_modules = {"ruamel": ["app.py", "utils.py"]}
        >>> vulns = _build_vulnerabilities(trivy_data, used_modules)
        >>> vulns[0]["direct_call"]
        True
        >>> "app.py" in vulns[0]["call_example"]
        True
    """
    if not trivy_data:
        return []

    if used_modules is None:
        used_modules = {}

    vulns: List[Dict[str, Any]] = []
    for item in trivy_data.get("vulnerabilities", []) or []:
        cve_id = item.get("id") or item.get("VulnerabilityID")
        if not cve_id:
            continue

        # Extract package name
        package_name = item.get("package_name") or item.get("PkgName") or "unknown"

        # Generate all possible normalized variations of this package name
        package_variants = _normalize_package_name(package_name)

        # Determine if this vulnerability is directly reachable
        # Check if ANY variant of the package name is in used_modules
        direct_call = False
        matched_locations: List[str] = []

        for variant in package_variants:
            if variant in used_modules:
                direct_call = True
                # Collect all file locations for this variant
                matched_locations.extend(used_modules[variant])

        # Build call evidence string
        call_evidence = None
        if direct_call and matched_locations:
            # Remove duplicates and limit to top 3 locations
            unique_locations = list(dict.fromkeys(matched_locations))[:3]
            if unique_locations:
                call_evidence = f"Imported in: {', '.join(unique_locations)}"
                # Add ellipsis if there are more locations
                if len(matched_locations) > 3:
                    call_evidence += f" (and {len(matched_locations) - 3} more)"

        vulns.append(
            {
                "cve_id": cve_id,
                "package": package_name,
                "version": item.get("installed_version")
                or item.get("InstalledVersion")
                or "unknown",
                "severity": (item.get("severity") or item.get("Severity") or "LOW").upper(),
                "description": item.get("description")
                or item.get("Description")
                or "N/A",
                "direct_call": direct_call,
                "call_example": call_evidence,
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


class AnalysisEngine:
    """
    Orchestrator for the analysis pipeline.

    Coordinates multiple specialized services to perform security analysis
    on container images, following the single responsibility principle.
    """

    def __init__(
        self,
        *,
        source_extraction_service: Optional[SourceExtractionService] = None,
        scanner_service: Optional[ScannerService] = None,
        parser_service: Optional[ParserService] = None,
        ast_analysis_service: Optional[ASTAnalysisService] = None,
        enrichment_service: Optional[EnrichmentService] = None,
    ):
        """
        Initialize the AnalysisEngine with dependency injection.

        Args:
            source_extraction_service: Service for extracting sources from container images
            scanner_service: Service for running vulnerability scans
            parser_service: Service for parsing and mapping CVE/API data
            ast_analysis_service: Service for AST analysis
            enrichment_service: Service for priority evaluation and enrichment
        """
        # Initialize services with defaults if not provided
        self.source_extraction = source_extraction_service or SourceExtractionService()
        self.scanner = scanner_service or ScannerService()
        self.parser = parser_service or ParserService()
        self.ast_analysis = ast_analysis_service or ASTAnalysisService()
        self.enrichment = enrichment_service

    def run_pipeline(self, config: PipelineConfig) -> Dict[str, Any]:
        """
        Execute the entire analysis pipeline and return a consolidated result.

        Args:
            config: Pipeline configuration

        Returns:
            Consolidated analysis results including metadata and artifacts
        """
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
        created_at = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

        # Update status to PROCESSING
        create_analysis_status(analysis_id, db_dir, status="PROCESSING")

        # Define output paths
        trivy_output = (db_dir / "trivy_analysis_result.json").resolve()
        mapping_output = (db_dir / "lib2cve2api.json").resolve()
        ast_output_prefix = (db_dir / "ast_visualize").resolve()
        gpt5_output = (db_dir / "gpt5_results.json").resolve()
        fetch_priority_output = (db_dir / "fetch_priority.json").resolve()
        results_dir = (db_dir / "cve_api_mapper_results").resolve()
        raw_dir = (db_dir / "cve_api_mapper_raw").resolve()

        # Configure Perplexity
        perplexity_api_key = config.perplexity_api_key or os.getenv("PERPLEXITY_API_KEY")
        enable_perplexity = config.enable_perplexity or bool(perplexity_api_key)
        if enable_perplexity:
            logger.info("Perplexity case search enabled using PERPLEXITY_API_KEY.")
        else:
            logger.info("Perplexity case search disabled (set PERPLEXITY_API_KEY to enable).")

        # Copy image to analysis directory if needed
        if not _is_path_within(image_path, db_dir):
            stored_image_path = db_dir / image_path.name
            try:
                ensure_dir(stored_image_path.parent)
                shutil.copy2(image_path, stored_image_path)
                image_path = stored_image_path
            except FileNotFoundError:
                logger.warning(
                    "Input image %s not found; proceeding with original path.", image_path
                )

        # CRITICAL STEPS: Fail-fast strategy
        # These steps are essential; if they fail, abort the entire pipeline

        try:
            # Step 1: Extract sources (CRITICAL)
            logger.info("[Pipeline Step 1/6] Extracting application sources...")
            self.source_extraction.extract_sources(
                image_tar=image_path,
                sources_dir=sources_dir,
                app_path=config.app_path,
                include_filter=config.include_filter,
                auto_detect=config.app_path is None,
                force=config.force,
            )
        except SourceExtractionError as e:
            logger.error("CRITICAL: Source extraction failed: %s", e)
            create_analysis_status(
                analysis_id, db_dir, status="FAILED",
                error_message=f"Source extraction failed: {str(e)}"
            )
            raise  # Abort pipeline

        try:
            # Step 2: Run Trivy scan (CRITICAL)
            logger.info("[Pipeline Step 2/6] Running Trivy vulnerability scan...")
            self.scanner.scan_vulnerabilities(
                image_tar=image_path,
                trivy_output=trivy_output,
                full_scan=config.full_scan,
                enhance=config.enhance_trivy,
                force=config.force,
            )
        except ScannerError as e:
            logger.error("CRITICAL: Vulnerability scanning failed: %s", e)
            create_analysis_status(
                analysis_id, db_dir, status="FAILED",
                error_message=f"Vulnerability scanning failed: {str(e)}"
            )
            raise  # Abort pipeline

        try:
            # Step 3: Build library CVE API mapping (CRITICAL)
            logger.info("[Pipeline Step 3/6] Building CVE/API mappings...")
            self.parser.build_library_cve_api_mapping(
                trivy_output=trivy_output,
                mapping_output=mapping_output,
                force=config.force,
            )
        except ParserError as e:
            logger.error("CRITICAL: CVE/API mapping failed: %s", e)
            create_analysis_status(
                analysis_id, db_dir, status="FAILED",
                error_message=f"CVE/API mapping failed: {str(e)}"
            )
            raise  # Abort pipeline

        try:
            # Step 4: Run AST analysis (CRITICAL)
            logger.info("[Pipeline Step 4/6] Analyzing AST and call graphs...")
            ast_json, ast_security_json = self.ast_analysis.analyze_ast(
                source_dir=sources_dir,
                output_prefix=ast_output_prefix,
                trivy_output=trivy_output if config.run_security_analysis else None,
                skip_graph=not config.emit_graph,
                run_security=config.run_security_analysis,
                force=config.force,
            )
        except ASTAnalysisError as e:
            logger.error("CRITICAL: AST analysis failed: %s", e)
            create_analysis_status(
                analysis_id, db_dir, status="FAILED",
                error_message=f"AST analysis failed: {str(e)}"
            )
            raise  # Abort pipeline

        try:
            # Step 5: Run CVE API mapper (CRITICAL)
            logger.info("[Pipeline Step 5/6] Running advanced CVE API mapper...")
            self.parser.run_cve_api_mapper(
                trivy_output=trivy_output,
                mapping_output=mapping_output,
                results_dir=results_dir,
                raw_dir=raw_dir,
                gpt5_output=gpt5_output,
                force=config.force,
            )
        except ParserError as e:
            logger.error("CRITICAL: CVE API mapping failed: %s", e)
            create_analysis_status(
                analysis_id, db_dir, status="FAILED",
                error_message=f"CVE API mapping failed: {str(e)}"
            )
            raise  # Abort pipeline

        # NON-CRITICAL STEP: Fail-safe strategy
        # Step 6: Evaluate patch priorities (AI-powered, may fail gracefully)
        logger.info("[Pipeline Step 6/6] Evaluating patch priorities (optional)...")
        priority_data = None
        enrichment_failed = False

        try:
            if self.enrichment:
                priority_data = self.enrichment.evaluate_patch_priorities(
                    ast_json=ast_json,
                    gpt5_json=gpt5_output,
                    mapping_json=mapping_output,
                    trivy_json=trivy_output,
                    output_json=fetch_priority_output,
                    force=config.force,
                )
            else:
                # Create enrichment service on-the-fly if not injected
                enrichment_service = EnrichmentService(
                    perplexity_api_key=perplexity_api_key,
                    enable_perplexity=enable_perplexity,
                )
                priority_data = enrichment_service.evaluate_patch_priorities(
                    ast_json=ast_json,
                    gpt5_json=gpt5_output,
                    mapping_json=mapping_output,
                    trivy_json=trivy_output,
                    output_json=fetch_priority_output,
                    force=config.force,
                )

            if priority_data is None:
                enrichment_failed = True
                logger.warning(
                    "NON-CRITICAL: AI priority analysis was skipped. "
                    "Continuing with scanner/AST data only."
                )
            else:
                logger.info("AI priority analysis completed successfully")

        except EnrichmentError as e:
            # EnrichmentError is NON-CRITICAL - log and continue
            enrichment_failed = True
            logger.warning(
                "NON-CRITICAL: AI priority analysis failed: %s. "
                "Continuing with scanner/AST data only.", e
            )
        except Exception as e:
            # Catch any unexpected errors from enrichment
            enrichment_failed = True
            logger.warning(
                "NON-CRITICAL: Unexpected error during enrichment: %s: %s. "
                "Continuing with scanner/AST data only.",
                type(e).__name__, str(e)
            )

        # Build and save final response
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
    ast_data = _read_json_if_exists(ast_json)
    ast_security_data = (
        _read_json_if_exists(ast_security_json) if ast_security_json else None
    )
    gpt5_data = _read_json_if_exists(gpt5_json)
    fetch_priority_data = _read_json_if_exists(fetch_priority_json) or {}

    # Phase 2: Reachability Analysis with Call Evidence
    # Extract modules actually used in the codebase from AST analysis
    used_modules = _extract_used_modules(ast_data)
    logger.info(
        "Reachability analysis: Found %d used modules from AST analysis",
        len(used_modules)
    )
    if used_modules:
        # Log module names and sample locations
        logger.debug("Used modules with locations:")
        for module, locations in sorted(used_modules.items())[:10]:  # Show first 10
            loc_preview = locations[0] if locations else "No location"
            logger.debug("  %s: %s%s", module, loc_preview,
                        f" (+{len(locations)-1} more)" if len(locations) > 1 else "")

    language = _infer_primary_language(sources_dir)
    vuln_summary = _build_vulnerability_summary(trivy_data)
    overview_text = _build_overview(vuln_summary, language)
    patch_priority = _build_patch_priority_list(fetch_priority_data)
    killchain_findings = detect_killchains(sources_dir, trivy_data)

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
        "vulnerabilities": _build_vulnerabilities(trivy_data, used_modules),
        "libraries_and_apis": _build_library_api_mappings(mapping_data),
        "patch_priority": patch_priority,
        "killchains" : killchain_findings,
        "logs": [],
    }

    raw_reports = {
        "trivy": trivy_data,
        "library_cve_api_mapping": mapping_data,
        "ast_analysis": ast_data,
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
    """
    Execute the entire pipeline and return a consolidated result.

    This function maintains backward compatibility by delegating to AnalysisEngine.

    Args:
        config: Pipeline configuration

    Returns:
        Consolidated analysis results including metadata and artifacts
    """
    engine = AnalysisEngine()
    return engine.run_pipeline(config)


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
    "AnalysisEngine",
    "run_pipeline",
    "run_security_analysis",
    "process_analysis_background",
    "create_analysis_status",
    "get_analysis_status",
]
