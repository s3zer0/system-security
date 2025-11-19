"""Service for AST call graph and security analysis."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Tuple

from common import ASTResult, read_json, write_json

from ..exceptions import ASTAnalysisError, wrap_exception

logger = logging.getLogger("pipeline.ast_analysis")


class ASTAnalysisService:
    """Handles AST call graph and optional security analysis."""

    def analyze_ast(
        self,
        *,
        source_dir: Path,
        output_prefix: Path,
        trivy_output: Optional[Path] = None,
        skip_graph: bool = False,
        run_security: bool = False,
        force: bool = False,
    ) -> Tuple[Path, Optional[Path]]:
        """
        Run AST call graph and optional security analysis.

        Args:
            source_dir: Directory containing Python source files
            output_prefix: Prefix for output files
            trivy_output: Path to Trivy results for security analysis
            skip_graph: Skip graph generation
            run_security: Run security analysis
            force: Force re-analysis even if results exist

        Returns:
            Tuple of (AST result JSON path, Security analysis JSON path or None)

        Raises:
            ASTAnalysisError: If AST analysis fails for any reason
        """
        try:
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

            # Validate source directory
            if not source_dir.exists():
                raise ASTAnalysisError(
                    f"Source directory not found: {source_dir}"
                )

            if not source_dir.is_dir():
                raise ASTAnalysisError(
                    f"Source path is not a directory: {source_dir}"
                )

            # Collect Python files
            py_files = self._collect_python_files(source_dir)
            if not py_files:
                raise ASTAnalysisError(
                    f"No Python files found under {source_dir}"
                )

            logger.info(
                "Running AST analysis on %d files -> %s", len(py_files), json_output
            )

            # Run AST analysis
            external, internal, unused = self._run_ast_visualization(
                py_files=py_files,
                base_dir=source_dir,
                output_prefix=output_prefix,
                skip_graph=skip_graph,
            )

            # Write results
            result = ASTResult(external=external, internal=internal, unused=unused)
            write_json(json_output, result.to_dict())

            # Verify output was created
            if not json_output.exists():
                raise ASTAnalysisError(
                    f"AST analysis completed but output file was not created: {json_output}"
                )

            logger.info("AST analysis completed successfully: %s", json_output)

            # Run security analysis if requested
            security_output_path = None
            if run_security:
                security_output_path = self._run_security_analysis(
                    external=external,
                    internal=internal,
                    unused=unused,
                    trivy_output=trivy_output,
                    security_json=security_json,
                )

            return json_output, security_output_path

        except ASTAnalysisError:
            # Re-raise our custom exceptions as-is
            raise

        except FileNotFoundError as e:
            logger.error("File not found during AST analysis: %s", e)
            raise wrap_exception(
                ASTAnalysisError,
                f"Required file not found during AST analysis: {e}",
                e
            )

        except PermissionError as e:
            logger.error("Permission denied during AST analysis: %s", e)
            raise wrap_exception(
                ASTAnalysisError,
                f"Permission denied: {e}",
                e
            )

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(
                "Unexpected error during AST analysis: %s: %s",
                type(e).__name__, str(e)
            )
            raise wrap_exception(
                ASTAnalysisError,
                f"Unexpected error during AST analysis: {type(e).__name__}",
                e
            )

    def _collect_python_files(self, root: Path) -> List[Path]:
        """Recursively gather Python files for AST analysis."""
        return [path for path in root.rglob("*.py") if path.is_file()]

    def _run_ast_visualization(
        self,
        *,
        py_files: List[Path],
        base_dir: Path,
        output_prefix: Path,
        skip_graph: bool,
    ) -> Tuple[dict, dict, dict]:
        """
        Run AST visualization and call flow analysis.

        Raises:
            ASTAnalysisError: If visualization fails
        """
        try:
            from ast_visualizer.utils import ast_to_png
        except ImportError as e:
            logger.error("Failed to import AST visualizer: %s", e)
            raise wrap_exception(
                ASTAnalysisError,
                "AST visualizer module not available - ensure dependencies are installed",
                e
            )

        base_dir = base_dir.resolve()
        targets = ast_to_png.parse_target_calls([])

        external, internal, unused = ast_to_png.visualize_call_flow(
            [str(p) for p in py_files],
            str(base_dir),
            str(output_prefix),
            targets,
            force_detection=True,
            no_graph=skip_graph,
        )

        return external, internal, unused

    def _run_security_analysis(
        self,
        *,
        external: dict,
        internal: dict,
        unused: dict,
        trivy_output: Optional[Path],
        security_json: Path,
    ) -> Optional[Path]:
        """Run security posture analysis."""
        try:
            from ast_visualizer.utils.security_analyzer import SecurityAnalyzer
        except ImportError as exc:  # pragma: no cover - optional dependency
            logger.warning("Security analysis disabled (missing dependency): %s", exc)
            return None

        trivy_data = read_json(trivy_output) if trivy_output else None
        analyzer = SecurityAnalyzer()
        analysis = analyzer.analyze_security_posture(
            external_apis=external,
            internal_apis=internal,
            unused_apis=unused,
            vulnerability_data=trivy_data,
        )
        write_json(security_json, analysis)
        return security_json
