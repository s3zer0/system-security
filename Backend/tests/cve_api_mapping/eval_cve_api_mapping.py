#!/usr/bin/env python3
"""Evaluate CVE→API mapping quality for multiple LLM-backed mappers."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Sequence,
    Tuple,
)

from dotenv import load_dotenv

# Ensure the Backend root directory is importable when running from repo root.
SCRIPT_DIR = Path(__file__).resolve().parent
# Tests live inside Backend/tests/, so go up two levels to reach the repo root.
BACKEND_ROOT = SCRIPT_DIR.parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from cve_api_mapper.mapper.cve_api_mapper import (  # type: ignore  # noqa: E402
    GPTClient,
    ClaudeClient,
    GeminiClient,
    GrokClient,
    LLMClient,
)

logger = logging.getLogger(__name__)

DEFAULT_CASES = BACKEND_ROOT / "tests" / "cve_api_mapping" / "dataset.json"
DEFAULT_OUTPUT = BACKEND_ROOT / "tests" / "cve_api_eval_results_v1.json"
DEFAULT_MODELS = ["gpt-5", "claude-sonnet-4.5", "gemini-2.5-pro", "grok-4"]

REQUIRED_FIELDS = (
    "id",
    "cve_id",
    "package",
    "language",
    "ecosystem",
    "version_range",
    "short_description",
    "expected_apis",
)


class BenchmarkError(RuntimeError):
    """Raised for configuration issues that should abort evaluation."""


class MappingModel(Protocol):
    """Protocol that all mapping model adapters must implement."""

    name: str

    def map_apis(self, case: "EvalCase") -> Tuple[List[str], bool]:
        """Return predicted APIs and parse_error flag for a given case."""


@dataclass
class EvalCase:
    """Structured representation of an evaluation case."""

    id: str
    cve_id: str
    package: str
    language: str
    ecosystem: str
    version_range: str
    short_description: str
    expected_apis: List[str]
    api_dict: Dict[str, List[str]]


class ClientMappingModel:
    """Adapter that wires the shared LLM client interface into this evaluator."""

    def __init__(self, name: str, client: LLMClient):
        self.name = name
        self._client = client

    def map_apis(self, case: EvalCase) -> Tuple[List[str], bool]:
        cve_descriptions = [(case.cve_id, case.short_description)]
        try:
            _, mapping = self._client.query(
                case.package,
                case.version_range,
                case.api_dict,
                cve_descriptions,
            )
        except Exception:
            logger.exception("Model %s failed for case %s", self.name, case.id)
            return ([], True)

        if mapping is None or not isinstance(mapping, Mapping):
            return ([], True)

        entry = _locate_case_entry(mapping, case.cve_id)
        if not isinstance(entry, Mapping):
            return ([], False)

        apis = entry.get("apis", [])
        if isinstance(apis, Sequence):
            return (_clean_string_list(apis), False)
        return ([], False)


ModelFactory = Callable[[str], LLMClient]
MODEL_SPECS: Dict[str, Tuple[str, ModelFactory]] = {
    "gpt-5": ("OPENAI_API_KEY", lambda key: GPTClient(key, "gpt-5")),
    "claude-sonnet-4.5": (
        "ANTHROPIC_API_KEY",
        lambda key: ClaudeClient(key, "claude-sonnet-4-5-20250929"),
    ),
    "gemini-2.5-pro": ("GOOGLE_API_KEY", lambda key: GeminiClient(key, "gemini-2.5-pro")),
    "grok-4": ("XAI_API_KEY", lambda key: GrokClient(key, "grok-4")),
}

MODEL_ALIASES: Dict[str, str] = {
    "gpt": "gpt-5",
    "gpt5": "gpt-5",
    "openai": "gpt-5",
    "claude": "claude-sonnet-4.5",
    "claude-sonnet": "claude-sonnet-4.5",
    "claude-sonnet-4-5-20250929": "claude-sonnet-4.5",
    "sonnet": "claude-sonnet-4.5",
    "gemini": "gemini-2.5-pro",
    "gemini-2.5": "gemini-2.5-pro",
    "grok": "grok-4",
    "xai": "grok-4",
}


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        type=Path,
        default=DEFAULT_CASES,
        help=f"Path to benchmark dataset (default: {DEFAULT_CASES})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Path to evaluation output JSON (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--models",
        type=str,
        default=None,
        help="Comma-separated model list (e.g. 'gpt5,claude,gemini,grok'). "
        "Defaults to all supported models when omitted.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        help="Logging level (default: INFO)",
    )
    return parser.parse_args(argv)


def configure_logging(level: str) -> None:
    """Initialize root logger configuration."""
    resolved_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=resolved_level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )


def read_json(path: Path) -> Any:
    """Load JSON data from disk."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise BenchmarkError(f"Input file '{path}' not found.") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkError(f"Input file '{path}' is not valid JSON: {exc}") from exc


def write_json(path: Path, payload: Mapping[str, Any]) -> None:
    """Persist JSON data to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def resolve_cli_path(path: Path, require_exists: bool) -> Path:
    """Resolve user-provided paths regardless of the current working directory."""
    expanded = path.expanduser()
    candidates = []

    if expanded.is_absolute():
        candidates.append(expanded)
    else:
        cwd_candidate = (Path.cwd() / expanded).resolve()
        candidates.append(cwd_candidate)
        candidates.append((BACKEND_ROOT / expanded).resolve())
        candidates.append((BACKEND_ROOT.parent / expanded).resolve())

    if require_exists:
        for candidate in candidates:
            if candidate.exists():
                return candidate
    else:
        for candidate in candidates:
            if candidate.parent.exists():
                return candidate
    return candidates[0]


def parse_model_list(raw: Optional[str]) -> Optional[List[str]]:
    """Split comma/space separated model names."""
    if raw is None:
        return None
    tokens = [chunk.strip() for chunk in raw.replace(",", " ").split() if chunk.strip()]
    return tokens or None


def build_model_adapters(model_names: Optional[Iterable[str]]) -> MutableMapping[str, MappingModel]:
    """Instantiate adapters for the requested models."""
    requested = list(model_names) if model_names else list(DEFAULT_MODELS)
    canonical: List[str] = []
    for name in requested:
        normalized = MODEL_ALIASES.get(name.lower(), name)
        canonical.append(normalized)

    load_dotenv()

    adapters: MutableMapping[str, MappingModel] = {}
    for name in canonical:
        if name in adapters:
            continue
        spec = MODEL_SPECS.get(name)
        if not spec:
            raise BenchmarkError(
                f"Unknown model '{name}'. Supported models: {', '.join(MODEL_SPECS)}"
            )
        env_key, factory = spec
        api_key = os.getenv(env_key)
        if not api_key:
            logger.warning("Skipping model %s because %s is not set.", name, env_key)
            continue
        adapters[name] = ClientMappingModel(name, factory(api_key))
        logger.info("Initialized mapping model: %s", name)

    if not adapters:
        raise BenchmarkError("No model clients initialized. Check API keys or --models input.")
    return adapters


def load_cases(path: Path) -> Tuple[List[EvalCase], int, int]:
    """Load all eval cases, returning (valid_cases, skipped_count, total_count)."""
    payload = read_json(path)
    if not isinstance(payload, list):
        raise BenchmarkError(f"Case file '{path}' must contain a JSON list.")

    cases: List[EvalCase] = []
    skipped = 0
    for index, entry in enumerate(payload):
        case = _build_case(entry, index)
        if case is None:
            skipped += 1
            continue
        cases.append(case)
    return cases, skipped, len(payload)


def _build_case(entry: Any, index: int) -> Optional[EvalCase]:
    """Validate and normalize a single case."""
    if not isinstance(entry, Mapping):
        logger.warning("Skipping non-dict case at index %s.", index)
        return None

    missing = [field for field in REQUIRED_FIELDS if field not in entry]
    if missing:
        logger.warning(
            "Skipping case %s due to missing fields: %s",
            entry.get("id", f"#{index}"),
            ", ".join(missing),
        )
        return None

    expected = _clean_string_list(entry["expected_apis"])
    if not expected:
        logger.warning("Case %s has empty expected_apis; skipping.", entry.get("id"))
        return None

    api_dict = _determine_api_dict(entry, expected)
    return EvalCase(
        id=str(entry["id"]),
        cve_id=str(entry["cve_id"]),
        package=str(entry["package"]),
        language=str(entry["language"]),
        ecosystem=str(entry["ecosystem"]),
        version_range=str(entry["version_range"]),
        short_description=str(entry["short_description"]),
        expected_apis=expected,
        api_dict=api_dict,
    )


def _determine_api_dict(entry: Mapping[str, Any], fallback: Sequence[str]) -> Dict[str, List[str]]:
    """Build the API dictionary supplied to the mapper prompt."""
    candidates = entry.get("api_candidates")
    api_dict: Dict[str, List[str]] = {}

    if isinstance(candidates, Mapping):
        for module, apis in candidates.items():
            if isinstance(apis, Sequence):
                cleaned = _clean_string_list(apis)
                if cleaned:
                    api_dict[str(module)] = cleaned
    elif isinstance(candidates, Sequence):
        cleaned = _clean_string_list(candidates)
        if cleaned:
            api_dict["__candidates__"] = cleaned

    if not api_dict and fallback:
        api_dict["__expected__"] = list(fallback)
        logger.info(
            "Case %s missing API candidates; using expected APIs as prompt candidates.",
            entry.get("id"),
        )

    return api_dict


def evaluate_cases(
    cases: Sequence[EvalCase],
    models: Mapping[str, MappingModel],
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Run evaluation for all cases and models."""
    per_case: List[Dict[str, Any]] = []
    summary: Dict[str, Dict[str, float]] = {
        name: {"precision": 0.0, "recall": 0.0, "f1": 0.0, "count": 0.0, "parse_errors": 0.0}
        for name in models.keys()
    }

    for case in cases:
        case_result = {
            "id": case.id,
            "cve_id": case.cve_id,
            "package": case.package,
            "language": case.language,
            "ecosystem": case.ecosystem,
            "version_range": case.version_range,
            "short_description": case.short_description,
            "expected_apis": list(case.expected_apis),
            "models": {},
        }
        for name, model in models.items():
            predicted, parse_error = model.map_apis(case)
            precision, recall, f1 = compute_metrics(predicted, case.expected_apis)
            stats = summary[name]
            stats["precision"] += precision
            stats["recall"] += recall
            stats["f1"] += f1
            stats["count"] += 1
            if parse_error:
                stats["parse_errors"] += 1

            case_result["models"][name] = {
                "predicted_apis": predicted,
                "precision": _round_metric(precision),
                "recall": _round_metric(recall),
                "f1": _round_metric(f1),
                "parse_error": bool(parse_error),
            }
        per_case.append(case_result)

    summary_payload: Dict[str, Dict[str, Any]] = {}
    for name, stats in summary.items():
        count = int(stats["count"])
        summary_payload[name] = {
            "avg_precision": _round_metric(stats["precision"] / count) if count else 0.0,
            "avg_recall": _round_metric(stats["recall"] / count) if count else 0.0,
            "avg_f1": _round_metric(stats["f1"] / count) if count else 0.0,
            "num_cases": count,
            "num_parse_errors": int(stats["parse_errors"]),
        }
    return per_case, summary_payload


def compute_metrics(predicted: Sequence[str], expected: Sequence[str]) -> Tuple[float, float, float]:
    """Compute precision, recall, and F1 for two API sets."""
    pred_set = {_normalize_api(api) for api in predicted if api}
    exp_set = {_normalize_api(api) for api in expected if api}

    true_positive = len(pred_set & exp_set)
    precision = true_positive / len(pred_set) if pred_set else 0.0
    recall = true_positive / len(exp_set) if exp_set else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return precision, recall, f1


def _normalize_api(value: str) -> str:
    """Normalize API strings for comparison."""
    return value.strip().lower()


def _clean_string_list(values: Sequence[Any]) -> List[str]:
    """Convert arbitrary sequences to de-duplicated string lists."""
    cleaned: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        cleaned.append(text)
    return cleaned


def _round_metric(value: float) -> float:
    """Round metric values for a cleaner JSON output."""
    return round(value, 4)


def _locate_case_entry(mapping: Mapping[Any, Any], cve_id: str) -> Optional[Mapping[str, Any]]:
    """Best-effort lookup for the CVE entry inside a model response."""
    entry = mapping.get(cve_id)
    if isinstance(entry, Mapping):
        return entry

    lowered = cve_id.lower()
    for key, value in mapping.items():
        if isinstance(key, str) and key.lower() == lowered and isinstance(value, Mapping):
            return value

    if len(mapping) == 1:
        lone_value = next(iter(mapping.values()))
        if isinstance(lone_value, Mapping):
            return lone_value
    return None


def run(argv: Optional[Sequence[str]] = None) -> int:
    """Script entry point."""
    args = parse_args(argv)
    configure_logging(args.log_level)

    try:
        model_names = parse_model_list(args.models)
        models = build_model_adapters(model_names)
        cases_path = resolve_cli_path(args.cases, require_exists=True)
        output_path = resolve_cli_path(args.output, require_exists=False)
        cases, skipped, total = load_cases(cases_path)
        per_case, summary = evaluate_cases(cases, models)

        payload = {
            "meta": {
                "num_cases": total,
                "models": list(models.keys()),
                "skipped_cases": skipped,
            },
            "per_case": per_case,
            "summary": summary,
        }
        write_json(output_path, payload)
        logger.info("Saved evaluation results to %s", output_path)
        return 0
    except BenchmarkError as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(run())
