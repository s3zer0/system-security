# Analysis Pipeline Services

This directory contains specialized services that follow the **Single Responsibility Principle (SRP)**, refactored from the monolithic analysis engine.

## Architecture Overview

The analysis pipeline uses the **Orchestrator Pattern**, where `AnalysisEngine` coordinates multiple specialized services without performing the actual work itself.

### Service Components

#### 1. SourceExtractionService
**Responsibility**: Extract application sources from container images

**Key Method**: `extract_sources()`
- Extracts application layer from container TAR files
- Supports auto-detection and custom filters
- Handles skipping when sources already exist

#### 2. ScannerService
**Responsibility**: Run Trivy vulnerability scans

**Key Method**: `scan_vulnerabilities()`
- Executes Trivy security scanner
- Optionally enhances vulnerability descriptions
- Manages scan output and caching

#### 3. ParserService
**Responsibility**: Parse Trivy output and build CVE/API mappings

**Key Methods**:
- `build_library_cve_api_mapping()`: Maps libraries to CVEs and APIs
- `run_cve_api_mapper()`: Runs GPT-5 powered CVE-API mapping

#### 4. ASTAnalysisService
**Responsibility**: Perform AST call graph and security analysis

**Key Method**: `analyze_ast()`
- Collects Python files for analysis
- Generates call flow graphs
- Runs optional security posture analysis

#### 5. EnrichmentService
**Responsibility**: Enrich analysis with AI-powered priority evaluation

**Key Method**: `evaluate_patch_priorities()`
- Uses Anthropic Claude for priority analysis
- Optionally integrates Perplexity for case search
- Gracefully handles API failures

## Dependency Injection

All services can be injected into `AnalysisEngine` for flexibility and testability:

```python
from core.analysis_engine import AnalysisEngine
from core.services import ScannerService, ParserService

# Custom services
scanner = ScannerService()
parser = ParserService()

# Inject into engine
engine = AnalysisEngine(
    scanner_service=scanner,
    parser_service=parser
)

# Run pipeline
result = engine.run_pipeline(config)
```

## Backward Compatibility

The original `run_pipeline()` function is preserved and delegates to `AnalysisEngine`:

```python
from core.analysis_engine import run_pipeline, PipelineConfig

# Old way still works
config = PipelineConfig(image_path=path, db_dir=db)
result = run_pipeline(config)
```

## Benefits of Refactoring

1. **Single Responsibility**: Each service has one clear purpose
2. **Testability**: Services can be tested in isolation
3. **Maintainability**: Changes to one service don't affect others
4. **Flexibility**: Services can be replaced or mocked
5. **Extensibility**: New services can be added without modifying existing code
