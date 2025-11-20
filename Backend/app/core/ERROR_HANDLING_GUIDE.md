# Global Error Handling & Resiliency Guide

이 문서는 Backend/app/core에 구현된 글로벌 에러 핸들링 시스템을 설명합니다.

## 📋 목차

1. [개요](#개요)
2. [커스텀 예외 계층](#커스텀-예외-계층)
3. [Fail-Fast vs Fail-Safe 전략](#fail-fast-vs-fail-safe-전략)
4. [서비스별 에러 핸들링](#서비스별-에러-핸들링)
5. [오케스트레이터 레벨 처리](#오케스트레이터-레벨-처리)
6. [테스트](#테스트)

---

## 개요

분석 파이프라인은 **표준화된 예외 처리 정책**을 적용하여 안정성과 복원력을 제공합니다:

### ✅ 핵심 원칙

1. **절대 에러를 삼키지 않음** - 모든 에러는 로깅되거나 상위로 전파
2. **구체적 예외 래핑** - 저수준 에러를 도메인 예외로 감싸기
3. **Fail-Fast for Critical** - 필수 단계 실패 시 즉시 중단
4. **Fail-Safe for Optional** - 선택적 단계 실패 시 계속 진행
5. **명확한 에러 메시지** - 실패 원인과 컨텍스트 제공

---

## 커스텀 예외 계층

### 구조 (`core/exceptions.py`)

```
AnalysisError (Base Exception)
├── SourceExtractionError  [CRITICAL]
├── ScannerError           [CRITICAL]
├── ParserError            [CRITICAL]
├── ASTAnalysisError       [CRITICAL]
└── EnrichmentError        [NON-CRITICAL]
```

### 사용 예시

```python
from core.exceptions import ScannerError, wrap_exception

try:
    trivy_func.scan_vulnerabilities(...)
except subprocess.CalledProcessError as e:
    logger.error("Trivy subprocess failed: %s", e)
    raise wrap_exception(
        ScannerError,
        "Trivy command failed with exit code",
        e
    )
```

### 예외 속성

```python
class AnalysisError(Exception):
    def __init__(self, message: str, cause: Optional[Exception] = None):
        self.message = message  # 사람이 읽을 수 있는 메시지
        self.cause = cause      # 원인이 된 예외 (체이닝)
```

---

## Fail-Fast vs Fail-Safe 전략

### 🚨 Fail-Fast (Critical Errors)

**적용 대상:**
- `SourceExtractionError` - 소스 코드 추출 필수
- `ScannerError` - 취약점 스캔 필수
- `ParserError` - CVE/API 매핑 필수
- `ASTAnalysisError` - AST 분석 필수

**동작:**
```python
try:
    self.scanner.scan_vulnerabilities(...)
except ScannerError as e:
    logger.error("CRITICAL: Vulnerability scanning failed: %s", e)
    create_analysis_status(analysis_id, db_dir, status="FAILED", ...)
    raise  # ⚠️ 파이프라인 중단
```

**결과:**
- 파이프라인 즉시 중단
- 상태를 `FAILED`로 설정
- 에러 메시지 기록
- 예외를 상위로 전파

---

### 🔄 Fail-Safe (Non-Critical Errors)

**적용 대상:**
- `EnrichmentError` - AI 우선순위 평가는 선택사항

**동작:**
```python
try:
    priority_data = enrichment_service.evaluate_patch_priorities(...)
except EnrichmentError as e:
    logger.warning("NON-CRITICAL: AI priority analysis failed: %s", e)
    # ✅ 계속 진행 (중단하지 않음)
    enrichment_failed = True
except Exception as e:
    logger.warning("NON-CRITICAL: Unexpected enrichment error: %s", e)
    enrichment_failed = True
```

**결과:**
- 파이프라인 계속 진행
- 실패를 로깅 (WARNING 레벨)
- 결과에 enrichment 실패 표시
- 상태는 `COMPLETED`로 유지

---

## 서비스별 에러 핸들링

### 1. SourceExtractionService

**잡는 에러:**
- `FileNotFoundError` → 이미지 파일 없음
- `subprocess.CalledProcessError` → 추출 명령 실패
- `PermissionError` → 권한 거부

**검증:**
- 입력 파일 존재 확인
- 출력 디렉토리 비어있지 않은지 확인
- 에러 로깅 후 `SourceExtractionError`로 감싸기

```python
try:
    if not image_tar.exists():
        raise SourceExtractionError(f"Image not found: {image_tar}")

    extract_app_layer(...)

    if not sources_dir.exists() or not any(sources_dir.iterdir()):
        raise SourceExtractionError("Output directory is empty")

except FileNotFoundError as e:
    logger.error("File not found: %s", e)
    raise wrap_exception(SourceExtractionError, "Required file not found", e)
```

---

### 2. ScannerService

**잡는 에러:**
- `ImportError` → Trivy 모듈 없음
- `subprocess.CalledProcessError` → Trivy 실행 실패
- `FileNotFoundError` → 입력 파일 없음

**검증:**
- Trivy 모듈 import 가능한지 확인
- 출력 파일이 생성되었는지 확인
- 출력 파일이 비어있지 않은지 확인

```python
try:
    from trivy_extracter.trivy_module import trivy_func
except ImportError as e:
    raise wrap_exception(ScannerError, "Trivy module not available", e)

trivy_func.scan_vulnerabilities(...)

if not trivy_output.exists():
    raise ScannerError("Output file was not created")

if trivy_output.stat().st_size == 0:
    raise ScannerError("Output file is empty")
```

---

### 3. ParserService

**잡는 에러:**
- `json.JSONDecodeError` → 잘못된 JSON
- `ImportError` → API extractor 없음
- `FileNotFoundError` → 입력 파일 없음

**검증:**
- Trivy 출력이 유효한 JSON인지 확인
- Trivy 데이터가 비어있지 않은지 확인
- 매핑 결과가 생성되었는지 확인

```python
try:
    trivy_data = read_json(trivy_output)
except json.JSONDecodeError as e:
    raise wrap_exception(ParserError, "Invalid JSON in Trivy output", e)

if not trivy_data:
    raise ParserError("Trivy output is empty")
```

---

### 4. ASTAnalysisService

**잡는 에러:**
- `ImportError` → AST visualizer 없음
- `FileNotFoundError` → 소스 디렉토리 없음
- `PermissionError` → 권한 거부

**검증:**
- 소스 디렉토리가 존재하고 디렉토리인지 확인
- Python 파일이 하나 이상 있는지 확인
- 분석 결과가 생성되었는지 확인

```python
if not source_dir.exists():
    raise ASTAnalysisError(f"Source directory not found: {source_dir}")

if not source_dir.is_dir():
    raise ASTAnalysisError(f"Source path is not a directory: {source_dir}")

py_files = self._collect_python_files(source_dir)
if not py_files:
    raise ASTAnalysisError("No Python files found")
```

---

### 5. EnrichmentService

**특별 처리 (NON-CRITICAL):**
- 모든 에러를 내부에서 catch
- 항상 `None` 반환하거나 skipped 파일 작성
- 예외를 상위로 전파하지 않음

```python
try:
    # Validate input files
    missing_files = []
    for name, path in [...]:
        if not path.exists():
            missing_files.append(f"{name}: {path}")

    if missing_files:
        logger.warning("Missing files. Skipping enrichment.")
        self._write_skipped_priority_file(...)
        return None

    # Run analysis
    evaluator.run_analysis(...)

except Exception as exc:
    logger.error("AI priority analysis failed: %s", exc)
    self._write_skipped_priority_file(...)
    return None  # ✅ 예외 전파 안 함
```

---

## 오케스트레이터 레벨 처리

### AnalysisEngine.run_pipeline()

**구조:**

```python
# CRITICAL STEPS (Fail-Fast)
try:
    logger.info("[Pipeline Step 1/6] Extracting sources...")
    self.source_extraction.extract_sources(...)
except SourceExtractionError as e:
    logger.error("CRITICAL: Source extraction failed: %s", e)
    create_analysis_status(analysis_id, db_dir, status="FAILED", ...)
    raise  # Abort

try:
    logger.info("[Pipeline Step 2/6] Running Trivy scan...")
    self.scanner.scan_vulnerabilities(...)
except ScannerError as e:
    logger.error("CRITICAL: Scanner failed: %s", e)
    create_analysis_status(analysis_id, db_dir, status="FAILED", ...)
    raise  # Abort

# ... (Parser, AST 동일)

# NON-CRITICAL STEP (Fail-Safe)
try:
    logger.info("[Pipeline Step 6/6] Evaluating priorities (optional)...")
    priority_data = enrichment_service.evaluate_patch_priorities(...)

    if priority_data is None:
        logger.warning("AI analysis skipped. Continuing...")
    else:
        logger.info("AI analysis completed successfully")

except EnrichmentError as e:
    logger.warning("NON-CRITICAL: Enrichment failed: %s. Continuing...", e)
except Exception as e:
    logger.warning("NON-CRITICAL: Unexpected enrichment error. Continuing...")
```

**흐름:**

```
┌─────────────────────────────────────────────────┐
│ Pipeline Start                                  │
└─────────────────────────────────────────────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ Step 1: Extract       │ ─── CRITICAL
        └───────────────────────┘
                    │
              [Error?]─────────► ABORT (Fail-Fast)
                    │
                    ▼
        ┌───────────────────────┐
        │ Step 2: Scanner       │ ─── CRITICAL
        └───────────────────────┘
                    │
              [Error?]─────────► ABORT (Fail-Fast)
                    │
                    ▼
        ┌───────────────────────┐
        │ Step 3: Parser        │ ─── CRITICAL
        └───────────────────────┘
                    │
              [Error?]─────────► ABORT (Fail-Fast)
                    │
                    ▼
        ┌───────────────────────┐
        │ Step 4: AST Analysis  │ ─── CRITICAL
        └───────────────────────┘
                    │
              [Error?]─────────► ABORT (Fail-Fast)
                    │
                    ▼
        ┌───────────────────────┐
        │ Step 5: CVE Mapper    │ ─── CRITICAL
        └───────────────────────┘
                    │
              [Error?]─────────► ABORT (Fail-Fast)
                    │
                    ▼
        ┌───────────────────────┐
        │ Step 6: Enrichment    │ ─── NON-CRITICAL
        └───────────────────────┘
                    │
              [Error?]─────────► LOG & CONTINUE (Fail-Safe)
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│ Pipeline Complete (Status: COMPLETED)           │
└─────────────────────────────────────────────────┘
```

---

## 테스트

### 실행 방법

```bash
cd Backend
PYTHONPATH=. python3 app/tests/test_error_handling.py
```

### 테스트 항목

1. **Critical Error Abort Test**
   - SourceExtractionError → 파이프라인 중단
   - ScannerError → 파이프라인 중단
   - ParserError → 파이프라인 중단
   - ASTAnalysisError → 파이프라인 중단

2. **Non-Critical Continue Test**
   - EnrichmentError → 파이프라인 계속
   - 모든 critical 서비스 실행됨
   - 상태는 COMPLETED

3. **Exception Hierarchy Test**
   - 모든 예외가 `AnalysisError` 상속
   - 예외 인스턴스화 가능
   - 원인 예외 래핑 가능

4. **Service Error Wrapping Test**
   - `wrap_exception()` 함수 작동
   - 예외 체이닝 정상

5. **Pipeline Logging Test**
   - 에러 발생 시 로깅됨
   - 적절한 로그 레벨 사용

### 테스트 결과

```
============================================================
📊 Error Handling Test Results
============================================================
   ✅ PASS: Critical Error Abort
   ✅ PASS: Non-Critical Continue
   ✅ PASS: Exception Hierarchy
   ✅ PASS: Service Error Wrapping
   ✅ PASS: Pipeline Logging

   Total: 5/5 tests passed

🎉🎉🎉 ALL ERROR HANDLING TESTS PASSED! 🎉🎉🎉
```

---

## 모범 사례

### ✅ DO

```python
# 1. 구체적 예외로 감싸기
try:
    risky_operation()
except subprocess.CalledProcessError as e:
    logger.error("Command failed: %s", e)
    raise wrap_exception(ScannerError, "Trivy failed", e)

# 2. 검증 후 즉시 실패
if not input_file.exists():
    raise ScannerError(f"Input file not found: {input_file}")

# 3. 성공 로깅
logger.info("Scan completed successfully: %s", output_file)
```

### ❌ DON'T

```python
# 1. 에러 삼키기 (절대 금지!)
try:
    risky_operation()
except Exception:
    pass  # ❌ 절대 금지!

# 2. 로깅 없이 return None
if something_failed:
    return None  # ❌ 로깅 없음!

# 3. 일반 Exception raise
if error:
    raise Exception("Something failed")  # ❌ 너무 일반적!
```

---

## 요약

| 단계 | 서비스 | 예외 | 전략 | 실패 시 |
|------|--------|------|------|---------|
| 1 | SourceExtraction | `SourceExtractionError` | Fail-Fast | 파이프라인 중단 |
| 2 | Scanner | `ScannerError` | Fail-Fast | 파이프라인 중단 |
| 3 | Parser | `ParserError` | Fail-Fast | 파이프라인 중단 |
| 4 | ASTAnalysis | `ASTAnalysisError` | Fail-Fast | 파이프라인 중단 |
| 5 | CVE Mapper | `ParserError` | Fail-Fast | 파이프라인 중단 |
| 6 | Enrichment | `EnrichmentError` | Fail-Safe | 로깅 & 계속 |

---

## 참고 자료

- `core/exceptions.py` - 예외 정의
- `core/services/*.py` - 서비스별 에러 핸들링 구현
- `core/analysis_engine.py` - 오케스트레이터 레벨 처리
- `tests/test_error_handling.py` - 에러 핸들링 테스트

---

**작성:** 2025-01-20
**버전:** 1.0
**상태:** Production Ready ✅
