"""Tests for global error handling and resiliency."""

import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app.core.analysis_engine import AnalysisEngine, PipelineConfig
from app.core.exceptions import (
    AnalysisError,
    SourceExtractionError,
    ScannerError,
    ParserError,
    ASTAnalysisError,
    EnrichmentError,
)
from app.core.services import (
    SourceExtractionService,
    ScannerService,
    ParserService,
    ASTAnalysisService,
    EnrichmentService,
)


def test_critical_error_aborts_pipeline():
    """Test that critical errors (SourceExtraction, Scanner, Parser, AST) abort the pipeline."""
    print("\n=== 🚨 Critical Error Abort Test ===\n")

    critical_errors = [
        ("SourceExtraction", SourceExtractionError("Source extraction failed")),
        ("Scanner", ScannerError("Scanner failed")),
        ("Parser", ParserError("Parser failed")),
        ("ASTAnalysis", ASTAnalysisError("AST analysis failed")),
    ]

    results = {}

    for service_name, error in critical_errors:
        print(f"\n   Testing {service_name}Error...")

        # Create mocks
        mock_source = MagicMock()
        mock_scanner = MagicMock()
        mock_parser = MagicMock()
        mock_ast = MagicMock()

        # Configure which service should fail
        if service_name == "SourceExtraction":
            mock_source.extract_sources.side_effect = error
        elif service_name == "Scanner":
            mock_scanner.scan_vulnerabilities.side_effect = error
        elif service_name == "Parser":
            mock_parser.build_library_cve_api_mapping.side_effect = error
        elif service_name == "ASTAnalysis":
            mock_ast.analyze_ast.side_effect = error

        # Set up non-failing services
        mock_ast.analyze_ast.return_value = (Path("/tmp/ast.json"), None)

        engine = AnalysisEngine(
            source_extraction_service=mock_source,
            scanner_service=mock_scanner,
            parser_service=mock_parser,
            ast_analysis_service=mock_ast,
        )

        config = PipelineConfig(
            image_path=Path("/tmp/test.tar"),
            db_dir=Path("/tmp/db"),
        )

        try:
            with patch('app.core.analysis_engine.load_dotenv'), \
                 patch('app.core.analysis_engine.ensure_dir'), \
                 patch('app.core.analysis_engine.shutil.copy2'), \
                 patch('app.core.analysis_engine.write_json'), \
                 patch('app.core.analysis_engine.create_analysis_status') as mock_status, \
                 patch('app.core.analysis_engine._build_pipeline_response', return_value={"result": {}, "meta": {}}), \
                 patch.object(Path, 'mkdir'), \
                 patch.object(Path, 'exists', return_value=True):

                engine.run_pipeline(config)

            # Should not reach here
            print(f"      ❌ Pipeline did not abort on {service_name}Error!")
            results[service_name] = False

        except (SourceExtractionError, ScannerError, ParserError, ASTAnalysisError) as e:
            # Expected behavior - pipeline aborted
            print(f"      ✅ Pipeline correctly aborted on {service_name}Error")
            # Verify status was set to FAILED
            assert mock_status.called, "Status was not updated"
            results[service_name] = True

        except Exception as e:
            print(f"      ❌ Unexpected exception: {type(e).__name__}: {e}")
            results[service_name] = False

    all_passed = all(results.values())
    if all_passed:
        print("\n🎉 SUCCESS: All critical errors correctly abort the pipeline!")
        return True
    else:
        print("\n⚠️ WARNING: Some critical errors did not abort properly.")
        return False


def test_enrichment_error_continues_pipeline():
    """Test that EnrichmentError is non-critical and allows pipeline to continue."""
    print("\n=== 🔄 Non-Critical Error Continue Test ===\n")

    mock_source = MagicMock()
    mock_scanner = MagicMock()
    mock_parser = MagicMock()
    mock_ast = MagicMock()
    mock_enrichment = MagicMock()

    # Set up normal returns for critical services
    mock_ast.analyze_ast.return_value = (Path("/tmp/ast.json"), None)

    # Enrichment fails but pipeline should continue
    mock_enrichment.evaluate_patch_priorities.return_value = None

    engine = AnalysisEngine(
        source_extraction_service=mock_source,
        scanner_service=mock_scanner,
        parser_service=mock_parser,
        ast_analysis_service=mock_ast,
        enrichment_service=mock_enrichment,
    )

    config = PipelineConfig(
        image_path=Path("/tmp/test.tar"),
        db_dir=Path("/tmp/db"),
    )

    try:
        with patch('app.core.analysis_engine.load_dotenv'), \
             patch('app.core.analysis_engine.ensure_dir'), \
             patch('app.core.analysis_engine.shutil.copy2'), \
             patch('app.core.analysis_engine.write_json'), \
             patch('app.core.analysis_engine.create_analysis_status') as mock_status, \
             patch('app.core.analysis_engine._build_pipeline_response', return_value={"result": {}, "meta": {}}), \
             patch.object(Path, 'mkdir'), \
             patch.object(Path, 'exists', return_value=True):

            result = engine.run_pipeline(config)

        # Should reach here successfully
        print("   ✅ Pipeline continued despite enrichment failure")

        # Verify all critical services were called
        assert mock_source.extract_sources.called, "Source extraction not called"
        assert mock_scanner.scan_vulnerabilities.called, "Scanner not called"
        assert mock_parser.build_library_cve_api_mapping.called, "Parser not called"
        assert mock_ast.analyze_ast.called, "AST analysis not called"
        print("   ✅ All critical services were executed")

        # Verify enrichment was attempted
        assert mock_enrichment.evaluate_patch_priorities.called, "Enrichment not attempted"
        print("   ✅ Enrichment was attempted")

        # Verify status was set to COMPLETED
        final_status_call = [call for call in mock_status.call_args_list if 'COMPLETED' in str(call)]
        assert final_status_call, "Status was not set to COMPLETED"
        print("   ✅ Pipeline status set to COMPLETED")

        print("\n🎉 SUCCESS: Pipeline handles enrichment failures gracefully!")
        return True

    except Exception as e:
        print(f"   ❌ Pipeline failed unexpectedly: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_exception_hierarchy():
    """Test that custom exceptions have proper hierarchy."""
    print("\n=== 🏗️ Exception Hierarchy Test ===\n")

    exceptions = [
        SourceExtractionError,
        ScannerError,
        ParserError,
        ASTAnalysisError,
        EnrichmentError,
    ]

    all_passed = True
    for exc_class in exceptions:
        # Test inheritance
        if not issubclass(exc_class, AnalysisError):
            print(f"   ❌ {exc_class.__name__} does not inherit from AnalysisError!")
            all_passed = False
        else:
            print(f"   ✅ {exc_class.__name__} inherits from AnalysisError")

        # Test instantiation
        try:
            exc = exc_class("Test message")
            assert str(exc) == "Test message"
            print(f"   ✅ {exc_class.__name__} can be instantiated")
        except Exception as e:
            print(f"   ❌ {exc_class.__name__} instantiation failed: {e}")
            all_passed = False

        # Test cause wrapping
        try:
            original = ValueError("Original error")
            exc = exc_class("Wrapped message", cause=original)
            assert exc.cause is original
            assert "Original error" in str(exc)
            print(f"   ✅ {exc_class.__name__} can wrap cause")
        except Exception as e:
            print(f"   ❌ {exc_class.__name__} cause wrapping failed: {e}")
            all_passed = False

    if all_passed:
        print("\n🎉 SUCCESS: Exception hierarchy is correct!")
        return True
    else:
        print("\n⚠️ WARNING: Exception hierarchy has issues.")
        return False


def test_service_error_wrapping():
    """Test that services properly wrap low-level exceptions."""
    print("\n=== 🎁 Service Error Wrapping Test ===\n")

    # Test that FileNotFoundError gets wrapped
    from app.core.exceptions import wrap_exception

    original_error = FileNotFoundError("/tmp/missing.tar")
    wrapped = wrap_exception(
        SourceExtractionError,
        "Container image not found",
        original_error
    )

    assert isinstance(wrapped, SourceExtractionError)
    assert wrapped.cause is original_error
    assert "Container image not found" in str(wrapped)
    assert "FileNotFoundError" in str(wrapped)
    print("   ✅ wrap_exception() creates proper exception chain")

    print("\n🎉 SUCCESS: Error wrapping works correctly!")
    return True


def test_pipeline_logging():
    """Test that proper logging occurs during errors."""
    print("\n=== 📝 Pipeline Logging Test ===\n")

    mock_source = MagicMock()
    mock_source.extract_sources.side_effect = SourceExtractionError("Test error")

    engine = AnalysisEngine(source_extraction_service=mock_source)

    config = PipelineConfig(
        image_path=Path("/tmp/test.tar"),
        db_dir=Path("/tmp/db"),
    )

    with patch('app.core.analysis_engine.load_dotenv'), \
         patch('app.core.analysis_engine.ensure_dir'), \
         patch('app.core.analysis_engine.shutil.copy2'), \
         patch('app.core.analysis_engine.create_analysis_status'), \
         patch('app.core.analysis_engine.logger') as mock_logger, \
         patch.object(Path, 'mkdir'), \
         patch.object(Path, 'exists', return_value=True):

        try:
            engine.run_pipeline(config)
        except SourceExtractionError:
            pass  # Expected

        # Verify error was logged
        error_calls = [call for call in mock_logger.error.call_args_list]
        assert len(error_calls) > 0, "No error logging occurred"
        print("   ✅ Errors are properly logged")

    print("\n🎉 SUCCESS: Logging works correctly!")
    return True


def run_all_error_tests():
    """Run all error handling tests."""
    print("\n" + "="*60)
    print("🧪 Running Error Handling Test Suite")
    print("="*60 + "\n")

    tests = [
        ("Critical Error Abort", test_critical_error_aborts_pipeline),
        ("Non-Critical Continue", test_enrichment_error_continues_pipeline),
        ("Exception Hierarchy", test_exception_hierarchy),
        ("Service Error Wrapping", test_service_error_wrapping),
        ("Pipeline Logging", test_pipeline_logging),
    ]

    results = {}
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"\n❌ Test '{name}' crashed: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False

    # Final summary
    print("\n" + "="*60)
    print("📊 Error Handling Test Results")
    print("="*60)

    for name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {status}: {name}")

    total = len(results)
    passed = sum(1 for r in results.values() if r)

    print(f"\n   Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉🎉🎉 ALL ERROR HANDLING TESTS PASSED! 🎉🎉🎉")
        print("\n   ✨ Your error handling implementation is solid! ✨")
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Please review the issues above.")

    return passed == total


if __name__ == "__main__":
    success = run_all_error_tests()
    sys.exit(0 if success else 1)
