"""Custom exceptions for the analysis pipeline.

This module defines a hierarchy of exceptions that allow services to
communicate failures in a structured way, enabling the orchestrator to
make informed decisions about fail-fast vs fail-safe strategies.
"""

from typing import Optional


class AnalysisError(Exception):
    """
    Base exception for all analysis pipeline errors.

    This is the root of the exception hierarchy and should be caught
    by the orchestrator for global error handling.
    """

    def __init__(self, message: str, cause: Optional[Exception] = None):
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            cause: The original exception that caused this error (if any)
        """
        super().__init__(message)
        self.message = message
        self.cause = cause

    def __str__(self) -> str:
        """Return a detailed string representation."""
        if self.cause:
            return f"{self.message} (caused by: {type(self.cause).__name__}: {str(self.cause)})"
        return self.message


class SourceExtractionError(AnalysisError):
    """
    Exception raised when source extraction from container image fails.

    This is a CRITICAL error - the pipeline cannot continue without sources.
    Fail-fast strategy: abort the entire pipeline.
    """

    pass


class ScannerError(AnalysisError):
    """
    Exception raised when Trivy vulnerability scanning fails.

    This is a CRITICAL error - vulnerability data is essential.
    Fail-fast strategy: abort the entire pipeline.
    """

    pass


class ParserError(AnalysisError):
    """
    Exception raised when parsing or mapping CVE/API data fails.

    This is a CRITICAL error - we need parsed data for analysis.
    Fail-fast strategy: abort the entire pipeline.
    """

    pass


class ASTAnalysisError(AnalysisError):
    """
    Exception raised when AST analysis fails.

    This is a CRITICAL error - AST data is core to the analysis.
    Fail-fast strategy: abort the entire pipeline.
    """

    pass


class EnrichmentError(AnalysisError):
    """
    Exception raised when AI-powered enrichment fails.

    This is a NON-CRITICAL error - enrichment is optional.
    Fail-safe strategy: log the error and continue pipeline execution.
    The result will indicate that enrichment was skipped.
    """

    pass


# Convenience function for wrapping exceptions
def wrap_exception(
    exception_class: type[AnalysisError],
    message: str,
    cause: Exception
) -> AnalysisError:
    """
    Wrap a lower-level exception in a domain-specific exception.

    Args:
        exception_class: The custom exception class to use
        message: Descriptive message about what operation failed
        cause: The original exception that was caught

    Returns:
        An instance of the specified exception class

    Example:
        try:
            risky_operation()
        except subprocess.CalledProcessError as e:
            raise wrap_exception(
                ScannerError,
                "Trivy scan failed",
                e
            )
    """
    return exception_class(message, cause=cause)


__all__ = [
    "AnalysisError",
    "SourceExtractionError",
    "ScannerError",
    "ParserError",
    "ASTAnalysisError",
    "EnrichmentError",
    "wrap_exception",
]
