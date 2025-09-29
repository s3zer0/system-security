import argparse

from trivy_module import trivy_func

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tool to scan container vulnerabilities using Trivy")
    parser.add_argument("input", help="Path to image tar/zip file")
    parser.add_argument("output", help="Path to save JSON report")
    parser.add_argument("--no-full-scan", action="store_true", help="Disable full scan")

    args = parser.parse_args()
    trivy_func.scan_vulnerabilities(args.input, args.output, full_scan=not args.no_full_scan)

# python3 main.py ../test_target/pyyaml-vuln.tar ../DB/trivy_analysis_result.json