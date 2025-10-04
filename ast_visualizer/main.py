#!/usr/bin/env python3
"""
Python AST Visualizer - Main Entry Point

Usage:
    python main.py <path> [options]

Options:
    -o, --output <prefix>    Output filename prefix (default: callflow)
    -t, --target <api>       Target API to highlight (e.g., yaml.load)
    --no-graph               Skip graph generation (only output API analysis)
    -j, --json               Save results to JSON file

Example:
    python3 main.py ../DB/output/ -o ../DB/test_output --json
"""

import os
import argparse
import logging
import json

from utils import ast_to_png

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Python code and generate call-graph diagram'
    )
    parser.add_argument('path', help='Path to Python file or folder')
    parser.add_argument('-o', '--output', default='callflow', 
                       help='Output prefix (default: callflow)')
    parser.add_argument('-t', '--target', action='append', default=[], 
                       help='Highlight target functions (e.g. yaml.load)')
    parser.add_argument('--no-graph', action='store_true',
                       help='Skip graph generation (only output API analysis)')
    parser.add_argument('-j', '--json', action='store_true',
                       help='Save results to JSON file')
    args = parser.parse_args()

    target_list = args.target
    force = len(target_list) == 0
    targets = ast_to_png.parse_target_calls(target_list)
    
    input_path = args.path
    if os.path.isdir(input_path):
        base = input_path.rstrip(os.sep)
        files = []
        for r, _, fns in os.walk(input_path):
            for fn in fns:
                if fn.endswith('.py'):
                    files.append(os.path.join(r, fn))
        logging.info(f"Collected {len(files)} Python files for analysis")
    else:
        base = os.path.dirname(input_path) or '.'
        files = [input_path]
        logging.info(f"Single file mode: {input_path}")

    external_apis, internal_only_apis, unused_apis = ast_to_png.visualize_call_flow(
        files, base, args.output, targets, force, args.no_graph
    )
    
    # Print results to console
    print("\nExternally exposed APIs:")
    for api in external_apis:
        print(f"  {api}")
    print("\nInternally only APIs:")
    for api in internal_only_apis:
        print(f"  {api}")
    print("\nUnused APIs:")
    for api in unused_apis:
        print(f"  {api}")
    
    # Save to JSON if requested
    if args.json:
        result = {
            "external": external_apis,
            "internal": internal_only_apis,
            "unused": unused_apis
        }
        json_filename = f"{args.output}_result.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logging.info(f"Results saved to {json_filename}")


if __name__ == '__main__':
    main()