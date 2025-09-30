"""Command-line interface module for the container image source extractor."""

import argparse
from typing import Optional

from .config import MESSAGES
from .extractor import extract_app_layer
from .utils import validate_tar_file


def create_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="컨테이너 이미지에서 애플리케이션 소스 코드를 추출합니다.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예제:
  # 자동 탐지 모드로 소스 추출
  python main.py image.tar ./output --auto-detect

  # 수동 경로 지정으로 소스 추출
  python main.py image.tar ./output --app-path /usr/src/app

  # Python 파일만 추출
  python main.py image.tar ./output --auto-detect --filter .py
        """
    )

    parser.add_argument(
        "image_tar",
        help="입력할 컨테이너 이미지 tar 파일 경로"
    )

    parser.add_argument(
        "output_dir",
        help="소스 코드를 추출하여 저장할 디렉토리 경로"
    )

    # 자동/수동 탐지 옵션 그룹
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--auto-detect",
        action="store_true",
        help="자동으로 소스 코드 경로를 탐지합니다."
    )
    group.add_argument(
        "--app-path",
        type=str,
        help="컨테이너 내의 소스 코드 절대 경로를 직접 지정합니다. (예: /usr/src/app)"
    )

    parser.add_argument(
        "--filter",
        type=str,
        help="복사할 파일의 확장자를 지정합니다. (예: .py, .js)"
    )

    return parser


def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command-line arguments.

    Args:
        args: Parsed arguments

    Returns:
        True if arguments are valid, False otherwise
    """
    # Validate tar file
    if not validate_tar_file(args.image_tar):
        print(f"[!] 오류: '{args.image_tar}'는 유효한 tar 파일이 아닙니다.")
        return False

    # Validate mutual exclusivity logic (already handled by argparse)
    if not args.auto_detect and not args.app_path:
        print("[!] 오류: --auto-detect 또는 --app-path 중 하나를 지정해야 합니다.")
        return False

    return True


def run_cli(argv: Optional[list] = None) -> int:
    """
    Run the CLI application.

    Args:
        argv: Command-line arguments (for testing purposes)

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # Validate arguments
    if not validate_arguments(args):
        return 1

    try:
        # Execute extraction
        extract_app_layer(
            image_tar_path=args.image_tar,
            output_dir=args.output_dir,
            app_path=args.app_path,
            auto_detect=args.auto_detect,
            include_filter=args.filter
        )
        print(MESSAGES["all_complete"])
        return 0

    except (FileNotFoundError, ValueError) as e:
        print(MESSAGES["error_occurred"].format(error=str(e)))
        return 1

    except Exception as e:
        print(MESSAGES["unexpected_error"].format(error=str(e)))
        return 1