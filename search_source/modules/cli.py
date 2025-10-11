"""컨테이너 이미지 소스 추출기를 위한 명령행 인터페이스 모듈입니다."""

import argparse
from typing import Optional

from .config import MESSAGES
from .extractor import extract_app_layer
from .utils import validate_tar_file


def create_parser() -> argparse.ArgumentParser:
    """
    인자 파서를 생성하고 필요한 옵션을 설정합니다.

    Returns:
        구성된 ArgumentParser 인스턴스입니다.
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
    명령행 인자를 검증합니다.

    Args:
        args: 파싱된 인자 값

    Returns:
        인자가 유효하면 True, 그렇지 않으면 False
    """
    # tar 파일을 검증합니다.
    if not validate_tar_file(args.image_tar):
        print(f"[!] 오류: '{args.image_tar}'는 유효한 tar 파일이 아닙니다.")
        return False

    # 상호 배타 옵션 검사 (argparse에서 기본 처리하지만 안전망으로 확인)
    if not args.auto_detect and not args.app_path:
        print("[!] 오류: --auto-detect 또는 --app-path 중 하나를 지정해야 합니다.")
        return False

    return True


def run_cli(argv: Optional[list] = None) -> int:
    """
    CLI 애플리케이션을 실행합니다.

    Args:
        argv: 테스트 목적으로 전달할 명령행 인자 목록

    Returns:
        종료 코드 (성공 시 0, 실패 시 1)
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    # 인자를 검증합니다.
    if not validate_arguments(args):
        return 1

    try:
        # 추출 작업을 수행합니다.
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
