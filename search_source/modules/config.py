"""Configuration and constants module for container image source extractor."""

# 소스 코드가 위치할 가능성이 높은 경로 목록
CANDIDATE_APP_PATHS = [
    "/app",
    "/usr/src/app",
    "/src",
    "/code",
    "/workspace"
]

# 메시지 상수
MESSAGES = {
    "extract_start": "[+] 이미지 tar 파일 추출 중: {path}",
    "layer_applied": "[+] 레이어 적용 완료: {layer}",
    "app_found": "[+] '{path}' 경로에서 애플리케이션 소스를 찾았습니다. 복사를 시작합니다.",
    "copy_complete": "[+] 자동 복사 완료: {src} → {dest}",
    "manual_copy_start": "[+] 지정된 경로에서 파일 복사를 시작합니다: {path}",
    "copy_success": "[+] 애플리케이션 파일 복사 완료: {path}",
    "all_complete": "\n[✔] 모든 작업이 성공적으로 완료되었습니다.",
    "error_occurred": "\n[✖] 오류가 발생했습니다: {error}",
    "unexpected_error": "\n[✖] 예상치 못한 오류가 발생했습니다: {error}",
}

# 에러 메시지 상수
ERROR_MESSAGES = {
    "manifest_not_found": "[!] manifest.json 파일을 찾을 수 없습니다. 올바른 이미지 tar 파일인지 확인하세요.",
    "auto_detect_failed": "[!] 자동 탐지 모드에서 앱 경로를 찾을 수 없습니다.",
    "app_path_required": "[!] 자동 탐지 모드가 아닐 경우 --app-path를 지정해야 합니다.",
    "app_path_not_found": "[!] 지정된 앱 경로를 찾을 수 없습니다: {path}",
}