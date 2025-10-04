"""
CVE 처리 모듈

gpt5_results.json 파일에서 CVE 결과를 처리하는 함수들을 포함합니다.
"""

import json
import logging

from .visualization import create_cve_graph


def load_gpt5_results(gpt5_file):
    """gpt5_results.json 파일 로드 및 파싱"""
    try:
        with open(gpt5_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"{gpt5_file} 로드 실패: {e}")
        return None


def extract_cve_data(gpt5_data):
    """gpt5 데이터에서 취약한 API들과 CVE 정보 추출"""
    vulnerable_apis = []
    cve_info = {}
    package_info = {}

    for package_name, package_data in gpt5_data.items():
        for version, version_data in package_data.items():
            package_info[package_name] = {
                'version': version,
                'cve_count': len(version_data.get('cves', []))
            }

            for cve_id, mapping_data in version_data.get('mapping_result', {}).items():
                apis = mapping_data.get('vulnerable_apis', [])
                reason = mapping_data.get('reason', '')

                cve_info[cve_id] = {
                    'package': package_name,
                    'version': version,
                    'vulnerable_apis': apis,
                    'reason': reason
                }

                vulnerable_apis.extend(apis)

    # 순서를 유지하면서 중복 제거
    unique_apis = list(dict.fromkeys(vulnerable_apis))

    return package_info, cve_info, unique_apis


def save_cve_results(result, output_prefix):
    """CVE 분석 결과를 JSON 파일로 저장"""
    json_filename = f"{output_prefix}_result.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    logging.info(f"CVE 분석 결과가 {json_filename}에 저장되었습니다")


def print_cve_summary(result, unique_apis):
    """CVE 분석 요약을 콘솔에 출력"""
    print(f"\nCVE 분석 요약:")
    print(f"분석된 패키지: {result['summary']['total_packages']}개")
    print(f"총 CVE: {result['summary']['total_cves']}개")
    print(f"고유 취약 API: {result['summary']['total_vulnerable_apis']}개")

    print(f"\n취약한 API들:")
    for api in unique_apis:
        print(f"  {api}")


def process_gpt5_results(gpt5_file, output_prefix, save_json=False, no_graph=False):
    """gpt5_results.json에서 CVE 결과를 처리하고 시각화 생성"""
    gpt5_data = load_gpt5_results(gpt5_file)
    if gpt5_data is None:
        return None

    # CVE 데이터 추출
    package_info, cve_info, unique_apis = extract_cve_data(gpt5_data)

    # 시각화 생성 (비활성화되지 않은 경우)
    if not no_graph:
        create_cve_graph(package_info, cve_info, output_prefix)

    # 요약 데이터 생성
    result = {
        'packages': package_info,
        'cves': cve_info,
        'vulnerable_apis': unique_apis,
        'summary': {
            'total_packages': len(package_info),
            'total_cves': len(cve_info),
            'total_vulnerable_apis': len(unique_apis)
        }
    }

    # 요청시 JSON으로 저장
    if save_json:
        save_cve_results(result, output_prefix)

    # 요약 출력
    print_cve_summary(result, unique_apis)

    return result