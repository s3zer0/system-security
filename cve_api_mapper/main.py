import os
import sys
import json
import logging

# 상위 디렉토리의 모듈을 import할 수 있도록 경로 추가
base_dir = os.path.dirname(os.path.abspath(__file__))
# sys.path.insert(0, base_dir) # 이 구조에서는 cve_api_mapper 폴더를 PYTHONPATH에 추가하거나, 직접 경로 조작이 필요할 수 있습니다.
# 더 안정적인 상대 임포트를 위해, cve_api_mapper 폴더에서 python -m cve_api_mapper.main 으로 실행하는 것을 권장합니다.
# 아래 코드는 python main.py 실행을 기준으로 작성되었습니다.
sys.path.insert(0, os.path.dirname(base_dir))


from cve_api_mapper.mapper.cve_api_mapper import CveApiMapper, setup_logging

def main():
    """
    메인 실행 함수.
    분석을 설정하고 CveApiMapper를 사용하여 실행합니다.
    """
    # 현재 파일의 상위 디렉토리(프로젝트 루트)를 기준으로 경로 설정
    project_root = os.path.dirname(base_dir)
    db_dir = os.path.join(project_root, 'DB')
    
    # DB 폴더가 없으면 생성
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)

    # 파일 경로 정의
    # Trivy 스캔 결과와 API 목록 파일을 입력으로 사용합니다.
    trivy_input_file = os.path.join(db_dir, "trivy_analysis_result.json")
    api_input_file = os.path.join(db_dir, "lib2cve2api.json")
    output_file = os.path.join(db_dir, "gpt5_results.json")
    llm_output_file = os.path.join(db_dir, "gpt5_raw_responses.json")
    
    # 로깅 설정 (로그 파일은 프로젝트 루트에 생성)
    log_file = os.path.join(project_root, 'app.log')
    setup_logging(log_file=log_file)

    # 입력 파일 존재 여부 확인
    if not os.path.exists(trivy_input_file):
        logging.error(f"Trivy input file not found at: {trivy_input_file}")
        logging.info("Please run Trivy scan and save the JSON output to the project root directory.")
        return
        
    if not os.path.exists(api_input_file):
        logging.error(f"API list file not found at: {api_input_file}")
        logging.info(f"Creating a sample API list file at {api_input_file}")
        sample_data = {
            "Flask": {
                "2.0.2": {
                    "apis": {
                        "flask.app": ["run", "handle_exception"],
                        "flask.sessions": ["SessionInterface", "SecureCookieSession"]
                    }
                }
            },
            "PyYAML": {
                "5.3.1": {
                    "apis": {
                        "yaml": ["load", "full_load", "safe_load"]
                    }
                }
            }
        }
        with open(api_input_file, 'w', encoding='utf-8') as f:
            json.dump(sample_data, f, indent=4)
        logging.info("Sample file created. Please populate it with real API data and run again.")
        return

    # 분석기 인스턴스 생성 및 실행
    try:
        mapper = CveApiMapper()
        mapper.run_analysis(
            trivy_input_file=trivy_input_file,
            api_input_file=api_input_file,
            output_file=output_file,
            llm_raw_output_file=llm_output_file
        )
    except Exception as e:
        logging.critical(f"A critical error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

