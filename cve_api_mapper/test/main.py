import os
import sys
import logging

# 상위 디렉토리의 모듈을 import할 수 있도록 경로 추가
base_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(base_dir))

from cve_api_mapper.mapper.cve_api_mapper import CveApiMapper
from common import ensure_dir, write_json
from common.logging_utils import setup_logging

def main():
    """
    메인 실행 함수.
    여러 LLM 모델을 사용하여 CVE-API 매핑 분석을 수행합니다.
    """
    # 현재 파일의 상위 디렉토리(프로젝트 루트)를 기준으로 경로 설정
    project_root = os.path.dirname(base_dir)
    db_dir = os.path.join(project_root, 'DB')
    
    # DB 폴더가 없으면 생성
    ensure_dir(db_dir)

    # 입력 파일 경로 정의
    trivy_input_file = os.path.join(db_dir, "trivy_analysis_result.json")
    api_input_file = os.path.join(db_dir, "lib2cve2api.json")
    
    # 출력 디렉토리 설정 (모델별로 구분)
    output_dir = os.path.join(db_dir, "results")
    llm_raw_output_dir = os.path.join(db_dir, "raw_responses")
    
    # 출력 디렉토리 생성
    ensure_dir(output_dir)
    ensure_dir(llm_raw_output_dir)
    
    # 로깅 설정
    log_file = os.path.join(project_root, 'app.log')
    setup_logging(log_file=log_file)

    # 입력 파일 존재 여부 확인
    if not os.path.exists(trivy_input_file):
        logging.error(f"Trivy input file not found at: {trivy_input_file}")
        logging.info("Please run Trivy scan and save the JSON output to the DB directory.")
        return
        
    if not os.path.exists(api_input_file):
        logging.error(f"API list file not found at: {api_input_file}")
        logging.info(f"Creating a sample API list file at {api_input_file}")
        sample_data = {
            "Flask": {
                "2.0.2": {
                    "cves": ["CVE-2023-30861"],
                    "apis": {
                        "flask.app": ["run", "handle_exception"],
                        "flask.sessions": ["SessionInterface", "SecureCookieSession"]
                    }
                }
            },
            "PyYAML": {
                "5.3.1": {
                    "cves": ["CVE-2020-14343"],
                    "apis": {
                        "yaml": ["load", "full_load", "safe_load", "load_all", "full_load_all", "unsafe_load", "unsafe_load_all"],
                        "yaml.loader": ["Loader", "FullLoader", "UnsafeLoader"],
                        "yaml.constructor": ["Constructor", "FullConstructor", "UnsafeConstructor"]
                    }
                }
            }
        }
        write_json(api_input_file, sample_data)
        logging.info("Sample file created. Please populate it with real API data and run again.")
        return

    # 테스트할 모델 선택 (명령행 인자로 받을 수 있음)
    models_to_test = ["gpt-5", "claude-sonnet-4.5", "grok-4", "gemini-2.5-pro"]
    
    if len(sys.argv) > 1:
        # 명령행에서 모델 선택: python main.py gpt-5 claude-sonnet-4.5
        models_to_test = sys.argv[1:]
        logging.info(f"Testing selected models: {models_to_test}")
    else:
        logging.info(f"Testing all available models: {models_to_test}")

    # 분석기 인스턴스 생성 및 실행
    try:
        mapper = CveApiMapper(models_to_test=models_to_test)
        mapper.run_analysis(
            trivy_input_file=trivy_input_file,
            api_input_file=api_input_file,
            output_dir=output_dir,
            llm_raw_output_dir=llm_raw_output_dir
        )
        
        logging.info("=" * 60)
        logging.info("Analysis completed successfully!")
        logging.info(f"Results saved in: {output_dir}")
        logging.info(f"Raw LLM responses saved in: {llm_raw_output_dir}")
        logging.info(f"Model comparison summary: {os.path.join(output_dir, 'model_comparison_summary.json')}")
        logging.info("=" * 60)
        
    except ValueError as e:
        logging.error(f"Configuration error: {e}")
        logging.info("\nPlease ensure you have set the required API keys in your .env file:")
        logging.info("  OPENAI_API_KEY=your-openai-key")
        logging.info("  ANTHROPIC_API_KEY=your-anthropic-key")
        logging.info("  GOOGLE_API_KEY=your-google-key")
        logging.info("  XAI_API_KEY=your-xai-key")
    except Exception as e:
        logging.critical(f"A critical error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    main()

# Usage examples:
# python3 main.py                              # Test all models
# python3 main.py gpt-5                        # Test only GPT-5
# python3 main.py gpt-5 claude-sonnet-4.5     # Test GPT-5 and Claude