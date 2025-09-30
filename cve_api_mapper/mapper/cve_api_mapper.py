import os
import json
import logging
import requests
import time
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from dotenv import load_dotenv
from openai import OpenAI

# 로거 설정
logger = logging.getLogger(__name__)

def setup_logging(log_file: str = "app.log", log_level: int = logging.INFO):
    """로깅을 설정하는 함수"""
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, mode="w"),
            logging.StreamHandler()
        ]
    )

class GPT5Client:
    """GPT-5 모델과의 상호작용을 담당하는 클라이언트 클래스"""
    def __init__(self, client: OpenAI, model: str = "gpt-4-turbo"): # 모델 이름은 실제 사용 가능 모델로 변경
        self.client = client
        self.model = model

    def query(self, library: str, version: str,
              api_dict: Dict[str, List[str]],
              cve_descriptions: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[Dict]]:
        """
        주어진 라이브러리, API, CVE 정보를 바탕으로 LLM에 쿼리합니다.
        성공 시 (원본 응답, 파싱된 JSON) 튜플을, 실패 시 (None, None)을 반환합니다.
        """
        api_list = [f"{m}.{a}" for m, apis in api_dict.items() for a in apis]
        cve_text = "\n".join(f"- {cve}: {desc}" for cve, desc in cve_descriptions if desc)

        prompt = (
            f"Given a list of APIs from {library} version {version} and a list of CVE descriptions, "
            "identify which APIs are vulnerable for each CVE. "
            "The output must be a valid JSON object with the following structure:\n"
            "{\"CVE-ID-1\": {\"vulnerable_apis\": [\"module.api1\", \"module.api2\"], \"reason\": \"A brief explanation of why these APIs are vulnerable.\"}, "
            "\"CVE-ID-2\": {\"vulnerable_apis\": [], \"reason\": \"No specific APIs were found to be directly vulnerable.\"}}\n\n"
            f"APIs: {', '.join(api_list)}\n\n"
            f"CVE Descriptions:\n{cve_text}"
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in static code analysis and vulnerability mapping."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content.strip()
            return content, json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response for {library} {version}: {e}\nRaw content: {content}")
            return content, None
        except Exception as e:
            logger.error(f"GPT-5 query failed for {library} {version}: {e}")
            return None, None

class CveApiMapper:
    """CVE와 API 매핑 분석을 수행하는 메인 클래스"""
    def __init__(self):
        load_dotenv()
        
        # API 키 로드
        self.openai_api_key = os.getenv("OPENAI_API_KEY")
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY not set in environment")
        
        # 클라이언트 초기화
        self.openai_client = OpenAI(api_key=self.openai_api_key)
        self.gpt5_client = GPT5Client(self.openai_client)
        
        # 상태 변수
        self.llm_responses: List[Dict] = []

    def _parse_trivy_output(self, trivy_data: Dict) -> Dict:
        """Trivy JSON 출력을 파싱하여 패키지별로 CVE를 그룹화합니다."""
        vulnerabilities_by_package = {}
        if "vulnerabilities" not in trivy_data or not isinstance(trivy_data["vulnerabilities"], list):
            logger.warning("Trivy data does not contain a 'vulnerabilities' list.")
            return {}

        for vuln in trivy_data["vulnerabilities"]:
            pkg_name = vuln.get("package_name")
            version = vuln.get("installed_version")
            cve_id = vuln.get("id")
            description = vuln.get("description")

            if not all([pkg_name, version, cve_id, description]):
                continue

            if pkg_name not in vulnerabilities_by_package:
                vulnerabilities_by_package[pkg_name] = {}
            if version not in vulnerabilities_by_package[pkg_name]:
                vulnerabilities_by_package[pkg_name][version] = {"cve_descriptions": []}

            vulnerabilities_by_package[pkg_name][version]["cve_descriptions"].append((cve_id, description))
        return vulnerabilities_by_package

    def _process_library(self, library: str, version: str, cve_descriptions: List[Tuple[str, str]],
                        apis: Dict[str, List[str]]) -> Dict:
        """단일 라이브러리에 대한 CVE-API 매핑을 처리합니다."""
        logger.info(f"Processing {library} {version} with {len(cve_descriptions)} CVEs from Trivy scan.")
        
        if not cve_descriptions or not apis:
            logger.warning(f"No valid CVE descriptions or APIs found for {library} {version}. Skipping LLM query.")
            cve_list = [cve_id for cve_id, desc in cve_descriptions]
            return {"cves": cve_list, "mapping_result": {}}

        # LLM 쿼리 실행
        raw_response, mapping = self.gpt5_client.query(library, version, apis, cve_descriptions)
        
        if raw_response is not None:
             self.llm_responses.append({"library": library, "version": version, "response": raw_response})

        cve_list = [cve_id for cve_id, desc in cve_descriptions]
        return {"cves": cve_list, "mapping_result": mapping or {}}

    def _load_input(self, input_file: str) -> Dict:
        """입력 JSON 파일을 로드합니다."""
        logger.info(f"Loading input data from {input_file}")
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data or {}
        except Exception as e:
            logger.error(f"Failed to load input file {input_file}: {e}")
            return {}

    def _save_output(self, data: Dict, output_file: str):
        """결과를 JSON 파일로 저장합니다."""
        logger.info(f"Saving results to {output_file}")
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save results to {output_file}: {e}")

    def run_analysis(self, trivy_input_file: str, api_input_file: str, output_file: str, llm_raw_output_file: str):
        """전체 분석 프로세스를 실행합니다."""
        trivy_data = self._load_input(trivy_input_file)
        api_data = self._load_input(api_input_file) # 기존 lib2cve2api.json 파일

        if not trivy_data or not api_data:
            logger.error("Trivy data or API data is empty. Aborting analysis.")
            return

        parsed_vulns = self._parse_trivy_output(trivy_data)

        results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_lib = {}
            for lib, versions in parsed_vulns.items():
                for ver, info in versions.items():
                    # API 정보를 api_data에서 가져옴
                    apis = api_data.get(lib, {}).get(ver, {}).get("apis", {})
                    if not apis:
                        logger.warning(f"No APIs found for {lib} {ver} in {api_input_file}. Skipping.")
                        continue
                    
                    cve_descriptions = info["cve_descriptions"]
                    future = executor.submit(self._process_library, lib, ver, cve_descriptions, apis)
                    future_to_lib[future] = (lib, ver)

            for future in as_completed(future_to_lib):
                lib, ver = future_to_lib[future]
                try:
                    result = future.result()
                    if lib not in results:
                        results[lib] = {}
                    results[lib][ver] = result
                except Exception as e:
                    logger.error(f"Error processing {lib} {ver} in main loop: {e}")
                    if lib not in results:
                        results[lib] = {}
                    cves_from_trivy = [c[0] for c in parsed_vulns.get(lib, {}).get(ver, {}).get("cve_descriptions", [])]
                    results[lib][ver] = {"cves": cves_from_trivy, "mapping_result": {"error": str(e)}}

        self._save_output(results, output_file)
        self._save_output(self.llm_responses, llm_raw_output_file)
        logger.info("Analysis complete.")

