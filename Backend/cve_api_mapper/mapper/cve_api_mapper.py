import os
import json
import logging
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from openai import OpenAI
import anthropic
from google import genai
from google.genai import types

logger = logging.getLogger(__name__)

class LLMClient:
    """LLM 클라이언트의 기본 클래스"""
    def __init__(self, model_name: str):
        self.model_name = model_name

    def create_prompt(self, library: str, version: str,
                     api_dict: Dict[str, List[str]],
                     cve_descriptions: List[Tuple[str, str]]) -> str:
        """상세한 프롬프트 생성 (test 폴더의 템플릿 사용)"""
        # API 리스트를 평탄화
        api_list = []
        for module, apis in api_dict.items():
            for api in apis:
                api_list.append(api)
        api_list_str = "\n".join(api_list)
        
        # CVE 설명 텍스트 생성
        cve_desc_text = "\n".join([f"{cve}: {desc}" for cve, desc in cve_descriptions if desc])

        system_prompt = f"""### System Prompt / Role Definition ###
You are a top-level cybersecurity analyst specializing in static code analysis. Your mission is to identify API functions from the provided API list that are directly related to vulnerabilities described in the given CVE (Common Vulnerabilities and Exposures) report set. Your analysis must be accurate, technically sound, and provide clear justification.

### Context Information ###
- Library Name: {library}
- Library Version: {version}
- Target API List:
{api_list_str}
- Target CVE Descriptions:
{cve_desc_text}

### Task Instructions ###
1. Carefully read and analyze each "Target CVE Description" provided above.
2. For each CVE, select API functions from the "Target API List" ONLY that are directly related to vulnerable functionality explicitly mentioned or strongly implied in the description.
3. For each CVE, provide a concise but technically accurate explanation in ENGLISH for why you selected the APIs. Your explanation should quote specific phrases from the CVE description to justify your selection.
4. If you determine that no APIs in the list are related to a specific CVE, leave the API list empty for that CVE. Do not guess or create non-existent APIs.
5. IMPORTANT: All explanations in the "reason" field must be written in ENGLISH only.

### Output Format Specification ###
Your final output must be a single valid JSON object that complies with the schema specified below. Do not include any explanatory text, markdown formatting (```json...```), or apologies outside the JSON object.

{{
  "CVE-ID_1": {{
    "apis": ["module.api1", "module.api2"],
    "reason": "The phrase '...' in the CVE description indicates that module.api1 and module.api2 can create arbitrary objects during deserialization."
  }},
  "CVE-ID_2": {{
    "apis": ["module.api3"],
    "reason": "CVE-ID_2 explicitly mentions a buffer overflow occurring in module.api3."
  }}
}}"""
        return system_prompt

    def query(self, library: str, version: str,
              api_dict: Dict[str, List[str]],
              cve_descriptions: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[Dict]]:
        """LLM에 쿼리 (하위 클래스에서 구현)"""
        raise NotImplementedError


class GPTClient(LLMClient):
    """OpenAI GPT 클라이언트"""
    def __init__(self, api_key: str, model: str = "gpt-5"):
        super().__init__(model)
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def query(self, library: str, version: str,
              api_dict: Dict[str, List[str]],
              cve_descriptions: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[Dict]]:
        prompt = self.create_prompt(library, version, api_dict, cve_descriptions)
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in static code analysis. Always respond with valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content.strip()
            return content, json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[{self.model_name}] Failed to parse JSON for {library} {version}: {e}")
            return content, None
        except Exception as e:
            logger.error(f"[{self.model_name}] Query failed for {library} {version}: {e}")
            return None, None


class ClaudeClient(LLMClient):
    """Anthropic Claude 클라이언트"""
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5-20250929"):
        super().__init__(model)
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def query(self, library: str, version: str,
              api_dict: Dict[str, List[str]],
              cve_descriptions: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[Dict]]:
        prompt = self.create_prompt(library, version, api_dict, cve_descriptions)
        json_instruction = "\n\nIMPORTANT: Return ONLY a valid JSON object without any markdown formatting, code blocks, or explanatory text."
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.1,
                system="You are a cybersecurity expert specializing in static code analysis. Always respond with valid JSON only.",
                messages=[{"role": "user", "content": prompt + json_instruction}]
            )
            content = message.content[0].text if message.content else ""
            # 마크다운 제거
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                content = content[start:end].strip()
            return content, json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[{self.model_name}] Failed to parse JSON for {library} {version}: {e}")
            return content, None
        except Exception as e:
            logger.error(f"[{self.model_name}] Query failed for {library} {version}: {e}")
            return None, None


class GeminiClient(LLMClient):
    """Google Gemini 클라이언트"""
    def __init__(self, api_key: str, model: str = "gemini-2.5-pro"):
        super().__init__(model)
        self.client = genai.Client(api_key=api_key)
        self.model = model

    def query(self, library: str, version: str,
              api_dict: Dict[str, List[str]],
              cve_descriptions: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[Dict]]:
        prompt = self.create_prompt(library, version, api_dict, cve_descriptions)
        json_instruction = "\n\nIMPORTANT: Return ONLY a valid JSON object without any markdown formatting, code blocks, or explanatory text."
        
        try:
            config = types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=4000,
                response_mime_type="application/json"
            )
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt + json_instruction,
                config=config
            )
            content = response.text
            return content, json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[{self.model_name}] Failed to parse JSON for {library} {version}: {e}")
            return content, None
        except Exception as e:
            logger.error(f"[{self.model_name}] Query failed for {library} {version}: {e}")
            return None, None


class GrokClient(LLMClient):
    """X.AI Grok 클라이언트 (OpenAI 호환 API 사용)"""
    def __init__(self, api_key: str, model: str = "grok-4"):
        super().__init__(model)
        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1"
        )
        self.model = model

    def query(self, library: str, version: str,
              api_dict: Dict[str, List[str]],
              cve_descriptions: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[Dict]]:
        prompt = self.create_prompt(library, version, api_dict, cve_descriptions)
        json_instruction = "\n\nIMPORTANT: Return ONLY a valid JSON object without any markdown formatting, code blocks, or explanatory text."
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in static code analysis. Always respond with valid JSON only."},
                    {"role": "user", "content": prompt + json_instruction}
                ],
                temperature=0.1
            )
            content = response.choices[0].message.content.strip()
            # 마크다운 제거
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                content = content[start:end].strip()
            return content, json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"[{self.model_name}] Failed to parse JSON for {library} {version}: {e}")
            return content, None
        except Exception as e:
            logger.error(f"[{self.model_name}] Query failed for {library} {version}: {e}")
            return None, None


class CveApiMapper:
    """CVE와 API 매핑 분석을 수행하는 메인 클래스"""
    def __init__(self, models_to_test: List[str] = None):
        load_dotenv()
        
        # 테스트할 모델 리스트 (기본값: 모든 모델)
        if models_to_test is None:
            models_to_test = ["gpt-5", "claude-sonnet-4.5", "grok-4", "gemini-2.5-pro"]
        
        # 클라이언트 초기화
        self.clients = {}
        
        if "gpt-5" in models_to_test:
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                self.clients["gpt-5"] = GPTClient(api_key, "gpt-5")
                logger.info("GPT-5 client initialized")
            else:
                logger.warning("OPENAI_API_KEY not found, skipping GPT-5")
        
        if "claude-sonnet-4.5" in models_to_test:
            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key:
                self.clients["claude-sonnet-4.5"] = ClaudeClient(api_key, "claude-sonnet-4-5-20250929")
                logger.info("Claude Sonnet 4.5 client initialized")
            else:
                logger.warning("ANTHROPIC_API_KEY not found, skipping Claude")
        
        if "grok-4" in models_to_test:
            api_key = os.getenv("XAI_API_KEY")
            if api_key:
                self.clients["grok-4"] = GrokClient(api_key, "grok-4")
                logger.info("Grok-4 client initialized")
            else:
                logger.warning("XAI_API_KEY not found, skipping Grok")
        
        if "gemini-2.5-pro" in models_to_test:
            api_key = os.getenv("GOOGLE_API_KEY")
            if api_key:
                self.clients["gemini-2.5-pro"] = GeminiClient(api_key, "gemini-2.5-pro")
                logger.info("Gemini 2.5 Pro client initialized")
            else:
                logger.warning("GOOGLE_API_KEY not found, skipping Gemini")
        
        if not self.clients:
            raise ValueError("No API keys found. Please set at least one API key in environment variables.")
        
        # 상태 변수
        self.llm_responses = {model: [] for model in self.clients.keys()}

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

    def _process_library_with_model(self, model_name: str, client: LLMClient,
                                    library: str, version: str,
                                    cve_descriptions: List[Tuple[str, str]],
                                    apis: Dict[str, List[str]]) -> Dict:
        """단일 라이브러리를 특정 모델로 처리합니다."""
        logger.info(f"[{model_name}] Processing {library} {version} with {len(cve_descriptions)} CVEs")
        
        if not cve_descriptions or not apis:
            logger.warning(f"[{model_name}] No valid CVE descriptions or APIs for {library} {version}")
            cve_list = [cve_id for cve_id, desc in cve_descriptions]
            return {"cves": cve_list, "mapping_result": {}}

        # LLM 쿼리 실행
        raw_response, mapping = client.query(library, version, apis, cve_descriptions)
        
        if raw_response is not None:
            self.llm_responses[model_name].append({
                "library": library,
                "version": version,
                "response": raw_response
            })

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

    def run_analysis(self, trivy_input_file: str, api_input_file: str,
                    output_dir: str, llm_raw_output_dir: str):
        """전체 분석 프로세스를 실행합니다 (모든 모델 병렬 처리)"""
        trivy_data = self._load_input(trivy_input_file)
        api_data = self._load_input(api_input_file)

        if not trivy_data or not api_data:
            logger.error("Trivy data or API data is empty. Aborting analysis.")
            return

        parsed_vulns = self._parse_trivy_output(trivy_data)

        # 각 모델별로 결과 저장
        results_by_model = {model: {} for model in self.clients.keys()}

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_info = {}
            
            # 모든 라이브러리-버전-모델 조합에 대해 작업 제출
            for lib, versions in parsed_vulns.items():
                for ver, info in versions.items():
                    apis = api_data.get(lib, {}).get(ver, {}).get("apis", {})
                    if not apis:
                        logger.warning(f"No APIs found for {lib} {ver}, skipping")
                        continue
                    
                    cve_descriptions = info["cve_descriptions"]
                    
                    # 각 모델에 대해 병렬로 작업 제출
                    for model_name, client in self.clients.items():
                        future = executor.submit(
                            self._process_library_with_model,
                            model_name, client, lib, ver, cve_descriptions, apis
                        )
                        future_to_info[future] = (model_name, lib, ver)

            # 결과 수집
            for future in as_completed(future_to_info):
                model_name, lib, ver = future_to_info[future]
                try:
                    result = future.result()
                    if lib not in results_by_model[model_name]:
                        results_by_model[model_name][lib] = {}
                    results_by_model[model_name][lib][ver] = result
                    logger.info(f"[{model_name}] Completed {lib} {ver}")
                except Exception as e:
                    logger.error(f"[{model_name}] Error processing {lib} {ver}: {e}")
                    if lib not in results_by_model[model_name]:
                        results_by_model[model_name][lib] = {}
                    cves = [c[0] for c in parsed_vulns.get(lib, {}).get(ver, {}).get("cve_descriptions", [])]
                    results_by_model[model_name][lib][ver] = {"cves": cves, "mapping_result": {"error": str(e)}}

        # 각 모델별로 결과 저장
        for model_name in self.clients.keys():
            output_file = os.path.join(output_dir, f"{model_name}_results.json")
            self._save_output(results_by_model[model_name], output_file)
            
            llm_output_file = os.path.join(llm_raw_output_dir, f"{model_name}_raw_responses.json")
            self._save_output(self.llm_responses[model_name], llm_output_file)

        logger.info("Analysis complete for all models.")
        
        # 결과 비교 요약 생성
        self._generate_comparison_summary(results_by_model, output_dir)

    def _generate_comparison_summary(self, results_by_model: Dict, output_dir: str):
        """모델별 결과 비교 요약을 생성합니다."""
        summary = {
            "models_tested": list(results_by_model.keys()),
            "comparison": {}
        }
        
        # 각 라이브러리-버전 조합에 대해 비교
        all_libs = set()
        for model_results in results_by_model.values():
            for lib in model_results.keys():
                all_libs.add(lib)
        
        for lib in all_libs:
            summary["comparison"][lib] = {}
            versions = set()
            for model_results in results_by_model.values():
                if lib in model_results:
                    versions.update(model_results[lib].keys())
            
            for ver in versions:
                summary["comparison"][lib][ver] = {}
                for model_name, model_results in results_by_model.items():
                    if lib in model_results and ver in model_results[lib]:
                        result = model_results[lib][ver]
                        mapping = result.get("mapping_result", {})
                        summary["comparison"][lib][ver][model_name] = {
                            "cve_count": len(result.get("cves", [])),
                            "mapped_cve_count": len([k for k in mapping.keys() if k != "error"]),
                            "has_error": "error" in mapping
                        }
        
        summary_file = os.path.join(output_dir, "model_comparison_summary.json")
        self._save_output(summary, summary_file)
        logger.info(f"Comparison summary saved to {summary_file}")