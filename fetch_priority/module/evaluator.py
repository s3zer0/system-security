import json
import os
from typing import Dict, List, Any, Tuple, Optional
from enum import Enum
from pathlib import Path

from common import read_json, write_json
from common.models import VulnerabilityContext
from dotenv import load_dotenv
import logging
from datetime import datetime
import requests

# Anthropic API 사용
import anthropic

# Perplexity 검색기
from .perplexity_searcher import create_searcher, PerplexitySearcher

# .env 파일에서 환경 변수 로드
load_dotenv()

logger = logging.getLogger(__name__)


class Severity(Enum):
    """취약점 심각도 레벨"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1



class PatchPriorityEvaluator:
    """취약점 패치 우선순위를 평가하는 클래스"""
    
    def __init__(self, 
                 api_key: str, 
                 model: str = "claude-sonnet-4-5-20250929",
                 perplexity_api_key: Optional[str] = None,
                 enable_perplexity: bool = False):
        """
        LLM 자격 증명으로 평가자 초기화
        
        Args:
            api_key: Anthropic API 키
            model: 사용할 Claude 모델 이름
            perplexity_api_key: Perplexity API 키 (선택사항, 환경변수에서 로드 가능)
            enable_perplexity: Perplexity 검색 활성화 여부
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        
        # Perplexity 검색기 초기화
        self.perplexity_enabled = enable_perplexity
        self.perplexity_searcher: Optional[PerplexitySearcher] = None
        self._claude_raw_response_path: Optional[Path] = None
        self._epss_cache: Dict[str, float] = {}
        
        if enable_perplexity:
            perplexity_key = perplexity_api_key or os.getenv("PERPLEXITY_API_KEY")
            if perplexity_key:
                try:
                    self.perplexity_searcher = create_searcher(perplexity_key)
                    logger.info("Perplexity 검색 활성화됨")
                except Exception as e:
                    logger.warning(f"Perplexity 검색기 초기화 실패: {e}")
                    self.perplexity_enabled = False
            else:
                logger.warning("PERPLEXITY_API_KEY 없음 - 실제 사례 검색 비활성화")
                self.perplexity_enabled = False
    
    def load_data(self, 
                  ast_file: str,
                  gpt5_results_file: str,
                  lib2cve2api_file: str,
                  trivy_file: str) -> Dict[str, Any]:
        """
        모든 취약점 데이터 파일을 로드합니다
        
        Args:
            ast_file: AST 분석 결과 파일 경로
            gpt5_results_file: GPT5 CVE 매핑 결과 파일 경로
            lib2cve2api_file: 라이브러리-CVE-API 매핑 파일 경로
            trivy_file: Trivy 스캔 결과 파일 경로
            
        Returns:
            모든 취약점 데이터를 포함하는 딕셔너리
        """
        ast_data = read_json(ast_file)
        gpt5_results = read_json(gpt5_results_file)
        lib2cve2api = read_json(lib2cve2api_file)
        trivy_data = read_json(trivy_file)

        return {
            'ast': ast_data,
            'gpt5_results': gpt5_results,
            'lib2cve2api': lib2cve2api,
            'trivy': trivy_data
        }

    def _fetch_epss_score(self, cve_id: str) -> float:
        """
        FIRST EPSS API에서 CVE별 EPSS 점수를 가져옵니다.

        Args:
            cve_id: EPSS 점수를 조회할 CVE ID

        Returns:
            EPSS 점수 (조회 실패 시 0.0)
        """
        if not cve_id:
            return 0.0

        if cve_id in self._epss_cache:
            return self._epss_cache[cve_id]

        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
            data = payload.get('data') or []
            if not data:
                logger.warning('EPSS 데이터가 비어 있습니다: %s', cve_id)
                score = 0.0
            else:
                score_str = data[0].get('epss')
                score = float(score_str) if score_str is not None else 0.0
        except Exception as exc:
            logger.warning('EPSS 점수 조회 실패 (%s): %s', cve_id, exc)
            score = 0.0

        self._epss_cache[cve_id] = score
        return score
    
    def analyze_api_usage(self, vulnerable_apis: List[str], 
                          external_apis: List[str],
                          internal_apis: List[str]) -> Tuple[bool, List[str], bool, List[str]]:
        """
        취약한 API가 코드베이스에서 실제로 사용되는지 확인합니다
        Docker 환경에서 external API 사용 여부를 별도로 추적합니다
        
        Args:
            vulnerable_apis: 취약한 API 목록
            external_apis: 외부로 노출되는 API 목록
            internal_apis: 내부에서만 사용되는 API 목록
            
        Returns:
            (전체_사용_여부, 일치하는_API_목록, external_사용_여부, external_일치_목록) 튜플
        """
        matching_apis = []
        matching_external_apis = []
        
        # 전체 사용된 API 확인
        all_used_apis = external_apis + internal_apis
        for v_api in vulnerable_apis:
            for used_api in all_used_apis:
                if v_api in used_api or used_api in v_api:
                    matching_apis.append(v_api)
                    break
        
        # External API 사용 확인 (Docker 환경에서 외부 노출)
        for v_api in vulnerable_apis:
            for ext_api in external_apis:
                if v_api in ext_api or ext_api in v_api:
                    matching_external_apis.append(v_api)
                    break
        
        is_used = len(matching_apis) > 0
        is_external_used = len(matching_external_apis) > 0
        
        return is_used, matching_apis, is_external_used, matching_external_apis
    
    def build_vulnerability_contexts(self, data: Dict[str, Any]) -> List[VulnerabilityContext]:
        """
        각 취약점에 대한 통합 컨텍스트를 구축합니다
        
        Args:
            data: 로드된 취약점 데이터
            
        Returns:
            취약점 컨텍스트 객체 리스트
        """
        contexts = []
        
        # AST 분석에서 external과 internal API 분리
        external_apis = data['ast']['external']
        internal_apis = data['ast']['internal']
        
        # Trivy 스캔의 각 취약점 처리
        for vuln in data['trivy']['vulnerabilities']:
            cve_id = vuln['id']
            package_name = vuln['package_name']
            version = vuln['installed_version']
            
            # GPT5 결과에서 취약한 API 가져오기
            vulnerable_apis = []
            if package_name in data['gpt5_results']:
                if version in data['gpt5_results'][package_name]:
                    mapping = data['gpt5_results'][package_name][version].get('mapping_result', {})
                    if cve_id in mapping:
                        entry = mapping.get(cve_id) or {}
                        apis = entry.get('vulnerable_apis') or entry.get('apis') or []
                        if isinstance(apis, str):
                            apis = [apis]
                        elif isinstance(apis, dict):
                            # 중첩된 딕셔너리 값이 있으면 평탄화합니다.
                            flattened = []
                            for value in apis.values():
                                if isinstance(value, str):
                                    flattened.append(value)
                                elif isinstance(value, (list, tuple, set)):
                                    flattened.extend(str(item) for item in value)
                            apis = flattened
                        vulnerable_apis = [api for api in apis if isinstance(api, str)]
            
            # 취약한 API가 실제로 사용되는지 확인 (external/internal 구분)
            is_used, matching_apis, is_external_used, matching_external = self.analyze_api_usage(
                vulnerable_apis, external_apis, internal_apis
            )
            
            # CVSS 점수 추출 (NVD 우선, 다른 소스로 폴백)
            cvss_score = 0.0
            if 'cvss' in vuln:
                if 'nvd' in vuln['cvss'] and 'V3Score' in vuln['cvss']['nvd']:
                    cvss_score = vuln['cvss']['nvd']['V3Score']
                elif 'ghsa' in vuln['cvss'] and 'V3Score' in vuln['cvss']['ghsa']:
                    cvss_score = vuln['cvss']['ghsa']['V3Score']
                elif 'redhat' in vuln['cvss'] and 'V3Score' in vuln['cvss']['redhat']:
                    cvss_score = vuln['cvss']['redhat']['V3Score']
            
            epss_score = self._fetch_epss_score(cve_id)

            context = VulnerabilityContext(
                cve_id=cve_id,
                package_name=package_name,
                version=version,
                severity=vuln['severity'],
                cvss_score=cvss_score,
                epss_score=epss_score,
                description=vuln.get('description', '설명 없음'),
                vulnerable_apis=vulnerable_apis,
                used_apis=matching_apis,
                is_api_used=is_used,
                is_external_api_used=is_external_used,
                external_apis=matching_external,
                fix_version=vuln.get('fixed_version', 'Unknown')
            )
            
            contexts.append(context)
        
        return contexts
    
    def search_real_world_cases(self, contexts: List[VulnerabilityContext]) -> Dict[str, List[Dict[str, str]]]:
        """
        Perplexity를 사용해 실제 사례 검색
        
        Args:
            contexts: 취약점 컨텍스트 리스트
            
        Returns:
            CVE ID를 키로 하는 실제 사례 딕셔너리
        """
        if not self.perplexity_enabled or not self.perplexity_searcher:
            logger.info("Perplexity 검색 비활성화됨 - 실제 사례 생략")
            return {}
        
        logger.info("Perplexity를 통한 실제 사례 검색 시작...")
        
        # 컨텍스트를 딕셔너리로 변환
        cve_contexts = [
            {
                "cve_id": ctx.cve_id,
                "package_name": ctx.package_name,
                "description": ctx.description
            }
            for ctx in contexts
        ]
        
        # 일괄 검색
        results = self.perplexity_searcher.search_multiple_cves(cve_contexts)
        
        return results
    
    def group_by_module(self, 
                       contexts: List[VulnerabilityContext],
                       real_world_cases: Optional[Dict[str, List[Dict[str, str]]]] = None) -> Dict[str, Dict[str, Any]]:
        """
        취약점을 패키지/모듈별로 그룹화합니다
        
        Args:
            contexts: 취약점 컨텍스트 리스트
            real_world_cases: CVE별 실제 사례 딕셔너리 (선택사항)
            
        Returns:
            모듈별로 그룹화된 취약점 딕셔너리
        """
        modules = {}
        
        if real_world_cases is None:
            real_world_cases = {}
        
        for ctx in contexts:
            if ctx.package_name not in modules:
                modules[ctx.package_name] = {
                    'package_name': ctx.package_name,
                    'current_version': ctx.version,
                    'vulnerabilities': [],
                    'fix_versions': set(),
                    'has_external_exposure': False  # Docker 외부 노출 여부
                }
            
            # 이 CVE에 대한 실제 사례 가져오기
            cve_cases = real_world_cases.get(ctx.cve_id, [])
            
            # 취약점 정보 추가
            vuln_info = {
                'cve_id': ctx.cve_id,
                'severity': ctx.severity,
                'cvss_score': ctx.cvss_score,
                'epss_score': ctx.epss_score,
                'description': ctx.description,
                'vulnerable_functions': ctx.vulnerable_apis,
                'functions_used_in_code': ctx.is_api_used,
                'matching_functions': ctx.used_apis,
                'external_api_exposed': ctx.is_external_api_used,
                'external_functions': ctx.external_apis,
                'real_world_cases': cve_cases  # 실제 사례 추가
            }
            
            modules[ctx.package_name]['vulnerabilities'].append(vuln_info)
            
            # 모듈에 external API 노출이 있는지 추적
            if ctx.is_external_api_used:
                modules[ctx.package_name]['has_external_exposure'] = True
            
            # 수정 버전 추적
            if ctx.fix_version and ctx.fix_version != 'Unknown':
                modules[ctx.package_name]['fix_versions'].add(ctx.fix_version)
        
        # fix_versions set을 list로 변환하고 최신/권장 버전 선택
        for module in modules.values():
            fix_versions = list(module['fix_versions'])
            module['fix_versions'] = fix_versions
            # 첫 번째 수정 버전을 대상으로 사용 (버전 파싱으로 개선 가능)
            module['target_fix_version'] = fix_versions[0] if fix_versions else 'Unknown'
        
        return modules
    
    def create_llm_prompt(self, modules: Dict[str, Dict[str, Any]]) -> str:
        """
        사전 그룹화된 모듈로 LLM 분석을 위한 포괄적인 프롬프트를 생성합니다
        
        Args:
            modules: 그룹화된 모듈 딕셔너리
            
        Returns:
            LLM에 전달할 프롬프트 문자열
        """
        
        prompt = """당신은 소프트웨어 프로젝트의 취약점 패치 우선순위를 정하는 보안 분석가입니다.

다음은 패키지/모듈별로 그룹화된 취약점에 대한 상세 정보입니다:

"""
        
        for i, (pkg_name, module_data) in enumerate(modules.items(), 1):
            # Docker 외부 노출 여부 표시
            external_warning = " ⚠️ DOCKER 외부 노출" if module_data.get('has_external_exposure', False) else ""
            

            prompt += f"""
## Module {i}: {pkg_name}{external_warning}

**Current Version:** {module_data['current_version']}
**Fix Versions Available:** {', '.join(module_data['fix_versions']) if module_data['fix_versions'] else 'Unknown'}
**Total Vulnerabilities:** {len(module_data['vulnerabilities'])}
**External API Exposure:** {'YES - 외부로 노출되는 취약한 API 사용 중 ⚠️' if module_data.get('has_external_exposure', False) else 'NO'}

### Vulnerabilities in this module:

"""
            
            for j, vuln in enumerate(module_data['vulnerabilities'], 1):
                external_exposure = ""
                if vuln.get('external_api_exposed', False):
                    external_exposure = f"\n⚠️ **CRITICAL: Docker 환경에서 외부로 노출되는 API 사용 중!**\n- 노출된 취약 함수: {', '.join(vuln.get('external_functions', []))}"
                
                # 실제 사례 정보 추가
                real_cases = vuln.get('real_world_cases', [])
                cases_info = ""
                if real_cases:
                    cases_info = f"\n\n**Real-World Cases Found ({len(real_cases)} cases):**\n"
                    for case in real_cases[:3]:  # 최대 3개만 표시
                        cases_info += f"- {case.get('title', 'N/A')} ({case.get('date', 'Unknown date')})\n"
                        cases_info += f"  {case.get('description', '')[:150]}...\n"
                        cases_info += f"  Source: {case.get('source_url', 'N/A')}\n"
                
                
                epss_value = vuln.get('epss_score', 'Unknown')
                if isinstance(epss_value, (int, float)):
                    epss_display = f"{epss_value:.3f}"
                else:
                    epss_display = str(epss_value)

                prompt += f"""
#### {j}. {vuln['cve_id']} ({vuln['severity']}, CVSS: {vuln['cvss_score']})

**Description:** {vuln['description'][:300]}...

**EPSS Score:** {epss_display}

**Vulnerable Functions:**
{', '.join(vuln['vulnerable_functions']) if vuln['vulnerable_functions'] else 'Not specified'}

**Usage in Codebase:**
- Functions used in code: {'YES ✓' if vuln['functions_used_in_code'] else 'NO ✗'}
{f"- Matching functions: {', '.join(vuln['matching_functions'])}" if vuln['matching_functions'] else ""}
{external_exposure}
{cases_info}

---
"""
        
        prompt += f"""

위에 나열된 **{len(modules)}개 모듈**에 대한 정보를 바탕으로 패치 우선순위를 분석해주세요.

**중요: 위에 나열된 모든 {len(modules)}개 모듈에 대한 분석을 제공해야 합니다.**

**우선순위 결정 시 핵심 고려사항:**
1. **Docker 외부 노출 (최우선)**: 외부로 노출되는 취약한 API가 사용되는 경우 CRITICAL 우선순위로 처리
2. **실제 사례**: 실제 공격이나 사고가 보고된 경우 우선순위 상향
3. **EPSS 점수**: 실제 악용 가능성이 높은 취약점일수록 우선순위를 높게 책정
4. CVSS 점수와 심각도
5. 취약한 함수의 실제 사용 여부
6. 공격 가능성과 잠재적 영향도

각 모듈별로 다음을 제공하세요:

1. **모듈 정보**
   - 패키지 이름과 현재 버전
   - 우선순위 레벨 (CRITICAL/HIGH/MEDIUM/LOW)
   - 전체 위험 점수 (1-100)
   - **Docker 외부 노출 여부 (매우 중요!)**

2. **취약점 분석**
   - 이 모듈의 각 CVE에 대해:
     * 공격 시나리오 (어떻게 악용될 수 있는지)
     * 잠재적 영향 (어떤 피해가 발생할 수 있는지)
     * 취약한 함수가 실제로 사용되는지 여부
     * **Docker 환경에서 외부 공격자가 접근 가능한지 여부**

3. **패치 지침**
   - 업그레이드 대상 버전 (제공된 수정 버전 사용)
   - 정확한 업그레이드 명령어 (예: `pip install package>=version`)
   - 주요 변경사항이나 호환성 문제
   - 테스트 권장사항

4. **실제 사례**
   - 제공된 실제 사례를 기반으로 분석
   - 프로덕션 환경에서의 유사한 사고
   - 보안 권고사항 링크

응답은 반드시 유효한 JSON 형식으로만 제공해주세요. JSON 코드 블록(```)이나 다른 텍스트 없이 순수 JSON만 출력하세요:

{{
  "modules_by_priority": [
    {{
      "package_name": "PackageName",
      "current_version": "1.0.0",
      "priority_level": "CRITICAL",
      "risk_score": 95,
      "docker_external_exposure": true,
      "vulnerabilities": [
        {{
          "cve_id": "CVE-XXXX-XXXXX",
          "severity": "CRITICAL",
          "cvss_score": 9.8,
          "epss_score": 0.85,
          "vulnerable_functions": ["function1", "function2"],
          "functions_used_in_code": true,
          "external_api_exposed": true,
          "exploit_scenario": "어떻게 악용될 수 있는지",
          "potential_impact": "어떤 피해가 발생할 수 있는지"
        }}
      ],
      "patching": {{
        "target_version": "2.0.0",
        "upgrade_command": "pip install PackageName>=2.0.0",
        "breaking_changes": ["변경사항이 있다면"],
        "compatibility_notes": "호환성 정보",
        "testing_steps": ["테스트 단계 1", "테스트 단계 2"]
      }},
      "real_world_cases": [
        {{
          "title": "사례 제목",
          "description": "사례 설명",
          "source_url": "URL",
          "date": "날짜"
        }}
      ],
      "overall_recommendation": "이 우선순위로 패치해야 하는 이유"
    }}
  ],
  "summary": {{
    "total_modules": {len(modules)},
    "critical_modules": 0,
    "high_priority_modules": 0,
    "medium_priority_modules": 0,
    "low_priority_modules": 0,
    "total_vulnerabilities": 0,
    "external_exposed_modules": 0
  }},
  "patching_roadmap": {{
    "immediate": ["지금 패치할 패키지"],
    "this_week": ["1주일 이내 패치할 패키지"],
    "this_month": ["1개월 이내 패치할 패키지"],
    "when_convenient": ["낮은 우선순위 패키지"]
  }},
  "overall_assessment": "전체 보안 평가 및 행동 계획"
}}

기억하세요: 위에 나열된 모든 {len(modules)}개 모듈을 분석해야 합니다.
"""
        
        return prompt
    
    def _attempt_json_recovery(self, response_text: str) -> Optional[Any]:
        """LLM 응답에서 유효한 JSON 세그먼트를 추출하려고 시도합니다."""
        decoder = json.JSONDecoder()
        candidates: List[Tuple[int, int, Any]] = []

        for opening in ("{", "["):
            start = response_text.find(opening)
            while start != -1:
                try:
                    obj, end = decoder.raw_decode(response_text, start)
                except json.JSONDecodeError:
                    start = response_text.find(opening, start + 1)
                    continue

                if isinstance(obj, (dict, list)):
                    candidates.append((start, end, obj))

                start = response_text.find(opening, start + 1)

        if not candidates:
            return None

        # 가장 앞에서 찾은 JSON 조각 사용
        candidates.sort(key=lambda item: item[0])
        start, end, obj = candidates[0]
        if end < len(response_text.strip()):
            logger.warning("LLM 응답의 JSON 이후 텍스트를 무시했습니다 (offset %d-%d).", start, end)

        return obj if isinstance(obj, (dict, list)) else None

    def _persist_claude_response(
        self,
        raw_text: str,
        cleaned_text: str,
        parsed_payload: Optional[Any] = None,
        error: Optional[str] = None,
    ) -> None:
        """Claude 응답을 JSON 포맷으로 저장합니다."""
        target_path = getattr(self, '_claude_raw_response_path', None)
        if not target_path:
            return
        payload: Dict[str, Any] = {
            'timestamp': datetime.utcnow().isoformat(timespec='seconds'),
            'raw_text': raw_text,
            'cleaned_text': cleaned_text,
        }
        if parsed_payload is not None:
            payload['parsed_payload'] = parsed_payload
        if error:
            payload['error'] = error
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with target_path.open('w', encoding='utf-8') as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.debug('Claude raw 응답 저장 실패(%s): %s', target_path, exc)
        else:
            logger.debug('Claude raw 응답 저장 -> %s', target_path)


    def evaluate_priorities(self, modules: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        그룹화된 취약점 데이터를 LLM에 전송하여 우선순위를 평가합니다
        
        Args:
            modules: 취약점이 포함된 모듈 딕셔너리
        
        Returns:
            우선순위가 지정된 모듈 및 권장사항이 포함된 딕셔너리
        """
        prompt = self.create_llm_prompt(modules)
        
        response_text = ""
        cleaned_text = ""
        try:
            # Claude API 호출
            response = self.client.messages.create(
                model=self.model,
                max_tokens=20000,
                temperature=0.3,
                system="당신은 취약점 평가와 패치 우선순위 결정을 전문으로 하는 보안 분석 전문가입니다.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            # 응답 텍스트 추출
            content_blocks = getattr(response, "content", [])
            if not content_blocks:
                raise ValueError("LLM 응답이 비어 있습니다.")

            parts: List[str] = []
            for block in content_blocks:
                text_value = getattr(block, "text", None)
                if text_value is None and isinstance(block, dict):
                    text_value = block.get("text")
                if text_value is not None:
                    parts.append(text_value)

            response_text = "".join(parts) if parts else str(content_blocks[0])
            logger.debug("LLM raw response length: %d chars", len(response_text))

            cleaned_text = response_text
            if "```json" in cleaned_text:
                json_start = cleaned_text.find("```json") + 7
                json_end = cleaned_text.find("```", json_start)
                cleaned_text = cleaned_text[json_start:json_end].strip()
            elif "```" in cleaned_text:
                json_start = cleaned_text.find("```") + 3
                json_end = cleaned_text.find("```", json_start)
                cleaned_text = cleaned_text[json_start:json_end].strip()

            try:
                result = json.loads(cleaned_text)
            except json.JSONDecodeError as decode_error:
                recovered = self._attempt_json_recovery(cleaned_text)
                if recovered is not None:
                    logger.info('LLM 응답 JSON 복구 성공 (원본 오류: %s)', decode_error)
                    self._persist_claude_response(
                        response_text,
                        cleaned_text,
                        parsed_payload=recovered,
                        error=str(decode_error),
                    )
                    return recovered
                self._persist_claude_response(
                    response_text,
                    cleaned_text,
                    parsed_payload=None,
                    error=str(decode_error),
                )
                raise
            else:
                self._persist_claude_response(
                    response_text,
                    cleaned_text,
                    parsed_payload=result,
                )
                return result

        except json.JSONDecodeError as e:
            logger.error(f"LLM JSON 파싱 실패: {e}")
            candidate_text = cleaned_text or response_text or ""
            if candidate_text:
                snippet = candidate_text[:800].replace("\n", " ")
                logger.debug("LLM raw response (truncated): %s", snippet)
            recovered = self._attempt_json_recovery(candidate_text)
            if recovered is not None:
                logger.info("LLM 응답에서 JSON 구조를 복구했습니다.")
                self._persist_claude_response(
                    response_text or candidate_text,
                    candidate_text,
                    parsed_payload=recovered,
                    error=str(e),
                )
                return recovered
            logger.warning("LLM 응답을 JSON으로 파싱하지 못해 점수 기반 폴백을 사용합니다.")
            fallback_result = self._fallback_prioritization_by_module(modules)
            self._persist_claude_response(
                response_text or candidate_text,
                candidate_text,
                parsed_payload=fallback_result,
                error=str(e),
            )
            return fallback_result
        except Exception as e:
            logger.error(f"LLM API 호출 오류: {e}")
            candidate_text = cleaned_text or response_text or ""
            if candidate_text:
                snippet = candidate_text[:800].replace("\n", " ")
                logger.debug("LLM raw response (truncated): %s", snippet)
            else:
                logger.debug("LLM raw response가 비어 있습니다.")
            logger.warning("LLM 호출 실패로 점수 기반 폴백을 사용합니다.")
            fallback_result = self._fallback_prioritization_by_module(modules)
            self._persist_claude_response(
                response_text or candidate_text,
                candidate_text,
                parsed_payload=fallback_result,
                error=str(e),
            )
            return fallback_result

    def _fallback_prioritization_by_module(self, modules: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        LLM 실패 시 간단한 점수 기반 폴백 우선순위 지정
        
        Args:
            modules: 모듈 딕셔너리
            
        Returns:
            점수 기반으로 우선순위가 지정된 결과
        """
        scored_modules = []
        
        severity_weights = {
            'CRITICAL': 40,
            'HIGH': 30,
            'MEDIUM': 20,
            'LOW': 10
        }
        
        for pkg_name, module_data in modules.items():
            # 모든 취약점을 기반으로 모듈 점수 계산
            module_score = 0
            has_used_vuln = False
            has_external_exposure = module_data.get('has_external_exposure', False)
            has_real_cases = False
            max_cvss = 0
            has_high_epss = False
            all_real_cases = []
            
            for vuln in module_data['vulnerabilities']:
                vuln_score = severity_weights.get(vuln['severity'], 10)
                vuln_score += vuln['cvss_score'] * 3
                epss_val = float(vuln.get('epss_score') or 0.0)
                vuln_score += epss_val * 60
                if epss_val >= 0.7:
                    vuln_score += 15
                elif epss_val >= 0.4:
                    vuln_score += 5
                
                # 취약한 함수가 사용되는 경우
                if vuln['functions_used_in_code']:
                    vuln_score += 25
                    has_used_vuln = True
                
                # Docker 외부 노출 API 사용 시 점수 대폭 증가
                if vuln.get('external_api_exposed', False):
                    vuln_score += 50
                
                # 실제 사례가 있는 경우 점수 증가
                if vuln.get('real_world_cases'):
                    vuln_score += 20
                    has_real_cases = True
                    all_real_cases.extend(vuln['real_world_cases'])

                if epss_val >= 0.7:
                    has_high_epss = True

                module_score += vuln_score
                max_cvss = max(max_cvss, vuln['cvss_score'])
            
            # 취약점당 평균 점수
            avg_score = module_score / len(module_data['vulnerabilities'])
            
            # 추가 점수 조정
            if has_used_vuln:
                avg_score += 15
            if has_external_exposure:
                avg_score += 30
            if has_real_cases:
                avg_score += 10
            if has_high_epss:
                avg_score += 10
            
            # 100점 초과 방지
            avg_score = min(avg_score, 100)
            
            priority_level = 'CRITICAL' if avg_score >= 75 or has_external_exposure else \
                           'HIGH' if avg_score >= 50 else \
                           'MEDIUM' if avg_score >= 30 else 'LOW'
            
            scored_modules.append({
                'package_name': pkg_name,
                'current_version': module_data['current_version'],
                'priority_level': priority_level,
                'risk_score': int(avg_score),
                'docker_external_exposure': has_external_exposure,
                'vulnerabilities': [
                    {
                        'cve_id': v['cve_id'],
                        'severity': v['severity'],
                        'cvss_score': v['cvss_score'],
                        'epss_score': v.get('epss_score', 0.0),
                        'vulnerable_functions': v['vulnerable_functions'],
                        'functions_used_in_code': v['functions_used_in_code'],
                        'external_api_exposed': v.get('external_api_exposed', False),
                        'exploit_scenario': f"자동 평가: {v['severity']} 심각도 취약점" + 
                                          (" - Docker 외부 노출 ⚠️" if v.get('external_api_exposed', False) else "") +
                                          (" - 실제 공격 사례 존재" if v.get('real_world_cases') else "") +
                                          (f" - EPSS {v.get('epss_score', 0.0):.2f}" if v.get('epss_score') is not None else ""),
                        'potential_impact': f"CVSS 점수 {v['cvss_score']}는 {'높은' if v['cvss_score'] >= 7 else '중간'} 영향을 나타냄" +
                                          (" - 외부 공격자가 직접 접근 가능" if v.get('external_api_exposed', False) else "")
                    }
                    for v in module_data['vulnerabilities']
                ],
                'patching': {
                    'target_version': module_data['target_fix_version'],
                    'upgrade_command': f"pip install {pkg_name}>={module_data['target_fix_version']}",
                    'breaking_changes': [],
                    'compatibility_notes': '자동 권장사항입니다. 릴리스 노트를 확인하세요.',
                    'testing_steps': ['전체 테스트 스위트 실행', '애플리케이션 기능 확인']
                },
                'real_world_cases': all_real_cases[:5],  # 최대 5개
                'overall_recommendation': f"{'즉시' if avg_score >= 75 or has_external_exposure else '계획된'} 패치 권장. " +
                                        f"점수: {int(avg_score)}/100" +
                                        (" - Docker 외부 노출로 인한 긴급 조치 필요" if has_external_exposure else "") +
                                        (" - 실제 공격 사례 존재" if has_real_cases else "") +
                                        (" - EPSS 고위험" if has_high_epss else "")
            })
        
        scored_modules.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return {
            'modules_by_priority': scored_modules,
            'summary': {
                'total_modules': len(scored_modules),
                'critical_modules': sum(1 for m in scored_modules if m['priority_level'] == 'CRITICAL'),
                'high_priority_modules': sum(1 for m in scored_modules if m['priority_level'] == 'HIGH'),
                'medium_priority_modules': sum(1 for m in scored_modules if m['priority_level'] == 'MEDIUM'),
                'low_priority_modules': sum(1 for m in scored_modules if m['priority_level'] == 'LOW'),
                'total_vulnerabilities': sum(len(m['vulnerabilities']) for m in scored_modules),
                'external_exposed_modules': sum(1 for m in scored_modules if m.get('docker_external_exposure', False))
            },
            'patching_roadmap': {
                'immediate': [m['package_name'] for m in scored_modules if m['priority_level'] == 'CRITICAL'],
                'this_week': [m['package_name'] for m in scored_modules if m['priority_level'] == 'HIGH'],
                'this_month': [m['package_name'] for m in scored_modules if m['priority_level'] == 'MEDIUM'],
                'when_convenient': [m['package_name'] for m in scored_modules if m['priority_level'] == 'LOW']
            },
            'overall_assessment': '폴백 우선순위 지정이 사용되었습니다. ' +
                                '외부 노출된 모듈과 위험 점수 >= 75인 모듈에 즉시 집중하세요.'
        }
    
    def run_analysis(self, 
                     ast_file: str,
                     gpt5_results_file: str,
                     lib2cve2api_file: str,
                     trivy_file: str,
                     output_file: str = 'patch_priorities.json'):
        """
        전체 분석 파이프라인을 실행합니다
        
        Args:
            ast_file: AST 분석 결과 파일 경로
            gpt5_results_file: GPT5 CVE 매핑 결과 파일 경로
            lib2cve2api_file: 라이브러리-CVE-API 매핑 파일 경로
            trivy_file: Trivy 스캔 결과 파일 경로
            output_file: 우선순위 결과를 저장할 파일 경로
            
        Returns:
            분석 결과 딕셔너리
        """
        data_dir = Path(ast_file).resolve().parent
        self._claude_raw_response_path = data_dir / 'fetch_prioiriy_raw_response.json'
        if self.perplexity_searcher:
            self.perplexity_searcher.set_raw_response_dir(data_dir / 'perplexity_raw_responses')
        logger.info("취약점 데이터 로딩 중...")
        data = self.load_data(ast_file, gpt5_results_file, lib2cve2api_file, trivy_file)
        
        logger.info("취약점 컨텍스트 구축 중...")
        contexts = self.build_vulnerability_contexts(data)
        logger.info(f"분석할 취약점 {len(contexts)}개 발견")
        
        # Perplexity로 실제 사례 검색
        real_world_cases = {}
        if self.perplexity_enabled:
            try:
                real_world_cases = self.search_real_world_cases(contexts)
            except Exception as e:
                logger.warning(f"실제 사례 검색 중 오류 발생: {e}")
        
        logger.info("모듈별로 취약점 그룹화 중...")
        modules = self.group_by_module(contexts, real_world_cases)
        logger.info(f"{len(modules)}개 모듈로 그룹화됨: {', '.join(modules.keys())}")
        
        logger.info("Claude를 통한 우선순위 평가 중...")
        results = self.evaluate_priorities(modules)
        
        # 메타데이터 추가
        results['metadata'] = {
            'total_vulnerabilities': len(contexts),
            'scan_date': data['trivy']['scan_info']['scan_date'],
            'target': data['trivy']['scan_info']['target'],
            'perplexity_enabled': self.perplexity_enabled,
            'real_world_cases_found': sum(len(cases) for cases in real_world_cases.values())
        }
        
        # 결과 저장
        write_json(output_file, results)
        
        logger.info(f"\n✓ 분석 완료! 결과가 {output_file}에 저장되었습니다")
        logger.info(f"\n요약:")
        summary = results.get('summary', {})
        logger.info(f"  분석된 전체 모듈 수: {summary.get('total_modules', 0)}")
        logger.info(f"  🚨 Docker 외부 노출 모듈: {summary.get('external_exposed_modules', 0)}")
        logger.info(f"  Critical 우선순위: {summary.get('critical_modules', 0)}")
        logger.info(f"  High 우선순위: {summary.get('high_priority_modules', 0)}")
        logger.info(f"  Medium 우선순위: {summary.get('medium_priority_modules', 0)}")
        logger.info(f"  Low 우선순위: {summary.get('low_priority_modules', 0)}")
        logger.info(f"  전체 취약점 수: {summary.get('total_vulnerabilities', 0)}")
        if self.perplexity_enabled:
            logger.info(f"  📚 발견된 실제 사례: {results['metadata'].get('real_world_cases_found', 0)}개")
        
        self._claude_raw_response_path = None
        return results


__all__ = [
    "Severity",
    "VulnerabilityContext",
    "PatchPriorityEvaluator",
]
