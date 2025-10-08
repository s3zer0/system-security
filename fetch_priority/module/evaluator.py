import json
import os
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from dotenv import load_dotenv

# Anthropic API 사용
import anthropic

# .env 파일에서 환경 변수 로드
load_dotenv()


class Severity(Enum):
    """취약점 심각도 레벨"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class VulnerabilityContext:
    """취약점 분석을 위한 통합 컨텍스트"""
    cve_id: str
    package_name: str
    version: str
    severity: str
    cvss_score: float
    description: str
    vulnerable_apis: List[str]
    used_apis: List[str]  # 코드베이스에서 실제 사용되는 API
    is_api_used: bool
    is_external_api_used: bool  # Docker 환경에서 외부 노출 API 사용 여부
    external_apis: List[str]  # 외부로 노출되는 취약한 API 목록
    fix_version: str


class PatchPriorityEvaluator:
    """취약점 패치 우선순위를 평가하는 클래스"""
    
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5-20250929"):
        """
        LLM 자격 증명으로 평가자 초기화
        
        Args:
            api_key: Anthropic API 키
            model: 사용할 Claude 모델 이름
        """
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
    
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
        with open(ast_file, 'r', encoding='utf-8') as f:
            ast_data = json.load(f)
        with open(gpt5_results_file, 'r', encoding='utf-8') as f:
            gpt5_results = json.load(f)
        with open(lib2cve2api_file, 'r', encoding='utf-8') as f:
            lib2cve2api = json.load(f)
        with open(trivy_file, 'r', encoding='utf-8') as f:
            trivy_data = json.load(f)
        
        return {
            'ast': ast_data,
            'gpt5_results': gpt5_results,
            'lib2cve2api': lib2cve2api,
            'trivy': trivy_data
        }
    
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
                            # Flatten any nested dict values just in case
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
            
            context = VulnerabilityContext(
                cve_id=cve_id,
                package_name=package_name,
                version=version,
                severity=vuln['severity'],
                cvss_score=cvss_score,
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
    
    def group_by_module(self, contexts: List[VulnerabilityContext]) -> Dict[str, Dict[str, Any]]:
        """
        취약점을 패키지/모듈별로 그룹화합니다
        
        Args:
            contexts: 취약점 컨텍스트 리스트
            
        Returns:
            모듈별로 그룹화된 취약점 딕셔너리
        """
        modules = {}
        
        for ctx in contexts:
            if ctx.package_name not in modules:
                modules[ctx.package_name] = {
                    'package_name': ctx.package_name,
                    'current_version': ctx.version,
                    'vulnerabilities': [],
                    'fix_versions': set(),
                    'has_external_exposure': False  # Docker 외부 노출 여부
                }
            
            # 취약점 정보 추가
            vuln_info = {
                'cve_id': ctx.cve_id,
                'severity': ctx.severity,
                'cvss_score': ctx.cvss_score,
                'description': ctx.description,
                'vulnerable_functions': ctx.vulnerable_apis,
                'functions_used_in_code': ctx.is_api_used,
                'matching_functions': ctx.used_apis,
                'external_api_exposed': ctx.is_external_api_used,  # Docker 외부 노출 API 사용
                'external_functions': ctx.external_apis
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
                
                prompt += f"""
#### {j}. {vuln['cve_id']} ({vuln['severity']}, CVSS: {vuln['cvss_score']})

**Description:** {vuln['description'][:300]}...

**Vulnerable Functions:**
{', '.join(vuln['vulnerable_functions']) if vuln['vulnerable_functions'] else 'Not specified'}

**Usage in Codebase:**
- Functions used in code: {'YES ✓' if vuln['functions_used_in_code'] else 'NO ✗'}
{f"- Matching functions: {', '.join(vuln['matching_functions'])}" if vuln['matching_functions'] else ""}
{external_exposure}

---
"""
        
        prompt += f"""

위에 나열된 **{len(modules)}개 모듈**에 대한 정보를 바탕으로 패치 우선순위를 분석해주세요.

**중요: 위에 나열된 모든 {len(modules)}개 모듈에 대한 분석을 제공해야 합니다.**

**우선순위 결정 시 핵심 고려사항:**
1. **Docker 외부 노출 (최우선)**: 외부로 노출되는 취약한 API가 사용되는 경우 CRITICAL 우선순위로 처리
2. CVSS 점수와 심각도
3. 취약한 함수의 실제 사용 여부
4. 공격 가능성과 잠재적 영향도

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
   - 이러한 CVE에 대한 알려진 공격이나 사례
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
      "vulnerabilities": [
        {{
          "cve_id": "CVE-XXXX-XXXXX",
          "severity": "CRITICAL",
          "cvss_score": 9.8,
          "vulnerable_functions": ["function1", "function2"],
          "functions_used_in_code": true,
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
    "total_vulnerabilities": 0
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
    
    def evaluate_priorities(self, modules: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        그룹화된 취약점 데이터를 LLM에 전송하여 우선순위를 평가합니다
        
        Args:
            modules: 취약점이 포함된 모듈 딕셔너리
        
        Returns:
            우선순위가 지정된 모듈 및 권장사항이 포함된 딕셔너리
        """
        prompt = self.create_llm_prompt(modules)
        
        try:
            # Claude API 호출
            response = self.client.messages.create(
                model=self.model,
                max_tokens=8000,
                temperature=0.3,
                system="당신은 취약점 평가와 패치 우선순위 결정을 전문으로 하는 보안 분석 전문가입니다.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # 응답 텍스트 추출
            response_text = response.content[0].text
            
            # JSON 파싱 (코드 블록이 있다면 제거)
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            
            result = json.loads(response_text)
            return result
            
        except Exception as e:
            print(f"LLM API 호출 오류: {e}")
            print(f"오류 세부사항: {type(e).__name__}")
            return self._fallback_prioritization_by_module(modules)
    
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
            max_cvss = 0
            
            for vuln in module_data['vulnerabilities']:
                vuln_score = severity_weights.get(vuln['severity'], 10)
                vuln_score += vuln['cvss_score'] * 3
                
                # 취약한 함수가 사용되는 경우
                if vuln['functions_used_in_code']:
                    vuln_score += 25
                    has_used_vuln = True
                
                # Docker 외부 노출 API 사용 시 점수 대폭 증가 (최우선 처리)
                if vuln.get('external_api_exposed', False):
                    vuln_score += 50  # 외부 노출 시 추가 점수
                
                module_score += vuln_score
                max_cvss = max(max_cvss, vuln['cvss_score'])
            
            # 취약점당 평균 점수
            avg_score = module_score / len(module_data['vulnerabilities'])
            
            # 취약한 함수가 사용되는 경우 점수 증가
            if has_used_vuln:
                avg_score += 15
            
            # Docker 외부 노출이 있는 경우 추가 점수 (모듈 레벨)
            if has_external_exposure:
                avg_score += 30
            
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
                        'vulnerable_functions': v['vulnerable_functions'],
                        'functions_used_in_code': v['functions_used_in_code'],
                        'external_api_exposed': v.get('external_api_exposed', False),
                        'exploit_scenario': f"자동 평가: {v['severity']} 심각도 취약점" + 
                                          (" - Docker 외부 노출 ⚠️" if v.get('external_api_exposed', False) else ""),
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
                'real_world_cases': [],
                'overall_recommendation': f"{'즉시' if avg_score >= 75 or has_external_exposure else '계획된'} 패치 권장. " +
                                        f"점수: {int(avg_score)}/100" +
                                        (" - Docker 외부 노출로 인한 긴급 조치 필요" if has_external_exposure else "")
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
        print("취약점 데이터 로딩 중...")
        data = self.load_data(ast_file, gpt5_results_file, lib2cve2api_file, trivy_file)
        
        print("취약점 컨텍스트 구축 중...")
        contexts = self.build_vulnerability_contexts(data)
        print(f"분석할 취약점 {len(contexts)}개 발견")
        
        print("모듈별로 취약점 그룹화 중...")
        modules = self.group_by_module(contexts)
        print(f"{len(modules)}개 모듈로 그룹화됨: {', '.join(modules.keys())}")
        
        print("Claude를 통한 우선순위 평가 중...")
        results = self.evaluate_priorities(modules)
        
        # 메타데이터 추가
        results['metadata'] = {
            'total_vulnerabilities': len(contexts),
            'scan_date': data['trivy']['scan_info']['scan_date'],
            'target': data['trivy']['scan_info']['target']
        }
        
        # 결과 저장
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n✓ 분석 완료! 결과가 {output_file}에 저장되었습니다")
        print(f"\n요약:")
        summary = results.get('summary', {})
        print(f"  분석된 전체 모듈 수: {summary.get('total_modules', 0)}")
        print(f"  🚨 Docker 외부 노출 모듈: {summary.get('external_exposed_modules', 0)}")
        print(f"  Critical 우선순위: {summary.get('critical_modules', 0)}")
        print(f"  High 우선순위: {summary.get('high_priority_modules', 0)}")
        print(f"  Medium 우선순위: {summary.get('medium_priority_modules', 0)}")
        print(f"  Low 우선순위: {summary.get('low_priority_modules', 0)}")
        print(f"  전체 취약점 수: {summary.get('total_vulnerabilities', 0)}")
        
        return results

__all__ = [
    "Severity",
    "VulnerabilityContext",
    "PatchPriorityEvaluator",
]
