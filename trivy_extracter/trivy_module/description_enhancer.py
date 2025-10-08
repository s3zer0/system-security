"""
취약점 설명 향상 모듈 - LLM으로 CVE 설명을 이해하기 쉽게 변환
"""

import os
import json
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from anthropic import Anthropic
from dotenv import load_dotenv

class DescriptionEnhancer:
    """CVE 설명을 개발자 친화적으로 변환하는 클래스"""
    
    def __init__(self, api_key: str = None, max_workers: int = 3):
        """
        초기화
        
        Args:
            api_key: Anthropic API 키
            max_workers: 병렬 처리 워커 수
        """
        load_dotenv()

        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not found")
        
        self.client = Anthropic(api_key=self.api_key)
        self.max_workers = max_workers
    
    def enhance_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """단일 취약점 설명을 향상"""
        cve_id = vulnerability.get("id", "Unknown")
        package = vulnerability.get("package_name", "Unknown")
        severity = vulnerability.get("severity", "UNKNOWN")
        cvss_score = self._extract_cvss_score(vulnerability.get("cvss", {}))
        description = vulnerability.get("description", "")
        
        prompt = f"""당신은 보안 전문가입니다. 다음 CVE 취약점을 개발자가 쉽게 이해할 수 있도록 설명해주세요.

    ## 취약점 정보
    - **CVE ID**: {cve_id}
    - **패키지**: {package}
    - **심각도**: {severity}
    - **CVSS 점수**: {cvss_score}

    ## 원본 설명 (기술적)
    {description}

    ## 요청사항
    반드시 아래 JSON 형식으로만 응답하세요. 문자열 내부의 따옴표는 이스케이프하고, 줄바꿈은 사용하지 마세요.

    {{
    "simple_summary": "비전공자도 이해할 수 있는 한 줄 요약 (한국어, 30자 이내)",
    "what_is_it": "이 취약점이 무엇인지 쉬운 말로 설명 (한국어, 2-3 문장)",
    "attack_scenario": "공격자가 이 취약점을 어떻게 악용하는지 구체적 시나리오 (한국어, 3-4 문장)",
    "real_world_impact": "실제로 발생할 수 있는 피해 (한국어, 2-3 문장)",
    "how_to_check": "내 시스템이 영향받는지 확인하는 방법 (한국어, 2-3 문장)",
    "immediate_action": "당장 해야 할 조치 (한국어, 구체적인 명령어 포함)",
    "why_critical": "왜 {severity} 심각도인지 이유 (한국어, 1-2 문장)",
    "related_cves": []
    }}

    **중요 규칙**: 
    - 모든 응답은 반드시 유효한 JSON이어야 합니다
    - 문자열 내부에 따옴표가 필요하면 \\"로 이스케이프하세요
    - 줄바꿈(\n), 탭(\t) 등 특수문자는 이스케이프하세요
    - 백슬래시(\\)는 \\\\로 이스케이프하세요
    - JSON만 반환하고 다른 텍스트는 절대 포함하지 마세요"""

        max_retries = 3  # 재시도 횟수
        
        for attempt in range(max_retries):
            try:
                # Claude API 호출
                response = self.client.messages.create(
                    model="claude-sonnet-4-5-20250929",
                    max_tokens=2000,
                    temperature=0.2,
                    system="당신은 보안 취약점을 쉽게 설명하는 전문가입니다. 반드시 유효한 JSON으로만 응답하세요. 문자열 내부의 모든 특수 문자를 올바르게 이스케이프하세요.",
                    messages=[{"role": "user", "content": prompt}]
                )
                
                # 응답 파싱
                content = response.content[0].text.strip()
                
                # JSON 추출
                if "```json" in content:
                    start = content.find("```json") + 7
                    end = content.find("```", start)
                    if end != -1:
                        content = content[start:end].strip()
                elif "```" in content:
                    start = content.find("```") + 3
                    end = content.find("```", start)
                    if end != -1:
                        content = content[start:end].strip()
                
                # JSON 시작/끝 찾기 (중괄호 기준)
                brace_start = content.find("{")
                brace_end = content.rfind("}")
                if brace_start != -1 and brace_end != -1:
                    content = content[brace_start:brace_end+1]
                
                # JSON 파싱 시도
                enhanced = json.loads(content)
                
                # 필수 필드 검증
                required_fields = ["simple_summary", "what_is_it", "attack_scenario"]
                if all(field in enhanced for field in required_fields):
                    vulnerability["enhanced_description"] = enhanced
                    vulnerability["enhancement_status"] = "success"
                    return vulnerability
                else:
                    raise ValueError("필수 필드 누락")
                
            except json.JSONDecodeError as e:
                if attempt < max_retries - 1:
                    print(f"[!] {cve_id}: JSON 파싱 실패 (시도 {attempt+1}/{max_retries}), 재시도 중...")
                    continue
                else:
                    print(f"[!] {cve_id}: JSON 파싱 최종 실패 - {e}")
                    print(f"    응답 내용 (처음 200자): {content[:200]}")
            
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"[!] {cve_id}: 오류 발생 (시도 {attempt+1}/{max_retries}) - {e}")
                    continue
                else:
                    print(f"[!] {cve_id}: 최종 실패 - {e}")
        
        # 모든 시도 실패 시 fallback
        vulnerability["enhanced_description"] = self._fallback_enhancement(
            cve_id, package, severity, cvss_score
        )
        vulnerability["enhancement_status"] = "fallback"
        return vulnerability
    
    def enhance_all_vulnerabilities(
        self, 
        trivy_data: Dict[str, Any],
        progress_callback=None
    ) -> Dict[str, Any]:
        """
        모든 취약점 설명을 병렬로 향상
        
        Args:
            trivy_data: Trivy 스캔 결과
            progress_callback: 진행률 콜백 함수
            
        Returns:
            향상된 Trivy 데이터
        """
        vulnerabilities = trivy_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            print("[!] 취약점이 없습니다.")
            return trivy_data
        
        print(f"[+] {len(vulnerabilities)}개 취약점 설명 향상 중...")
        
        enhanced_vulns = []
        
        # 병렬 처리
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 모든 취약점에 대해 작업 제출
            future_to_vuln = {
                executor.submit(self.enhance_vulnerability, vuln): vuln
                for vuln in vulnerabilities
            }
            
            # 결과 수집
            completed = 0
            for future in as_completed(future_to_vuln):
                enhanced_vuln = future.result()
                enhanced_vulns.append(enhanced_vuln)
                
                completed += 1
                if progress_callback:
                    progress_callback(completed, len(vulnerabilities))
                else:
                    print(f"  [{completed}/{len(vulnerabilities)}] {enhanced_vuln.get('id', 'Unknown')} 완료")
        
        # 원본 순서 유지 (id 기준)
        id_to_enhanced = {v.get("id"): v for v in enhanced_vulns}
        trivy_data["vulnerabilities"] = [
            id_to_enhanced.get(v.get("id"), v)
            for v in vulnerabilities
        ]
        
        # 통계 추가
        success_count = sum(
            1 for v in trivy_data["vulnerabilities"]
            if v.get("enhancement_status") == "success"
        )
        
        trivy_data.setdefault("enhancement_metadata", {})
        trivy_data["enhancement_metadata"]["total_enhanced"] = len(vulnerabilities)
        trivy_data["enhancement_metadata"]["success_count"] = success_count
        trivy_data["enhancement_metadata"]["fallback_count"] = len(vulnerabilities) - success_count
        
        print(f"\n[✓] 완료: {success_count}/{len(vulnerabilities)} 성공")
        
        return trivy_data
    
    def _extract_cvss_score(self, cvss_data: Dict[str, Any]) -> float:
        """CVSS 점수 추출 (NVD 우선)"""
        if "nvd" in cvss_data and "V3Score" in cvss_data["nvd"]:
            return cvss_data["nvd"]["V3Score"]
        if "ghsa" in cvss_data and "V3Score" in cvss_data["ghsa"]:
            return cvss_data["ghsa"]["V3Score"]
        if "redhat" in cvss_data and "V3Score" in cvss_data["redhat"]:
            return cvss_data["redhat"]["V3Score"]
        return 0.0
    
    def _fallback_enhancement(
        self, 
        cve_id: str, 
        package: str, 
        severity: str,
        cvss_score: float
    ) -> Dict[str, Any]:
        """LLM 실패 시 기본 설명 제공"""
        return {
            "simple_summary": f"{package}의 {severity} 심각도 취약점",
            "what_is_it": f"{cve_id}는 {package} 패키지에서 발견된 보안 취약점입니다. 자동 설명 생성에 실패했습니다.",
            "attack_scenario": "자동 분석을 사용할 수 없습니다. 원본 CVE 설명을 참조하세요.",
            "real_world_impact": f"CVSS 점수 {cvss_score}는 {'높은' if cvss_score >= 7 else '중간'} 위험도를 나타냅니다.",
            "how_to_check": f"{package} 패키지의 버전을 확인하세요.",
            "immediate_action": "패키지를 최신 버전으로 업데이트하세요.",
            "why_critical": f"{severity} 등급은 {'즉시 조치가 필요함' if severity in ['CRITICAL', 'HIGH'] else '계획된 업데이트 필요'}을 의미합니다.",
            "related_cves": [],
            "enhancement_error": "LLM 분석 실패"
        }
    
    def generate_readable_report(
        self, 
        trivy_data: Dict[str, Any],
        output_file: str = None
    ) -> str:
        """
        읽기 쉬운 취약점 리포트 생성
        
        Args:
            trivy_data: 향상된 Trivy 데이터
            output_file: 저장할 파일 경로
            
        Returns:
            포맷된 리포트 문자열
        """
        lines = []
        
        # 헤더
        lines.append("=" * 100)
        lines.append("🔍 취약점 상세 분석 리포트")
        lines.append("=" * 100)
        lines.append("")
        
        vulnerabilities = trivy_data.get("vulnerabilities", [])
        
        # 심각도별 분류
        by_severity = {}
        for vuln in vulnerabilities:
            sev = vuln.get("severity", "UNKNOWN")
            by_severity.setdefault(sev, []).append(vuln)
        
        # 심각도 순서
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        
        vuln_number = 1
        for severity in severity_order:
            vulns = by_severity.get(severity, [])
            if not vulns:
                continue
            
            lines.append(f"\n{'#' * 100}")
            lines.append(f"## {severity} 심각도 취약점 ({len(vulns)}개)")
            lines.append(f"{'#' * 100}\n")
            
            for vuln in vulns:
                cve_id = vuln.get("id", "Unknown")
                package = vuln.get("package_name", "Unknown")
                version = vuln.get("installed_version", "Unknown")
                fixed = vuln.get("fixed_version", "정보 없음")
                
                enhanced = vuln.get("enhanced_description", {})
                
                lines.append(f"\n{'─' * 100}")
                lines.append(f"### [{vuln_number}] {cve_id}")
                lines.append(f"{'─' * 100}")
                lines.append(f"**패키지**: {package} (설치 버전: {version})")
                lines.append(f"**수정 버전**: {fixed}")
                lines.append("")
                
                # 한 줄 요약
                summary = enhanced.get("simple_summary", "설명 없음")
                lines.append(f"📌 **한 줄 요약**")
                lines.append(f"   {summary}")
                lines.append("")
                
                # 상세 설명
                what = enhanced.get("what_is_it", "")
                if what:
                    lines.append(f"📖 **상세 설명**")
                    lines.append(f"   {what}")
                    lines.append("")
                
                # 공격 시나리오
                attack = enhanced.get("attack_scenario", "")
                if attack:
                    lines.append(f"⚔️ **공격 시나리오**")
                    lines.append(f"   {attack}")
                    lines.append("")
                
                # 실제 영향
                impact = enhanced.get("real_world_impact", "")
                if impact:
                    lines.append(f"💥 **실제 피해**")
                    lines.append(f"   {impact}")
                    lines.append("")
                
                # 확인 방법
                check = enhanced.get("how_to_check", "")
                if check:
                    lines.append(f"🔎 **영향 확인 방법**")
                    lines.append(f"   {check}")
                    lines.append("")
                
                # 즉시 조치
                action = enhanced.get("immediate_action", "")
                if action:
                    lines.append(f"✅ **즉시 조치**")
                    lines.append(f"   {action}")
                    lines.append("")
                
                # 심각도 이유
                why = enhanced.get("why_critical", "")
                if why:
                    lines.append(f"⚠️ **{severity} 심각도인 이유**")
                    lines.append(f"   {why}")
                    lines.append("")
                
                vuln_number += 1
        
        # 통계
        metadata = trivy_data.get("enhancement_metadata", {})
        if metadata:
            lines.append(f"\n{'=' * 100}")
            lines.append("## 📊 향상 통계")
            lines.append(f"{'=' * 100}")
            lines.append(f"총 분석: {metadata.get('total_enhanced', 0)}개")
            lines.append(f"성공: {metadata.get('success_count', 0)}개")
            lines.append(f"폴백: {metadata.get('fallback_count', 0)}개")
        
        report = "\n".join(lines)
        
        # 파일 저장
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[+] 리포트 저장: {output_file}")
        
        return report