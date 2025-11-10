"""
보안 분석 모듈 - AST 분석 결과를 LLM으로 해석
"""

import os
import json
from typing import List, Dict, Any
from anthropic import Anthropic
from dotenv import load_dotenv

class SecurityAnalyzer:
    """AST 분석 결과를 보안 관점에서 해석하는 클래스"""
    
    def __init__(self, api_key: str = None):
        """
        초기화
        
        Args:
            api_key: Anthropic API 키 (없으면 환경변수에서 읽음)
        """
        load_dotenv()
        
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment")
        
        self.client = Anthropic(api_key=self.api_key)
    
    def analyze_security_posture(
        self, 
        external_apis: List[str], 
        internal_apis: List[str],
        unused_apis: List[str],
        vulnerability_data: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        AST 분석 결과를 보안 관점에서 종합 평가
        
        Args:
            external_apis: 외부 노출된 API 목록
            internal_apis: 내부 전용 API 목록
            unused_apis: 사용되지 않는 API 목록
            vulnerability_data: Trivy 취약점 데이터 (선택)
            
        Returns:
            보안 분석 결과 딕셔너리
        """
        # 취약점 데이터 요약
        vuln_summary = self._summarize_vulnerabilities(vulnerability_data) if vulnerability_data else "취약점 데이터 없음"
        
        # 프롬프트 생성
        prompt = f"""당신은 사이버 보안 전문가입니다. 다음 Python 애플리케이션의 코드 분석 결과를 평가해주세요.

## 📊 분석 데이터

### 외부 노출 API (공격 표면)
총 {len(external_apis)}개의 API가 외부에 노출되어 있습니다:
{self._format_api_list(external_apis, limit=20)}

### 내부 전용 API
총 {len(internal_apis)}개의 내부 API:
{self._format_api_list(internal_apis, limit=15)}

### 미사용 API (데드 코드)
총 {len(unused_apis)}개의 미사용 API:
{self._format_api_list(unused_apis, limit=10)}

### 발견된 취약점
{vuln_summary}

## 📋 분석 요청

다음 형식의 JSON으로 보안 분석을 제공해주세요:

{{
  "critical_findings": [
    {{
      "title": "위험 요소 제목",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "description": "상세 설명",
      "affected_apis": ["api1", "api2"],
      "attack_scenario": "구체적인 공격 시나리오",
      "immediate_action": "즉시 취해야 할 조치"
    }}
  ],
  "attack_surface_analysis": {{
    "total_external_apis": 숫자,
    "vulnerable_external_apis": ["취약한 외부 API"],
    "unnecessary_exposure": ["불필요하게 노출된 API"],
    "recommendations": ["권장사항"]
  }},
  "code_quality": {{
    "dead_code_impact": "영향도 설명",
    "cleanup_priority": ["우선순위별 정리 대상"],
    "maintenance_recommendations": ["유지보수 권장사항"]
  }},
  "security_architecture": {{
    "current_issues": ["현재 아키텍처 문제점"],
    "improvement_suggestions": ["개선 제안"],
    "defense_in_depth": ["다층 방어 전략"]
  }},
  "action_items": [
    {{
      "priority": 1-5,
      "task": "작업 내용",
      "estimated_time": "예상 소요 시간",
      "risk_if_not_done": "미실행 시 위험도"
    }}
  ],
  "overall_risk_score": 0-100,
  "summary": "전체 요약 (3-5 문장)"
}}

**중요**: 반드시 유효한 JSON만 반환하고, 코드 블록(```)이나 다른 텍스트를 포함하지 마세요."""

        try:
            # Claude API 호출
            response = self.client.messages.create(
                model="claude-sonnet-4-5-20250929",
                max_tokens=8000,
                temperature=0.3,
                system="당신은 애플리케이션 보안 아키텍처 전문가입니다. 항상 유효한 JSON 형식으로만 응답하세요.",
                messages=[{"role": "user", "content": prompt}]
            )
            
            # 응답 파싱
            content = response.content[0].text.strip()
            
            # JSON 코드 블록 제거
            if "```json" in content:
                start = content.find("```json") + 7
                end = content.find("```", start)
                content = content[start:end].strip()
            elif "```" in content:
                start = content.find("```") + 3
                end = content.find("```", start)
                content = content[start:end].strip()
            
            # JSON 파싱
            analysis = json.loads(content)
            
            # 메타데이터 추가
            analysis["metadata"] = {
                "total_external_apis": len(external_apis),
                "total_internal_apis": len(internal_apis),
                "total_unused_apis": len(unused_apis),
                "analysis_timestamp": self._get_timestamp()
            }
            
            return analysis
            
        except json.JSONDecodeError as e:
            print(f"[!] JSON 파싱 오류: {e}")
            print(f"[!] 원본 응답: {content[:500]}...")
            return self._fallback_analysis(external_apis, internal_apis, unused_apis)
        
        except Exception as e:
            print(f"[!] LLM 분석 오류: {e}")
            return self._fallback_analysis(external_apis, internal_apis, unused_apis)
    
    def _format_api_list(self, apis: List[str], limit: int = 10) -> str:
        """API 목록을 보기 좋게 포맷"""
        if not apis:
            return "없음"
        
        displayed = apis[:limit]
        formatted = "\n".join([f"  - {api}" for api in displayed])
        
        if len(apis) > limit:
            formatted += f"\n  ... 외 {len(apis) - limit}개"
        
        return formatted
    
    def _summarize_vulnerabilities(self, vuln_data: Dict[str, Any]) -> str:
        """취약점 데이터를 요약"""
        if not vuln_data or "vulnerabilities" not in vuln_data:
            return "취약점 데이터 없음"
        
        vulns = vuln_data["vulnerabilities"]
        summary_lines = []
        
        # 심각도별 통계
        severity_counts = {}
        for vuln in vulns:
            sev = vuln.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        summary_lines.append(f"총 {len(vulns)}개 취약점:")
        for sev, count in sorted(severity_counts.items()):
            summary_lines.append(f"  - {sev}: {count}개")
        
        # 주요 CVE 나열 (최대 5개)
        if vulns:
            summary_lines.append("\n주요 CVE:")
            for vuln in vulns[:5]:
                cve_id = vuln.get("id", "Unknown")
                pkg = vuln.get("package_name", "Unknown")
                sev = vuln.get("severity", "Unknown")
                summary_lines.append(f"  - {cve_id} ({pkg}, {sev})")
        
        return "\n".join(summary_lines)
    
    def _fallback_analysis(
        self, 
        external_apis: List[str], 
        internal_apis: List[str],
        unused_apis: List[str]
    ) -> Dict[str, Any]:
        """LLM 실패 시 기본 분석 제공"""
        return {
            "critical_findings": [
                {
                    "title": "자동 분석 실패",
                    "severity": "MEDIUM",
                    "description": "LLM 분석이 실패하여 기본 분석을 제공합니다.",
                    "affected_apis": [],
                    "attack_scenario": "N/A",
                    "immediate_action": "LLM API 키 및 연결 상태를 확인하세요."
                }
            ],
            "attack_surface_analysis": {
                "total_external_apis": len(external_apis),
                "vulnerable_external_apis": [],
                "unnecessary_exposure": [],
                "recommendations": [
                    "외부 노출 API 최소화",
                    "입력 검증 강화",
                    "인증/인가 메커니즘 확인"
                ]
            },
            "code_quality": {
                "dead_code_impact": f"{len(unused_apis)}개의 미사용 API가 발견되었습니다.",
                "cleanup_priority": unused_apis[:5],
                "maintenance_recommendations": [
                    "미사용 코드 제거",
                    "코드 리뷰 프로세스 강화"
                ]
            },
            "security_architecture": {
                "current_issues": ["자동 분석 불가"],
                "improvement_suggestions": ["수동 보안 검토 권장"],
                "defense_in_depth": ["다층 방어 전략 구현"]
            },
            "action_items": [
                {
                    "priority": 1,
                    "task": "LLM 보안 분석 기능 복구",
                    "estimated_time": "30분",
                    "risk_if_not_done": "상세 보안 분석 불가"
                }
            ],
            "overall_risk_score": 50,
            "summary": f"기본 분석 결과: 외부 API {len(external_apis)}개, 내부 API {len(internal_apis)}개, 미사용 API {len(unused_apis)}개 발견. 상세 분석을 위해 LLM 연결을 복구하세요.",
            "metadata": {
                "total_external_apis": len(external_apis),
                "total_internal_apis": len(internal_apis),
                "total_unused_apis": len(unused_apis),
                "analysis_timestamp": self._get_timestamp(),
                "fallback_mode": True
            }
        }
    
    def _get_timestamp(self) -> str:
        """현재 타임스탬프 반환"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def generate_report(self, analysis: Dict[str, Any], output_file: str = None) -> str:
        """
        분석 결과를 읽기 쉬운 리포트로 변환
        
        Args:
            analysis: analyze_security_posture의 결과
            output_file: 저장할 파일 경로 (선택)
            
        Returns:
            포맷된 리포트 문자열
        """
        lines = []
        
        # 헤더
        lines.append("=" * 80)
        lines.append("🔐 보안 분석 리포트")
        lines.append("=" * 80)
        lines.append("")
        
        # 전체 요약
        lines.append("## 📋 전체 요약")
        lines.append(analysis.get("summary", "요약 없음"))
        lines.append(f"\n**전체 위험 점수**: {analysis.get('overall_risk_score', 'N/A')}/100")
        lines.append("")
        
        # 긴급 조치 사항
        critical_findings = analysis.get("critical_findings", [])
        if critical_findings:
            lines.append("## 🚨 긴급 조치 필요")
            lines.append("-" * 80)
            for i, finding in enumerate(critical_findings, 1):
                lines.append(f"\n### {i}. {finding.get('title', 'Unknown')} [{finding.get('severity', 'UNKNOWN')}]")
                lines.append(f"**설명**: {finding.get('description', 'N/A')}")
                lines.append(f"**공격 시나리오**: {finding.get('attack_scenario', 'N/A')}")
                lines.append(f"**즉시 조치**: {finding.get('immediate_action', 'N/A')}")
                
                affected = finding.get('affected_apis', [])
                if affected:
                    lines.append(f"**영향받는 API**: {', '.join(affected[:5])}")
            lines.append("")
        
        # 공격 표면 분석
        attack_surface = analysis.get("attack_surface_analysis", {})
        if attack_surface:
            lines.append("## 🎯 공격 표면 분석")
            lines.append("-" * 80)
            lines.append(f"총 외부 노출 API: {attack_surface.get('total_external_apis', 0)}개")
            
            vuln_apis = attack_surface.get('vulnerable_external_apis', [])
            if vuln_apis:
                lines.append(f"\n**취약한 외부 API** ({len(vuln_apis)}개):")
                for api in vuln_apis[:10]:
                    lines.append(f"  - {api}")
            
            unnecessary = attack_surface.get('unnecessary_exposure', [])
            if unnecessary:
                lines.append(f"\n**불필요한 노출** ({len(unnecessary)}개):")
                for api in unnecessary[:10]:
                    lines.append(f"  - {api}")
            
            recommendations = attack_surface.get('recommendations', [])
            if recommendations:
                lines.append("\n**권장사항**:")
                for rec in recommendations:
                    lines.append(f"  - {rec}")
            lines.append("")
        
        # 코드 품질
        code_quality = analysis.get("code_quality", {})
        if code_quality:
            lines.append("## 🧹 코드 품질")
            lines.append("-" * 80)
            lines.append(f"**영향도**: {code_quality.get('dead_code_impact', 'N/A')}")
            
            cleanup = code_quality.get('cleanup_priority', [])
            if cleanup:
                lines.append(f"\n**정리 우선순위** (상위 {len(cleanup)}개):")
                for api in cleanup:
                    lines.append(f"  - {api}")
            lines.append("")
        
        # 액션 아이템
        action_items = analysis.get("action_items", [])
        if action_items:
            lines.append("## ✅ 액션 아이템")
            lines.append("-" * 80)
            for item in sorted(action_items, key=lambda x: x.get('priority', 99)):
                priority = item.get('priority', 'N/A')
                task = item.get('task', 'N/A')
                time = item.get('estimated_time', 'N/A')
                risk = item.get('risk_if_not_done', 'N/A')
                
                lines.append(f"\n**[우선순위 {priority}]** {task}")
                lines.append(f"  - 예상 시간: {time}")
                lines.append(f"  - 미실행 시 위험: {risk}")
            lines.append("")
        
        # 메타데이터
        metadata = analysis.get("metadata", {})
        if metadata:
            lines.append("## ℹ️ 분석 정보")
            lines.append("-" * 80)
            lines.append(f"분석 시각: {metadata.get('analysis_timestamp', 'N/A')}")
            lines.append(f"외부 API: {metadata.get('total_external_apis', 0)}개")
            lines.append(f"내부 API: {metadata.get('total_internal_apis', 0)}개")
            lines.append(f"미사용 API: {metadata.get('total_unused_apis', 0)}개")
            if metadata.get('fallback_mode'):
                lines.append("\n⚠️ 폴백 모드로 분석됨 (LLM 연결 실패)")
        
        lines.append("\n" + "=" * 80)
        
        # 리포트 문자열 생성
        report = "\n".join(lines)
        
        # 파일 저장
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[+] 보안 리포트 저장: {output_file}")
        
        return report