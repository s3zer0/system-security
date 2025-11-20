"""Perplexity API를 사용한 CVE 실제 사례 검색 모듈"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from common.models import RealWorldCase
import logging

try:
    from perplexity import Perplexity
except ImportError as exc:
    raise ImportError("perplexity 패키지가 필요합니다. 'pip install perplexity'를 실행하세요.") from exc

logger = logging.getLogger(__name__)



class PerplexitySearcher:
    """Perplexity API를 사용한 CVE 실제 사례 검색"""
    
    def __init__(
        self,
        api_key: str,
        model: str = "sonar-pro",
        raw_response_dir: Optional[Union[str, Path]] = None,
    ):
        """
        Perplexity 검색기 초기화
        
        Args:
            api_key: Perplexity API 키
            model: 사용할 Perplexity 모델
            raw_response_dir: Perplexity raw 응답 저장 경로 (디버깅용)
        """
        self.client = self._create_client(api_key)
        self.model = model
        self.rate_limit_delay = 1.0  # API 호출 사이 대기 시간 (초)
        self.raw_response_dir = self._resolve_raw_dir(raw_response_dir)

    def _create_client(self, api_key: str) -> Perplexity:
        """Perplexity 클라이언트를 생성합니다."""
        try:
            return Perplexity(api_key=api_key)
        except TypeError:
            os.environ.setdefault("PERPLEXITY_API_KEY", api_key)
            return Perplexity()

    def _resolve_raw_dir(self, raw_response_dir: Optional[Union[str, Path]]) -> Optional[Path]:
        """raw response 저장 경로를 결정합니다."""
        candidate: Optional[Union[str, Path]] = raw_response_dir
        if candidate is None:
            env_dir = os.getenv("PERPLEXITY_RAW_DIR")
            if env_dir is not None:
                candidate = env_dir
            else:
                candidate = Path("DB") / "perplexity_raw_responses"
        if isinstance(candidate, str):
            candidate = candidate.strip()
            if not candidate:
                return None
            return Path(candidate)
        resolved = Path(candidate)
        return resolved

    def set_raw_response_dir(self, raw_response_dir: Optional[Union[str, Path]]) -> None:
        """동적으로 raw response 저장 경로를 변경합니다."""
        self.raw_response_dir = self._resolve_raw_dir(raw_response_dir)

    def _serialise_response(self, response: Any) -> Any:
        """Perplexity 응답 객체를 JSON 직렬화 가능한 형태로 변환합니다."""
        for attr in ("model_dump", "dict", "to_dict"):
            if hasattr(response, attr):
                try:
                    return getattr(response, attr)()
                except Exception:
                    logger.debug('Perplexity 응답 직렬화 실패(%s) - %s', attr, response)
        for attr in ("model_dump_json", "json"):
            if hasattr(response, attr):
                try:
                    return json.loads(getattr(response, attr)())
                except Exception:
                    logger.debug('Perplexity 응답 JSON 변환 실패(%s)', attr)
        if isinstance(response, dict):
            return response
        return {"repr": repr(response)}

    def _extract_structured_payload(self, response: Any) -> Optional[Any]:
        """JSON 스키마 응답에서 구조화된 페이로드를 추출합니다."""
        def _get(obj: Any, key: str) -> Any:
            if isinstance(obj, dict):
                return obj.get(key)
            if hasattr(obj, key):
                return getattr(obj, key)
            return None

        choices = _get(response, "choices")
        if not choices:
            return None
        first_choice = choices[0]
        message = _get(first_choice, "message")
        if message is None:
            return None

        parsed = _get(message, "parsed")
        if parsed is not None:
            return parsed

        content = _get(message, "content")
        if isinstance(content, list):
            for part in content:
                part_parsed = _get(part, "parsed")
                if part_parsed is not None:
                    return part_parsed
                part_content = _get(part, "content")
                if part_content is not None:
                    return part_content
        elif isinstance(content, (dict, list)):
            return content

        return None

    def _normalise_structured_cases(self, payload: Any) -> Optional[List[Dict[str, str]]]:
        """Perplexity가 반환한 구조화된 페이로드를 표준 케이스 리스트로 변환합니다."""
        if payload is None:
            return None
        if isinstance(payload, list):
            cases = [self._coerce_case(item) for item in payload]
            return [case for case in cases if case]
        if isinstance(payload, dict):
            candidate = None
            for key in ("cases", "results", "data", "items", "startups", "examples"):
                value = payload.get(key)
                if isinstance(value, list):
                    candidate = value
                    break
            if candidate is None:
                candidate = [payload]
            cases = [self._coerce_case(item) for item in candidate]
            return [case for case in cases if case]
        if isinstance(payload, str):
            try:
                return self._normalise_structured_cases(json.loads(payload))
            except Exception:
                return None
        return None

    def _coerce_case(self, item: Any) -> Optional[Dict[str, str]]:
        """단일 사례 항목을 표준 형태로 강제 변환합니다."""
        if isinstance(item, dict):
            title = str(item.get("title") or item.get("name") or "").strip()
            description = str(item.get("description") or item.get("summary") or "").strip()
            source_url = str(item.get("source_url") or item.get("url") or "").strip()
            date = str(item.get("date") or item.get("reported") or item.get("published") or "").strip()
            if not (title or description or source_url):
                return None
            return {
                "title": title[:200],
                "description": description[:500],
                "source_url": source_url[:300],
                "date": date[:50],
            }
        if isinstance(item, str):
            try:
                parsed = json.loads(item)
            except Exception:
                return None
            return self._coerce_case(parsed)
        return None

    def _persist_raw_response(
        self,
        cve_id: str,
        response: Any,
        structured_payload: Optional[Any] = None,
        normalised_cases: Optional[List[Dict[str, str]]] = None,
        error: Optional[str] = None,
    ) -> None:
        """디버깅을 위해 Perplexity raw 응답을 파일로 저장합니다."""
        directory = self.raw_response_dir
        if directory is None:
            return
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.debug('Perplexity raw 응답 디렉터리 생성 실패: %s', exc)
            return
        safe_id = ''.join(ch if ch.isalnum() or ch in ('-', '_') else '_' for ch in (cve_id or 'UNKNOWN'))
        filename = f"{safe_id}.json"
        file_path = directory / filename
        try:
            payload = {
                'timestamp': datetime.now(timezone.utc).isoformat(timespec='seconds'),
                'cve_id': cve_id,
                'raw_response': self._serialise_response(response),
            }
            if structured_payload is not None:
                payload['structured_payload'] = self._serialise_response(structured_payload)
            if normalised_cases is not None:
                payload['normalised_cases'] = normalised_cases
            if error:
                payload['error'] = error
            with file_path.open('w', encoding='utf-8') as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.debug('Perplexity raw 응답 저장 실패(%s): %s', file_path, exc)
            return
        logger.debug('CVE %s: Perplexity raw 응답 저장 -> %s', cve_id, file_path)
    
    def search_cve_cases(self, 
                        cve_id: str, 
                        package_name: str,
                        description: str,
                        max_retries: int = 3) -> List[Dict[str, str]]:
        """
        특정 CVE에 대한 실제 공격 사례 및 보안 권고사항 검색
        
        Args:
            cve_id: CVE 식별자
            package_name: 패키지 이름
            description: CVE 설명
            max_retries: 최대 재시도 횟수
            
        Returns:
            실제 사례 딕셔너리 리스트
        """
        query = self._build_search_query(cve_id, package_name, description)
        
        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are a cybersecurity researcher specializing in vulnerability analysis. "
                                "Search for real-world exploitation cases, security advisories, and documented "
                                "incidents related to the given CVE. Provide structured information with sources."
                            ),
                        },
                        {
                            "role": "user",
                            "content": query,
                        },
                    ],
                    temperature=0.2,
                    max_tokens=2000,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {
                            "schema": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "description": {"type": "string"},
                                        "source_url": {"type": "string"},
                                        "date": {"type": "string"},
                                    },
                                    "required": ["title", "description", "source_url", "date"],
                                },
                            }
                        },
                    },
                )

                structured_payload = self._extract_structured_payload(response)
                cases: Optional[List[Dict[str, str]]] = None
                error_notes: List[str] = []

                if structured_payload is not None:
                    cases = self._normalise_structured_cases(structured_payload)
                    if not cases:
                        error_notes.append("Structured payload present but empty")

                if not cases:
                    choice = response.choices[0]
                    message = getattr(choice, "message", None)
                    message_content = getattr(message, "content", None) if message is not None else None

                    if isinstance(message_content, list):
                        aggregated_text: List[str] = []
                        for part in message_content:
                            if isinstance(part, dict):
                                text_piece = part.get("text")
                                if isinstance(text_piece, str):
                                    aggregated_text.append(text_piece)
                                for key in ("content", "value"):
                                    extra_text = part.get(key)
                                    if isinstance(extra_text, str):
                                        aggregated_text.append(extra_text)
                                parsed_part = part.get("parsed")
                                if parsed_part is not None and not cases:
                                    possible_cases = self._normalise_structured_cases(parsed_part)
                                    if possible_cases:
                                        cases = possible_cases
                        if not cases:
                            content = "".join(aggregated_text)
                            cases = self._parse_response(content, cve_id)
                    elif isinstance(message_content, (dict, list)):
                        cases = self._normalise_structured_cases(message_content)
                        if not cases:
                            content = json.dumps(message_content, ensure_ascii=False)
                            cases = self._parse_response(content, cve_id)
                    else:
                        content = str(message_content or "")
                        cases = self._parse_response(content, cve_id)

                if cases is None:
                    cases = []

                self._persist_raw_response(
                    cve_id,
                    response,
                    structured_payload=structured_payload,
                    normalised_cases=cases,
                    error="; ".join(error_notes) or None,
                )

                # 호출 빈도를 제한합니다.
                time.sleep(self.rate_limit_delay)
                
                return cases
                
            except Exception as e:
                logger.warning(f"CVE {cve_id} 검색 시도 {attempt + 1}/{max_retries} 실패: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # 지수 백오프 적용
                else:
                    logger.error(f"CVE {cve_id} 검색 최종 실패")
                    self._persist_raw_response(
                        cve_id,
                        {"error": str(e)},
                        structured_payload=None,
                        normalised_cases=None,
                        error=str(e),
                    )
                    return []
        
        return []
    
    def _build_search_query(self, cve_id: str, package_name: str, description: str) -> str:
        """
        검색 쿼리 생성
        
        Args:
            cve_id: CVE 식별자
            package_name: 패키지 이름
            description: CVE 설명
            
        Returns:
            검색 쿼리 문자열
        """
        # 설명이 너무 길면 잘라냄
        short_desc = description[:200] + "..." if len(description) > 200 else description
        
        query = f"""Find real-world exploitation cases and security incidents for {cve_id} in {package_name}.

CVE Description: {short_desc}

Please search for and provide:
1. Documented real-world attacks or exploitation attempts
2. Security advisories from major organizations (CISA, NIST, vendors)
3. Reported incidents in production environments
4. Security research papers or blog posts analyzing this vulnerability
5. Proof-of-concept exploits or demonstrations

For each case found, provide:
- Title: Brief descriptive title
- Description: What happened, who was affected, impact
- Source URL: Link to the original source
- Date: When the incident occurred or was reported (if available)

Format your response as a JSON array of objects with keys: title, description, source_url, date
If no real cases found, return an empty array: []

Important: Only include verified, documented cases with credible sources. Avoid speculation."""
        
        return query
    
    def _parse_response(self, content: str, cve_id: str) -> List[Dict[str, str]]:
        """
        Perplexity 응답을 파싱하여 구조화된 데이터 추출
        
        Args:
            content: Perplexity 응답 텍스트
            cve_id: CVE 식별자 (로깅용)
            
        Returns:
            파싱된 사례 리스트
        """
        try:
            # JSON 코드 블록 추출 시도
            if "```json" in content:
                json_start = content.find("```json") + 7
                json_end = content.find("```", json_start)
                json_str = content[json_start:json_end].strip()
            elif "```" in content:
                json_start = content.find("```") + 3
                json_end = content.find("```", json_start)
                json_str = content[json_start:json_end].strip()
            else:
                # JSON 배열 추출 시도
                json_start = content.find("[")
                json_end = content.rfind("]") + 1
                if json_start != -1 and json_end > json_start:
                    json_str = content[json_start:json_end]
                else:
                    logger.warning(f"CVE {cve_id}: JSON 형식을 찾을 수 없음, 텍스트 파싱 시도")
                    return self._fallback_parse(content)
            
            logger.debug(
                "CVE %s: raw JSON fragment (trimmed): %s",
                cve_id,
                json_str[:200].replace("\n", " "),
            )

            # JSON 파싱
            try:
                raw_cases = json.loads(json_str)
            except json.JSONDecodeError as json_error:
                logger.debug(
                    "CVE %s: initial JSON decode failed (%s) - payload snippet: %s",
                    cve_id,
                    json_error,
                    json_str[:200].replace("\n", " "),
                )
                raw_cases = self._parse_multiple_json_segments(json_str, cve_id)
                if raw_cases is None:
                    raise json_error
                logger.info(f"CVE {cve_id}: 다중 JSON 세그먼트를 병합하여 파싱했습니다 ({len(raw_cases)}항목)")
            else:
                # dict 형태로 감싸진 결과 처리
                if isinstance(raw_cases, dict):
                    candidate_list = None
                    for key in ("cases", "results", "data", "items"):
                        value = raw_cases.get(key)
                        if isinstance(value, list):
                            candidate_list = value
                            break
                    raw_cases = candidate_list if candidate_list is not None else [raw_cases]

            if not isinstance(raw_cases, list):
                raw_cases = [raw_cases]
            cases = raw_cases
            logger.debug("CVE %s: 정상화된 사례 수 %d", cve_id, len(cases))

            # 유효성 검증 및 정제
            validated_cases = []
            for case in cases:
                if isinstance(case, dict) and all(k in case for k in ["title", "description", "source_url", "date"]):
                    # 데이터 정제
                    validated_case = {
                        "title": str(case["title"])[:200],  # 제목 길이 제한
                        "description": str(case["description"])[:500],  # 설명 길이 제한
                        "source_url": str(case["source_url"])[:300],
                        "date": str(case["date"])[:50]
                    }
                    validated_cases.append(validated_case)
            
            logger.info(f"CVE {cve_id}: {len(validated_cases)}개 실제 사례 발견")
            return validated_cases
            
        except json.JSONDecodeError as e:
            logger.warning(f"CVE {cve_id}: JSON 파싱 실패 - {e}, 폴백 파싱 시도")
            return self._fallback_parse(content)
        except Exception as e:
            logger.error(f"CVE {cve_id}: 응답 파싱 중 오류 - {e}")
            return []
    
    def _parse_multiple_json_segments(self, json_str: str, cve_id: Optional[str] = None) -> Optional[List[Any]]:
        """
        하나의 문자열에 이어 붙은 여러 JSON 세그먼트를 순차적으로 파싱합니다.
        제대로 파싱되지 못하면 None을 반환합니다.
        """
        decoder = json.JSONDecoder()
        idx = 0
        length = len(json_str)
        segments: List[Any] = []
        trailing_skipped = False

        while idx < length:
            # 공백 건너뛰기
            while idx < length and json_str[idx].isspace():
                idx += 1
            if idx >= length:
                break

            if json_str[idx] not in "[{":
                if segments:
                    trailing_skipped = True
                    logger.debug(
                        "CVE %s: ignoring trailing content after JSON payload: %s",
                        cve_id or "UNKNOWN",
                        json_str[idx:idx + 80].replace("\n", " "),
                    )
                    break
                return None

            try:
                obj, end = decoder.raw_decode(json_str, idx)
            except json.JSONDecodeError as err:
                if segments:
                    trailing_skipped = True
                    logger.debug(
                        "CVE %s: stopping JSON segment parsing at index %d due to %s",
                        cve_id or "UNKNOWN",
                        idx,
                        err,
                    )
                    break
                return None

            segments.append(obj)
            idx = end

        if not segments:
            return None

        combined: List[Any] = []
        for segment in segments:
            if isinstance(segment, list):
                combined.extend(segment)
            else:
                combined.append(segment)

        if trailing_skipped:
            logger.debug(
                "CVE %s: merged %d JSON segments with trailing text present",
                cve_id or "UNKNOWN",
                len(combined),
            )

        return combined

    def _fallback_parse(self, content: str) -> List[Dict[str, str]]:
        """
        JSON 파싱 실패 시 폴백 텍스트 파싱
        
        Args:
            content: 응답 텍스트
            
        Returns:
            추출된 사례 리스트 (최선의 노력)
        """
        cases = []
        
        # 간단한 휴리스틱 파싱
        # "1.", "2." 등으로 구분된 항목 찾기
        lines = content.split('\n')
        current_case = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 새로운 케이스 시작 감지
            if line[0].isdigit() and '.' in line[:3]:
                if current_case:
                    cases.append(current_case)
                current_case = {"title": line, "description": "", "source_url": "", "date": "Unknown"}
            
            # 필드 추출 시도
            elif "title:" in line.lower():
                current_case["title"] = line.split(":", 1)[1].strip()
            elif "description:" in line.lower():
                current_case["description"] = line.split(":", 1)[1].strip()
            elif "source" in line.lower() or "url" in line.lower():
                # URL 추출
                parts = line.split()
                for part in parts:
                    if part.startswith("http"):
                        current_case["source_url"] = part
                        break
            elif "date:" in line.lower():
                current_case["date"] = line.split(":", 1)[1].strip()
        
        if current_case:
            cases.append(current_case)
        
        # 최소한의 정보가 있는 케이스만 반환
        valid_cases = [c for c in cases if c.get("title") and (c.get("description") or c.get("source_url"))]
        
        logger.info(f"폴백 파싱: {len(valid_cases)}개 사례 추출")
        return valid_cases
    
    def search_multiple_cves(self, 
                            cve_contexts: List[Dict[str, Any]], 
                            batch_delay: float = 2.0) -> Dict[str, List[Dict[str, str]]]:
        """
        여러 CVE에 대한 실제 사례를 일괄 검색
        
        Args:
            cve_contexts: CVE 컨텍스트 리스트 (cve_id, package_name, description 포함)
            batch_delay: 배치 사이 대기 시간
            
        Returns:
            CVE ID를 키로 하는 사례 딕셔너리
        """
        results = {}
        total = len(cve_contexts)
        
        logger.info(f"총 {total}개 CVE에 대한 실제 사례 검색 시작")
        
        for idx, context in enumerate(cve_contexts, 1):
            cve_id = context.get("cve_id", "UNKNOWN")
            package_name = context.get("package_name", "")
            description = context.get("description", "")
            
            logger.info(f"진행: {idx}/{total} - {cve_id} 검색 중...")
            
            cases = self.search_cve_cases(cve_id, package_name, description)
            results[cve_id] = cases
            
            # 배치 사이 대기 (마지막 항목이 아닌 경우)
            if idx < total:
                time.sleep(batch_delay)
        
        # 통계 출력
        total_cases = sum(len(cases) for cases in results.values())
        cves_with_cases = sum(1 for cases in results.values() if cases)
        
        logger.info(f"검색 완료: {total}개 CVE 중 {cves_with_cases}개에서 총 {total_cases}개 실제 사례 발견")
        
        return results


def create_searcher(api_key: Optional[str] = None) -> Optional[PerplexitySearcher]:
    """
    Perplexity 검색기 생성 (환경변수에서 API 키 로드)
    
    Args:
        api_key: 명시적 API 키 (선택사항)
        
    Returns:
        PerplexitySearcher 인스턴스 또는 None
    """
    import os
    
    key = api_key or os.getenv("PERPLEXITY_API_KEY")
    
    if not key:
        logger.warning("PERPLEXITY_API_KEY가 설정되지 않음 - 실제 사례 검색 비활성화")
        return None
    
    return PerplexitySearcher(api_key=key)


__all__ = [
    "PerplexitySearcher",
    "RealWorldCase",
    "create_searcher",
]
