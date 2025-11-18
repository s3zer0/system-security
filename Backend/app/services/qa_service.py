"""LLM-backed Q&A service for stored analysis artefacts."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import List, Literal, Optional, Tuple

from dotenv import load_dotenv
from openai import AsyncOpenAI

from app.models import AnalysisMeta, AnalysisResult


load_dotenv()

logger = logging.getLogger("services.qa")
DEFAULT_QA_MODEL = os.getenv("LLM_QA_MODEL", "gpt-4o-mini")
_client: Optional[AsyncOpenAI] = None
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_RISK_KEYWORDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

SYSTEM_PROMPT = (
    "너는 Docker 이미지 보안 분석 리포트를 설명해주는 보안 어시스턴트이다. "
    "아래 JSON이 분석 결과이며 이것만이 진실이다.\n"
    "규칙:\n"
    "1. JSON에 포함된 이 Docker 이미지 보안 정보와 직접 관련된 질문만 답한다.\n"
    "2. JSON에 없는 CVE, 라이브러리, 버전, 설정 값은 절대 지어내지 않는다.\n"
    "3. 질문이 분석과 무관하면 다음 문장만 답한다:\n"
    "   이 엔드포인트는 이 이미지 분석 결과에 대한 보안 질문만 답변할 수 있습니다.\n"
    "4. 답변은 한국어로, 핵심만 간결하게 설명한다.\n"
    "5. 가능하면 CVE ID, 패키지 이름, 심각도, 패치 우선순위를 명확하게 언급한다."
)


def _get_client() -> AsyncOpenAI:
    """Return a cached AsyncOpenAI client instance."""

    global _client
    if _client is None:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not configured for LLM Q&A")
        _client = AsyncOpenAI()
    return _client


async def run_qa(
    meta: AnalysisMeta,
    result: AnalysisResult,
    question: str,
) -> Tuple[str, List[str], Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]]]:
    """Send the full analysis context to the LLM and return the parsed response."""

    qa_context = {
        "meta": {
            "analysis_id": meta.analysis_id,
            "file_name": meta.file_name,
            "created_at": meta.created_at.isoformat() if meta.created_at else None,
            "risk_level": meta.risk_level,
            "image_path": meta.image_path,
        },
        "result": result.dict(),
    }

    user_payload = {
        "question": question,
        "analysis": qa_context,
    }

    logger.debug("Invoking QA model %s for analysis %s", DEFAULT_QA_MODEL, meta.analysis_id)
    client = _get_client()
    response = await client.chat.completions.create(
        model=DEFAULT_QA_MODEL,
        temperature=0.0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
    )

    if not response.choices:
        raise RuntimeError("LLM response did not contain any choices")

    answer_text = response.choices[0].message.content or ""
    if not answer_text.strip():
        raise RuntimeError("LLM response was empty")

    used_cves: List[str] = []
    for match in _CVE_PATTERN.findall(answer_text):
        normalized = match.upper()
        if normalized not in used_cves:
            used_cves.append(normalized)

    upper_text = answer_text.upper()
    inferred_risk = next((level for level in _RISK_KEYWORDS if level in upper_text), None)

    return answer_text.strip(), used_cves, inferred_risk

