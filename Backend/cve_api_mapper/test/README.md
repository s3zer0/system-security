# CVE to API Mapper Test Suite

CVE 설명과 API를 매핑하는 각 LLM 서비스별 테스트 코드입니다.

## 설치

```bash
pip install -r requirements.txt
```

## 환경 변수 설정

### .env 파일 사용 (권장)

1. `.env.example` 파일을 `.env`로 복사:
```bash
cp .env.example .env
```

2. `.env` 파일을 열어 각 API 키를 입력:
```bash
# .env 파일
OPENAI_API_KEY=your-openai-api-key-here
ANTHROPIC_API_KEY=your-anthropic-api-key-here
GOOGLE_API_KEY=your-google-api-key-here
XAI_API_KEY=your-xai-api-key-here
```

### 환경 변수로 직접 설정

```bash
# ChatGPT
export OPENAI_API_KEY='your-openai-api-key'

# Claude
export ANTHROPIC_API_KEY='your-anthropic-api-key'

# Gemini
export GOOGLE_API_KEY='your-google-api-key'

# Grok
export XAI_API_KEY='your-xai-api-key'
```

## 사용법

### 개별 테스트 실행

```bash
# ChatGPT 테스트
python test_chatgpt.py

# Claude 테스트
python test_claude.py

# Gemini 테스트
python test_gemini.py

# Grok 테스트
python test_grok.py
```

### 배치 테스트 실행

여러 라이브러리를 한 번에 테스트:

```bash
python test_chatgpt.py --batch
python test_claude.py --batch
python test_gemini.py --batch
python test_grok.py --batch
```

## 출력

결과는 `output/` 디렉토리에 JSON 형식으로 저장됩니다:
- `{llm_name}_{library}_{version}_mapping.json` - 개별 테스트 결과
- `{llm_name}_batch_results.json` - 배치 테스트 결과

## 구조

- `base_utils.py` - 공통 유틸리티 함수
- `test_chatgpt.py` - OpenAI GPT 테스트
- `test_claude.py` - Anthropic Claude 테스트
- `test_gemini.py` - Google Gemini 테스트
- `test_grok.py` - X.AI Grok 테스트

## 프롬프트 커스터마이징

각 테스트 파일의 `create_prompt()` 함수를 수정하거나 `base_utils.py`의 프롬프트 템플릿을 수정하여 프롬프트를 커스터마이징할 수 있습니다.