"""
간단한 YAML 서비스 모듈
CVE-2020-1747 취약점을 포함한 다양한 yaml.load() 패턴
"""

import yaml

class YamlService:
    """
    YAML 처리 서비스 클래스

    다양한 YAML 로드 패턴을 제공하는 서비스
    """

    def __init__(self):
        """
        YamlService 초기화 - 기본 Loader 설정
        """
        self.loader = yaml.Loader  # 취약한 Loader 사용

    def load_unsafe(self, text):
        """
        취약한 YAML 로딩 메서드 - yaml.Loader 사용

        Args:
            text: YAML 문자열

        Returns:
            파싱된 YAML 데이터

        Warning:
            CVE-2020-1747 취약점 포함
        """
        return yaml.load(text, Loader=self.loader)

    def load_safe(self, text):
        """
        안전한 YAML 로딩 메서드 - yaml.safe_load 사용

        Args:
            text: YAML 문자열

        Returns:
            파싱된 YAML 데이터 (안전하게 처리됨)
        """
        return yaml.safe_load(text)

    def load_file_unsafe(self, filepath):
        """
        파일에서 취약한 YAML 로딩

        Args:
            filepath: YAML 파일 경로

        Returns:
            파싱된 YAML 데이터

        Warning:
            CVE-2020-1747 취약점 포함
        """
        with open(filepath, 'r') as f:
            return yaml.load(f, Loader=yaml.Loader)

    def merge_yaml_unsafe(self, yaml1, yaml2):
        """
        두 YAML 문서를 병합 (취약한 방식)

        Args:
            yaml1: 첫 번째 YAML 문자열
            yaml2: 두 번째 YAML 문자열

        Returns:
            병합된 YAML 데이터

        Warning:
            두 YAML 모두 취약한 Loader로 처리됨
        """
        # 취약한 Loader로 두 YAML 파싱
        data1 = yaml.load(yaml1, Loader=yaml.Loader)
        data2 = yaml.load(yaml2, Loader=yaml.Loader)

        # 딕셔너리인 경우 병합, 아니면 리스트로 반환
        if isinstance(data1, dict) and isinstance(data2, dict):
            data1.update(data2)
            return data1
        return [data1, data2]

# 내부 전용 YAML 처리 함수들
def _internal_yaml_processor(data):
    """
    내부 전용 YAML 처리 함수

    Args:
        data: YAML 문자열

    Returns:
        파싱된 YAML 데이터

    Note:
        외부에서 사용하지 말 것 (앞에 _가 붙은 함수는 내부용)
    """
    return yaml.load(data, Loader=yaml.Loader)

def _batch_yaml_processor(yaml_list):
    """
    여러 YAML 파일 일괄 처리 함수

    Args:
        yaml_list: YAML 문자열 리스트

    Returns:
        파싱된 YAML 데이터 리스트

    Warning:
        모든 항목을 취약한 Loader로 처리
    """
    results = []
    # 각 YAML 문자열을 취약한 방식으로 처리
    for yaml_str in yaml_list:
        results.append(yaml.load(yaml_str, Loader=yaml.Loader))
    return results

# 사용되지 않는 함수들 (테스트 목적)
def unused_yaml_processor():
    """
    사용되지 않는 YAML 처리 함수

    Returns:
        하드코딩된 YAML 데이터

    Note:
        실제로 호출되지 않음 (테스트 용도)
    """
    return yaml.load("unused: true", Loader=yaml.Loader)

class UnusedYamlProcessor:
    """
    사용되지 않는 YAML 처리 클래스

    Note:
        테스트 목적으로만 존재하는 클래스
    """
    def process(self, data):
        """
        YAML 데이터 처리

        Args:
            data: YAML 문자열

        Returns:
            파싱된 YAML 데이터

        Warning:
            UnsafeLoader 사용 (보안 취약)
        """
        return yaml.load(data, Loader=yaml.UnsafeLoader)