"""
간단한 YAML 서비스 모듈
CVE-2020-1747 취약점을 포함한 다양한 yaml.load() 패턴
"""

import yaml

class YamlService:
    """YAML 처리 서비스"""

    def __init__(self):
        self.loader = yaml.Loader

    def load_unsafe(self, text):
        """취약한 YAML 로딩 - yaml.Loader 사용"""
        return yaml.load(text, Loader=self.loader)

    def load_safe(self, text):
        """안전한 YAML 로딩 - yaml.safe_load 사용"""
        return yaml.safe_load(text)

    def load_file_unsafe(self, filepath):
        """파일에서 취약한 YAML 로딩"""
        with open(filepath, 'r') as f:
            return yaml.load(f, Loader=yaml.Loader)

    def merge_yaml_unsafe(self, yaml1, yaml2):
        """두 YAML 문서를 병합 (취약)"""
        data1 = yaml.load(yaml1, Loader=yaml.Loader)
        data2 = yaml.load(yaml2, Loader=yaml.Loader)
        if isinstance(data1, dict) and isinstance(data2, dict):
            data1.update(data2)
            return data1
        return [data1, data2]

# 내부 전용 YAML 처리 함수들
def _internal_yaml_processor(data):
    """내부 전용 YAML 처리"""
    return yaml.load(data, Loader=yaml.Loader)

def _batch_yaml_processor(yaml_list):
    """여러 YAML 파일 일괄 처리"""
    results = []
    for yaml_str in yaml_list:
        results.append(yaml.load(yaml_str, Loader=yaml.Loader))
    return results

# 사용되지 않는 함수들
def unused_yaml_processor():
    """사용되지 않는 YAML 처리 함수"""
    return yaml.load("unused: true", Loader=yaml.Loader)

class UnusedYamlProcessor:
    """사용되지 않는 YAML 처리 클래스"""
    def process(self, data):
        return yaml.load(data, Loader=yaml.UnsafeLoader)