"""
간단한 PyYAML 취약점 테스트
"""

import unittest
import yaml
from app.server import app
from app.yaml_service import YamlService

class TestYamlVulnerabilities(unittest.TestCase):
    """YAML 취약점 테스트"""

    def setUp(self):
        self.app = app.test_client()
        self.yaml_service = YamlService()

    def test_yaml_loader_endpoint(self):
        """yaml.Loader 엔드포인트 테스트"""
        payload = "test: data"
        response = self.app.post('/parse_yaml', data=payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn('result', response.json)

    def test_yaml_unsafe_loader(self):
        """yaml.UnsafeLoader 테스트"""
        payload = "unsafe: true"
        response = self.app.post('/parse_yaml_unsafe', data=payload)
        self.assertEqual(response.status_code, 200)

    def test_safe_yaml(self):
        """안전한 YAML 테스트"""
        payload = "safe: data"
        response = self.app.post('/safe_yaml', data=payload)
        self.assertEqual(response.status_code, 200)

    def test_yaml_service_unsafe(self):
        """YamlService 취약한 메소드 테스트"""
        result = self.yaml_service.load_unsafe("test: value")
        self.assertEqual(result, {"test": "value"})

    def test_yaml_service_safe(self):
        """YamlService 안전한 메소드 테스트"""
        result = self.yaml_service.load_safe("test: value")
        self.assertEqual(result, {"test": "value"})

class TestInternalFunctions(unittest.TestCase):
    """내부 함수 테스트"""

    def test_internal_yaml_processor(self):
        """내부 YAML 처리기 테스트"""
        from app.server import _internal_yaml_processor
        result = _internal_yaml_processor("key: value")
        self.assertEqual(result, {"key": "value"})

    def test_batch_yaml_processor(self):
        """배치 YAML 처리기 테스트"""
        from app.server import _batch_yaml_processor
        yaml_list = ["item1: value1", "item2: value2"]
        result = _batch_yaml_processor(yaml_list)
        self.assertEqual(len(result), 2)

class TestUnusedFunctions(unittest.TestCase):
    """사용되지 않는 함수 테스트"""

    def test_unused_functions_exist(self):
        """사용되지 않는 함수들 존재 확인"""
        from app.server import unused_yaml_function, unused_unsafe_loader
        self.assertTrue(callable(unused_yaml_function))
        self.assertTrue(callable(unused_unsafe_loader))

if __name__ == '__main__':
    unittest.main()