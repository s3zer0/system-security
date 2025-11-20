"""
간단한 PyYAML 취약점 테스트 서버
CVE-2020-1747: yaml.load() 임의 코드 실행 취약점
"""

import os
import json
import yaml  # PyYAML 5.3.1 - CVE-2020-1747 취약점
from flask import Flask, request, jsonify
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulnerable-secret-key'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'

# ====================================================================
# 외부 접근 가능 엔드포인트 (External APIs)
# ====================================================================

@app.route('/')
def index():
    """메인 페이지"""
    return jsonify({
        'app': 'PyYAML Vulnerability Test',
        'version': '1.0',
        'pyyaml_version': yaml.__version__,
        'endpoints': {
            '/parse_yaml': 'POST - yaml.Loader (취약)',
            '/parse_yaml_unsafe': 'POST - yaml.UnsafeLoader (매우 취약)',
            '/safe_yaml': 'POST - yaml.safe_load (안전)',
            '/health': 'GET - 헬스체크'
        }
    })

@app.route('/parse_yaml', methods=['POST'])
def parse_yaml():
    """
    취약한 YAML 파싱 (CVE-2020-1747)
    yaml.load() with Loader=yaml.Loader
    """
    data = request.data.decode('utf-8')
    try:
        # 취약: yaml.Loader는 임의 Python 객체 생성 가능
        result = yaml.load(data, Loader=yaml.Loader)
        return jsonify({'result': str(result), 'type': str(type(result))})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/parse_yaml_unsafe', methods=['POST'])
def parse_yaml_unsafe():
    """
    yaml.UnsafeLoader 사용 - 명시적으로 위험
    """
    data = request.data.decode('utf-8')
    try:
        # 매우 취약: UnsafeLoader는 모든 Python 태그 처리
        result = yaml.load(data, Loader=yaml.UnsafeLoader)
        return jsonify({'result': str(result), 'loader': 'UnsafeLoader'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/safe_yaml', methods=['POST'])
def safe_yaml():
    """
    안전한 YAML 파싱 - yaml.safe_load() 사용
    """
    data = request.data.decode('utf-8')
    try:
        # 안전: safe_load는 기본 타입만 허용
        result = yaml.safe_load(data)
        return jsonify({'result': result, 'safe': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/yaml_base64', methods=['POST'])
def yaml_base64():
    """
    Base64로 인코딩된 YAML 파싱
    """
    data = request.json
    b64_yaml = data.get('yaml_b64', '')

    try:
        # Base64 디코드
        yaml_bytes = base64.b64decode(b64_yaml)
        yaml_str = yaml_bytes.decode('utf-8')

        # 취약: 디코딩된 YAML을 안전하지 않게 파싱
        result = yaml.load(yaml_str, Loader=yaml.Loader)

        return jsonify({
            'decoded_yaml': yaml_str,
            'result': str(result)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/health')
def health_check():
    """헬스체크 엔드포인트"""
    return jsonify({
        'status': 'healthy',
        'service': 'PyYAML Vulnerability Test',
        'pyyaml_version': yaml.__version__
    })

# ====================================================================
# 내부 전용 함수들 (Internal APIs)
# ====================================================================

def _internal_yaml_processor(data):
    """
    내부 전용 YAML 처리
    다른 내부 함수에서만 호출됨
    """
    # 취약: 내부 함수도 yaml.Loader 사용
    return yaml.load(data, Loader=yaml.Loader)

def _batch_yaml_processor(yaml_list):
    """
    여러 YAML 문서 일괄 처리 (내부 전용)
    """
    results = []
    for yaml_str in yaml_list:
        # 취약: 각 문서를 안전하지 않게 처리
        results.append(yaml.load(yaml_str, Loader=yaml.Loader))
    return results

def _load_config_yaml(config_path):
    """
    설정 파일 로드 (내부 전용)
    """
    with open(config_path, 'r') as f:
        # 취약: 설정 파일도 yaml.Loader로 로드
        return yaml.load(f, Loader=yaml.Loader)

class _InternalYamlHandler:
    """
    내부 전용 YAML 핸들러 클래스
    외부에서 직접 인스턴스화할 수 없음
    """

    def process(self, data):
        """YAML 데이터 처리"""
        # 취약: 클래스 내부에서도 yaml.Loader 사용
        return yaml.load(data, Loader=yaml.Loader)

    def process_file(self, filepath):
        """파일에서 YAML 로드"""
        with open(filepath, 'r') as f:
            return yaml.load(f, Loader=yaml.Loader)

# ====================================================================
# 사용되지 않는 함수들 (Unused APIs)
# ====================================================================

def unused_yaml_function():
    """
    사용되지 않는 YAML 함수
    코드베이스에 존재하지만 호출되지 않음
    """
    # 취약하지만 실제로 실행되지 않음
    return yaml.load("test: data", Loader=yaml.Loader)

def unused_unsafe_loader():
    """
    사용되지 않는 UnsafeLoader 함수
    """
    return yaml.load("test: 123", Loader=yaml.UnsafeLoader)

def deprecated_yaml_function():
    """
    더 이상 사용되지 않는 deprecated 함수
    """
    import warnings
    warnings.filterwarnings('ignore')
    return yaml.load("deprecated: true")

class UnusedYamlClass:
    """
    사용되지 않는 YAML 처리 클래스
    """
    def parse(self, data):
        # 취약하지만 이 클래스는 인스턴스화되지 않음
        return yaml.load(data, Loader=yaml.Loader)

if __name__ == '__main__':
    # 업로드 폴더 생성
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # 서버 시작
    app.run(host='0.0.0.0', port=5000, debug=True)