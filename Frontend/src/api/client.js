import axios from 'axios';

// Proxy를 타기 위해 도메인을 제거하고 '/api'만 남깁니다.
const API_BASE_URL = '/api'; 

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * 1. Docker 이미지 업로드
 */
export const uploadImage = async (file, onProgress) => {
    return new Promise((resolve, reject) => {
        const formData = new FormData();
        formData.append('file', file); 

        const xhr = new XMLHttpRequest();

        xhr.upload.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentCompleted = Math.round((event.loaded * 100) / event.total);
                onProgress(percentCompleted);
            }
        };

        xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(JSON.parse(xhr.responseText));
            } else {
                reject(new Error(`Upload failed with status: ${xhr.status}`));
            }
        };

        xhr.onerror = () => {
            reject(new Error('Network error during upload.'));
        };

        // 수정: API_BASE_URL이 '/api'이므로, 결과적으로 /api/analysis 로 요청됨
        // (백엔드 명세가 /analysis 인 경우)
        xhr.open('POST', `${API_BASE_URL}/analysis`); 
        xhr.send(formData);
    });
};

/**
 * 2. 분석 진행 상황 조회
 */
export const getAnalysisStatus = async (jobId) => {
  try {
    // 백엔드에 status 전용 엔드포인트가 없다면 추후 수정 필요 (현재는 코드 보존)
    const response = await apiClient.get(`/analysis/${jobId}/status`);
    return response.data;
  } catch (error) {
    console.error('상태 조회 실패:', error);
    throw error;
  }
};

/**
 * 3. 분석 결과 요약 조회
 */
export const getAnalysisSummary = async (jobId) => {
  try {
    const response = await apiClient.get(`/analysis/${jobId}/summary`);
    return response.data;
  } catch (error) {
    console.error('요약 조회 실패:', error);
    throw error;
  }
};

/**
 * 4. 상세 보고서 조회
 */
export const getAnalysisReport = async (jobId) => {
  try {
    const response = await apiClient.get(`/analysis/${jobId}/report`);
    return response.data;
  } catch (error) {
    console.error('보고서 조회 실패:', error);
    throw error;
  }
};

/**
 * 5. 이전 분석 목록 조회 (수정됨)
 */
export const getAnalysesList = async () => {
  try {
    // 수정: baseURL(/api) + url(/analyses) -> Proxy -> 백엔드(/analyses)
    const response = await apiClient.get('/analyses');
    return response.data;
  } catch (error) {
    console.error('목록 조회 실패:', error);
    throw error;
  }
};

export default apiClient;