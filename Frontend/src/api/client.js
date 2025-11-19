import axios from 'axios';

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
        formData.append('file', file); // 백엔드에서 받을 key 이름

        const xhr = new XMLHttpRequest();
        
        xhr.timeout = 600000;

        xhr.upload.onprogress = (event) => {
            if (event.lengthComputable) {
                const percentCompleted = Math.round((event.loaded * 100) / event.total);
                onProgress(percentCompleted);
            }
        };

        xhr.onload = () => {
            if(xhr.status >= 200 && xhr.status < 300){
              try {
                resolve(JSON.parse(xhr.responseText));
              } catch (e) {
                reject(new Error(`Upload successful but failed to parse response JSON: ${e.message}`));
              }
            } else {
              reject(new Error(`Upload failed with status: ${xhr.status}`));
            }
        };

        xhr.onerror = () => {
            reject(new Error('Network error during upload.'));
        };

        xhr.ontimeout = () => {
          reject(new Error(`Upload timed out after ${xhr.timeout / 1000} seconds.`));
        };

        xhr.open('POST', `${API_BASE_URL}/analysis`);
        xhr.send(formData);
    });
};

/**
 * 2. 분석 진행 상황 조회
 */
export const getAnalysisStatus = async (jobId) => {
  try {
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
    const response = await apiClient.get(`/analysis/${jobId}`);
    return response.data.result;
  } catch (error) {
    console.error('분석 결과 조회 실패:', error);
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
    const response = await apiClient.get('/analyses');
    return response.data;
  } catch (error) {
    console.error('목록 조회 실패:', error);
    throw error;
  }
};

// AI 에이전트 채팅 API
export const getAiChatResponse = async (jobId, question) => {
  try {
    const response = await apiClient.post(`/analysis/${jobId}/qa`, { question });
    return {
      summary: response.data.answer,
      mainData: null
    }
  } catch (error) {
    console.error("AI 채팅 응답 실패:", error);
    throw error;
  }
};

export default apiClient;
