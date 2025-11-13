import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * 1. Docker 이미지 업로드
 * @param {File} file - 업로드할 .tar 파일
 * @param {Function} onProgress - 업로드 진행률 콜백 (0-100)
 * @returns {Promise<{ id: string, status: string }>}
 */
export const uploadImage = async (file, onProgress) => {

    return new Promise((resolve, reject) =>{
        const formData = new FormData();
        formData.append('imageFile', file); // 백엔드에서 받을 key 이름 (예: 'imageFile')

        const xhr = new XMLHttpRequest();

        xhr.upload.onprogress = (event) =>{
            if(event.lengthComputable){
                const percentCompleted = Math.round((event.loaded * 100)/ event.total);
                onProgress(percentCompleted);
            }
        };

        xhr.onload = () => {
            if(xhr.status >= 200 && xhr.status < 300){
                resolve(JSON.parse(xhr.responseText));
            }else{
                reject(new Error('Upload failed with status: ${xhr.status}'));
            }
        };

        xhr.onerror = () =>{
            reject(new Error('Network error during upload.'));
        };

        xhr.open('Post',  '${API_BASE_URL}/api/analyses');
        xhr.send(formData);
    });
};

/**
 * 2. 분석 진행 상황 조회
 * @param {string} jobId
 * @returns {Promise<object>} 진행 상태 객체
 */
export const getAnalysisStatus = async (jobId) => {
  try {
    const response = await apiClient.get(`/api/analyses/${jobId}/status`);
    return response.data;
  } catch (error) {
    console.error('상태 조회 실패:', error);
    throw error;
  }
};

/**
 * 3. 분석 결과 요약 조회
 * @param {string} jobId
 * @returns {Promise<object>} 요약 데이터 객체
 */
export const getAnalysisSummary = async (jobId) => {
  try {
    const response = await apiClient.get(`/api/analyses/${jobId}/summary`);
    return response.data;
  } catch (error) {
    console.error('요약 조회 실패:', error);
    throw error;
  }
};

/**
 * 4. 상세 보고서 조회
 * @param {string} jobId
 * @returns {Promise<Array>} 전체 모듈 정보 배열
 */
export const getAnalysisReport = async (jobId) => {
  try {
    const response = await apiClient.get(`/api/analyses/${jobId}/report`);
    return response.data;
  } catch (error) {
    console.error('보고서 조회 실패:', error);
    throw error;
  }
};

/**
 * 5. 이전 분석 목록 조회
 * @returns {Promise<Array>} 분석 목록 배열
 */
export const getAnalysesList = async () => {
  try {
    const response = await apiClient.get('/api/analyses');
    return response.data;
  } catch (error) {
    console.error('목록 조회 실패:', error);
    throw error;
  }
};