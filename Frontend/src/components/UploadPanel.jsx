// src/components/UploadPanel.jsx

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const UploadPanel = () => {
  const navigate = useNavigate();
  
  // State 설정 (FRONTEND_GUIDE 4.4 참고)
  const [file, setFile] = useState(null); 
  const [uploading, setUploading] = useState(false); 
  const [progress, setProgress] = useState(0); 
  const [error, setError] = useState(null); 
  
  const formatFileSize = (bytes) => {
    if (!bytes) return '0 MB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const handleFileChange = (event) => {
    const selectedFile = event.target.files[0];
    if (selectedFile) {
      // 파일 유효성 검사 (.tar 또는 .zip)
      if (!selectedFile.name.endsWith('.tar') && !selectedFile.name.endsWith('.zip')) {
        setError("⚠️ Docker 이미지는 .tar 또는 .zip 형식만 지원합니다.");
        setFile(null);
        return;
      }
      
      setFile(selectedFile);
      setError(null);
      setProgress(0);
    }
  };

  const handleUploadStart = async () => {
    if (!file) {
      setError("⚠️ 업로드할 파일을 선택해주세요.");
      return;
    }
    
    setUploading(true);
    setError(null);
    setProgress(0);

    try {
      // FormData 생성
      const formData = new FormData();
      formData.append('file', file);

      // XMLHttpRequest를 사용하여 업로드 progress 추적
      const xhr = new XMLHttpRequest();

      // Progress 이벤트 핸들러
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = Math.round((e.loaded / e.total) * 100);
          setProgress(percentComplete);
        }
      });

      // 업로드 완료 핸들러
      xhr.addEventListener('load', () => {
        console.log('Upload response status:', xhr.status);
        console.log('Upload response text:', xhr.responseText);
        
        if (xhr.status === 200 || xhr.status === 201 || xhr.status === 202) {
          try {
            const response = JSON.parse(xhr.responseText);
            console.log('Parsed response:', response);
            
            // 백엔드 AnalysisResponse 구조: { meta: { analysis_id, ... }, result: { ... } }
            const analysisId = response.meta?.analysis_id || response.analysis_id || response.id;
            
            console.log('Extracted analysis_id:', analysisId);
            
            if (analysisId) {
              setTimeout(() => {
                setUploading(false);
                navigate(`/analysis/${analysisId}`);
              }, 500);
            } else {
              console.error('No analysis_id found in response:', response);
              setError('⚠️ 분석 ID를 받지 못했습니다. 응답 구조를 확인해주세요.');
              setUploading(false);
            }
          } catch (parseError) {
            console.error('Response parsing error:', parseError);
            console.error('Raw response:', xhr.responseText);
            setError(`⚠️ 서버 응답 처리 중 오류가 발생했습니다: ${parseError.message}`);
            setUploading(false);
          }
        } else {
          console.error('Upload failed with status:', xhr.status);
          console.error('Response:', xhr.responseText);
          setError(`⚠️ 업로드 실패: HTTP ${xhr.status} - ${xhr.statusText || '알 수 없는 오류'}`);
          setUploading(false);
        }
      });

      // 에러 핸들러
      xhr.addEventListener('error', () => {
        setError('⚠️ 네트워크 오류가 발생했습니다.');
        setUploading(false);
        setProgress(0);
      });

      // 업로드 중단 핸들러
      xhr.addEventListener('abort', () => {
        setError('⚠️ 업로드가 취소되었습니다.');
        setUploading(false);
        setProgress(0);
      });

      // 업로드 시작 - Vite 프록시를 통해 백엔드로 전달됨
      xhr.open('POST', '/analysis');
      xhr.send(formData);

    } catch (err) {
      console.error('Upload error:', err);
      setError('⚠️ 업로드 중 오류가 발생했습니다: ' + err.message);
      setUploading(false);
      setProgress(0);
    }
  };

  return (
    <div className="landing-upload-panel rounded-xl border border-gray-300 bg-white p-5 shadow-xl shadow-blue-500/10">
      <div className="landing-upload-title text-base font-semibold text-gray-900">빠른 시작</div>
      <div className="landing-upload-sub text-xs text-gray-500 mb-3">
        Docker 이미지 파일을 바로 올려서 분석을 시작하세요.
      </div>
      
      {/* Error Message */}
      {error && (
        <div className="bg-red-100 text-red-700 text-sm p-2 rounded-lg mb-3">
          {error}
        </div>
      )}

      {/* 파일 선택 UI 및 Dropzone */}
      <label htmlFor="file-upload" className="cursor-pointer">
        <div className="landing-dropzone rounded-xl border-2 border-dashed border-indigo-300 p-5 text-center bg-indigo-50 hover:bg-indigo-100 transition">
          {file ? (
            <>
              <div className="font-medium text-gray-900">{file.name}</div>
              <small className="block mt-1 text-xs text-gray-500">크기: {formatFileSize(file.size)}</small>
            </>
          ) : (
            <>
              .tar / .zip 파일을 이 영역으로 드래그 앤 드롭<br/>
              <small className="block mt-1 text-xs text-gray-500">또는 클릭해서 파일 선택 · 최대 1GB</small>
            </>
          )}
        </div>
      </label>
      <input 
        id="file-upload" 
        type="file" 
        accept=".tar,.zip" 
        onChange={handleFileChange} 
        className="hidden" 
        disabled={uploading}
      />
      
      {/* Progress Bar */}
      {uploading && (
        <div className="w-full bg-gray-200 rounded-full h-2.5 mb-3 mt-2">
          <div 
            className="bg-blue-600 h-2.5 rounded-full text-xs font-medium text-white text-center transition-all duration-300 ease-out" 
            style={{ width: `${progress}%` }}
          >
            {progress > 10 ? `${progress}%` : ''}
          </div>
        </div>
      )}

      {/* Upload/Action Buttons */}
      <button 
        className="btn-primary w-full rounded-full px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 transition mb-2 disabled:opacity-50"
        onClick={handleUploadStart}
        disabled={!file || uploading} 
      >
        {uploading ? `Uploading... (${progress}%)` : '분석 시작'}
      </button>
      
      <button 
        className="btn-ghost w-full rounded-full border border-gray-300 px-4 py-2 text-sm text-gray-700 bg-white hover:bg-gray-50 transition disabled:opacity-50"
        onClick={() => navigate('/summary/sample-job-id')}
        disabled={uploading}
      >
        최근에 돌린 분석 불러오기 (샘플)
      </button>

      {/* Pills */}
      <div className="landing-pill-row flex flex-wrap gap-2 mt-3 text-xs">
        <span className="pill border border-gray-300 px-2 py-1 rounded-full text-gray-600 bg-white">Trivy 스캔 결과 요약</span>
        <span className="pill border border-gray-300 px-2 py-1 rounded-full text-gray-600 bg-white">라이브러리 &amp; API 매핑</span>
      </div>
    </div>
  );
};

export default UploadPanel;