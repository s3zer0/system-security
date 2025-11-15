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

    // [데모용 임시 로직: Progress Bar만 시뮬레이션하고 페이지 이동]
    let currentProgress = 0;
    const interval = setInterval(() => {
        currentProgress += 10;
        setProgress(currentProgress);
        if (currentProgress >= 100) {
            clearInterval(interval);
            setTimeout(() => {
                setUploading(false);
                // FRONTEND_GUIDE 4.3.4에 따라 analysis 페이지로 이동
                navigate('/analysis/mock-job-id-1234');
            }, 500);
        }
    }, 150);
    // [데모용 임시 로직 끝]
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
