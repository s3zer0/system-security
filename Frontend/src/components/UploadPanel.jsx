// src/components/UploadPanel.jsx (Pills UI 삭제 완료)

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadImage } from '../api/client';

const UploadPanel = () => {
    const navigate = useNavigate();
    
    // State 설정
    const [file, setFile] = useState(null); 
    const [uploading, setUploading] = useState(false); 
    const [progress, setProgress] = useState(0); 
    const [error, setError] = useState(null); 
    const [isDragging, setIsDragging] = useState(false); 
    
    const formatFileSize = (bytes) => {
        if (!bytes) return '0 MB';
        return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    };

    // 파일 유효성 검사 및 상태 설정 (드롭/클릭 공통 로직)
    const processFile = (selectedFile) => {
        if (selectedFile) {
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

    // INPUT 태그 파일 변경 핸들러
    const handleFileChange = (event) => {
        processFile(event.target.files[0]);
    };

    // 드래그 앤 드롭 이벤트 핸들러
    const handleDragOver = (e) => { e.preventDefault(); };
    const handleDragEnter = (e) => {
        e.preventDefault();
        if (e.dataTransfer.items && e.dataTransfer.items.length > 0) { setIsDragging(true); }
    };
    const handleDragLeave = (e) => { e.preventDefault(); setIsDragging(false); };
    const handleDrop = (e) => {
        e.preventDefault();
        setIsDragging(false);

        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            processFile(e.dataTransfer.files[0]);
        }
    };

    // 🚀 API 호출 및 로직 통합
    const handleUploadStart = async () => {
        if (!file) {
            setError("⚠️ 업로드할 파일을 선택해주세요.");
            return;
        }
        
        setUploading(true);
        setError(null);

        try {
            const result = await uploadImage(file, setProgress); 
            
            // Job ID 확인 로직
            if (result && result.analysis_id) {
                // 성공 시, 반환된 analysis_id로 페이지 이동
                navigate(`/analysis/${result.analysis_id}`);
            } else {
                 // 응답 형식이 잘못된 경우 처리
                setError("분석 시작 실패: 서버 응답에 Job ID가 없습니다.");
                setUploading(false);
            }

        } catch (e) {
            console.error("Upload Error:", e);
            // 에러 메시지 업데이트 및 상태 초기화
            setError(`업로드 실패: ${e.message}`);
            setUploading(false);
            setProgress(0);
        }
    };

    return (
        // 최상위 div: 닫는 괄호(</div>)가 파일 끝에 올바르게 배치됨
        <div className="landing-upload-panel w-full rounded-xl border border-gray-300 bg-white p-5 shadow-xl shadow-blue-500/10">
            <div className="landing-upload-title text-base font-semibold text-gray-900 font-medium">빠른 시작</div>
            <div className="landing-upload-sub text-xs text-gray-500 mb-3 font-normal">
                Docker 이미지 파일을 바로 올려서 분석을 시작하세요.
            </div>
            
            {/* Error Message */}
            {error && (
                <div className="bg-red-100 text-red-700 text-sm p-2 rounded-lg mb-3 font-normal">
                    {error}
                </div>
            )}

            {/* 파일 선택 UI 및 Dropzone */}
            <label htmlFor="file-upload" className="cursor-pointer">
                <div 
                    className={`
                        landing-dropzone rounded-xl border-2 border-dashed p-5 text-center transition
                        ${isDragging 
                            ? 'border-blue-600 bg-blue-100'
                            : 'border-indigo-300 bg-indigo-50 hover:bg-indigo-100'
                        }
                    `}
                    onDragOver={handleDragOver}
                    onDragEnter={handleDragEnter}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                >
                    {file ? (
                        <>
                            <div className="font-medium text-gray-900">{file.name}</div>
                            <small className="block mt-1 text-xs text-gray-500 font-normal">크기: {formatFileSize(file.size)}</small>
                        </>
                    ) : (
                        <>
                            .tar / .zip 파일을 이 영역으로 드래그 앤 드롭<br/>
                            <small className="block mt-1 text-xs text-gray-500 font-normal">또는 클릭해서 파일 선택 · 최대 1GB</small>
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
                        className="bg-blue-600 h-2.5 rounded-full text-[10px] font-medium text-white transition-all duration-300 ease-out flex items-center justify-center" 
                        style={{ width: `${progress}%` }}
                    >
                        {progress > 10 ? `${progress}%` : ''}
                    </div>
                </div>
            )}

            {/* Upload/Action Buttons */}
            <button 
                className="btn-primary w-full rounded-full px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 transition mb-2 disabled:opacity-50 mt-3"
                onClick={handleUploadStart}
                disabled={!file || uploading} 
            >
                {uploading ? `Uploading... (${progress}%)` : '분석 시작'}
            </button>
            
            <button 
                className="btn-ghost w-full rounded-full border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 transition disabled:opacity-50"
                onClick={() => navigate('/summary/sample-job-id')}
                disabled={uploading}
            >
                최근에 돌린 분석 불러오기 (샘플)
            </button>

            {/* Pills UI는 완전히 삭제되었습니다. */}

        </div>
    );
};

export default UploadPanel;
