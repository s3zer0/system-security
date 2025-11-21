// src/components/UploadPanel.jsx (충돌 해결 완료 및 최종 버전)

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { uploadImage } from '../api/client'; 
import { useAnalysis } from '../context/AnalysisContext';

const UploadPanel = () => {
    const navigate = useNavigate();

    const { addAnalysis } = useAnalysis();
    
    // State 설정 (드래그 상태 및 API 관련 상태 포함)
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
            // 파일 유효성 검사
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

    // 드래그 앤 드롭 이벤트 핸들러 (유지)
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

    // 🚀 API 호출 및 로직 통합 (폴링 메커니즘 포함)
    const handleUploadStart = async () => {
        if (!file) {
            setError("⚠️ 업로드할 파일을 선택해주세요.");
            return;
        }

        setUploading(true);
        setError(null);

        try {
            const result = await uploadImage(file, setProgress); 
            
            // Job ID 확인 및 페이지 이동
            if (result && result.analysis_id) {

                const pendingJob = {
                    analysis_id: result.analysis_id,
                    original_filename: file.name,
                    file_name: file.name,
                    created_at: Date.now(),
                    risk_level: 'Analyzing',

                    id: result.analysis_id,
                    name: file.name,
                    risk: 'Analyzing'
                };
                const savedPending = JSON.parse(localStorage.getItem('pendingAnalyses') || '[]');
                
                if(!savedPending.find(job => String(job.analysis_id) === String(result.analysis_id))){
                    localStorage.setItem('pendingAnalyses', JSON.stringify([...savedPending, pendingJob]));
                }

                addAnalysis(pendingJob);
                navigate(`/analysis/${result.analysis_id}`);
            } else {
                setError("분석 시작 실패: 서버 응답에 Job ID가 없습니다.");
                setUploading(false);
                return;
            }

            const analysisId = result.analysis_id;

            // 폴링 시작: 분석이 완료될 때까지 상태 확인
            const pollInterval = 2000; // 2초마다 체크
            const maxAttempts = 300; // 최대 10분 (300 * 2초)
            let attempts = 0;

            while (attempts < maxAttempts) {
                try {
                    const statusData = await getAnalysisStatus(analysisId);

                    if (statusData.status === "COMPLETED") {
                        // 분석 완료 - 결과 페이지로 이동
                        navigate(`/analysis/${analysisId}`);
                        return;
                    } else if (statusData.status === "FAILED") {
                        // 분석 실패
                        const errorMsg = statusData.error_message || "알 수 없는 오류";
                        setError(`분석 실패: ${errorMsg}`);
                        setUploading(false);
                        setProgress(0);
                        return;
                    }
                    // PENDING 또는 PROCESSING인 경우 계속 대기

                } catch (pollError) {
                    console.error("Status polling error:", pollError);
                    // 상태 조회 실패 시에도 계속 시도 (일시적 네트워크 오류 가능성)
                }

                // 다음 폴링까지 대기
                await new Promise(resolve => setTimeout(resolve, pollInterval));
                attempts++;
            }

            // 타임아웃
            setError("분석 대기 시간 초과: 분석이 너무 오래 걸리고 있습니다.");
            setUploading(false);
            setProgress(0);

        } catch (e) {
            console.error("Upload Error:", e);
            setError(`업로드 실패: ${e.message}`);
            setUploading(false);
            setProgress(0);
        }
    };

    return (
        // 최신 스타일: w-full, font-medium/normal 적용
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
                {uploading ? (progress < 100 ? `Uploading... (${progress}%)` : 'Processing...') : '분석 시작'}
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