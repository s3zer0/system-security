import React, { useRef, useState, useEffect} from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useAnalysis } from '../context/AnalysisContext';
import RiskBadge from './RiskBadge';
import { uploadImage, getAnalysesList } from "../api/client";

function formatTimeAgo(isoTimestamp) {
    if (!isoTimestamp) return '날짜 정보 없음';
    const timestamp = new Date(isoTimestamp).getTime();
    const now = Date.now();
    const seconds = Math.floor((now - timestamp)/1000);

    if(seconds < 60) return '방금 전';
    if(seconds < 60 * 60) return `${Math.floor(seconds / 60)}분 전`;
    if(seconds < 60 * 60 * 24) return `${Math.floor(seconds / 3600)}시간 전`;

    return `${Math.floor(seconds / 86400)}일 전`;
}

function calculateRisk(summary){
    if(!summary) return 'N/A';
    if(summary.critical >= 1) return 'CRITICAL';
    if(summary.high >= 1) return 'HIGH';
    if(summary.medium >= 1) return 'MEDIUM';
    if(summary.low >= 1) return 'LOW';
    return 'SAFE';
}

function RunItem({ analysis, isActive }){
    return (
        <Link
            to={`/analysis/${analysis.id}`}
            className={`block p-2.5 rounded-xl cursor-pointer hover:bg-gray-100
                        ${isActive ? 'bg-primary-soft border border-primary' : 'border-transparent'}`}
        >
            <div className="font-medium text-text-main">{analysis.name}</div>
            <div className="flex justify-between items-center text-xs text-text-muted mt-0.5">
                <span>{formatTimeAgo(analysis.createdAt)}</span>
                <RiskBadge level={analysis.risk}/>
            </div>
        </Link>
    );
}

export default function AnalysisSidebar() {
    const navigate = useNavigate();
    const { analyses, addAnalysis, setAnalyses } = useAnalysis();
    const { jobId } = useParams();
  
    const [isUploading, setIsUploading] = useState(false);
    const [isDragging, setIsDragging] = useState(false);
    const [now, setNow] = useState(Date.now());
    const fileInputRef = useRef(null);

    /*
    useEffect(() =>{
        const fetchList = async () =>  {
            try{
                const ListFromDB = await getAnalysesList();
                const formattedList = ListFromDB.map(item => ({
                    id: item.id,
                    name: item.image_name,
                    createAt: item.create_at,
                    risk: item.status === 'completed'
                            ? calculateRisk(item.summary)
                            : item.status.toUpperCase()
                }));

                setAnalyses(formattedList);

            }catch(err){
                console.error("최근 목록 로딩 실패:", err);
                setAnalyses([]);
            }
        };

        fetchList();
    }, [setAnalyses]);
    */

    useEffect(() => {
        const interval = setInterval(() =>{
            setNow(Date.now());
        }, 60000);

        return () => clearInterval(interval);
    }, []);

    const handleFileUpload = async (file) => {
    
        if (!file) return;
        if (!file.name.toLowerCase().endsWith('.tar') && !file.name.toLowerCase().endsWith('.zip')) {
            alert('.tar 파일, .zip 파일만 업로드할 수 있습니다.');
            return;
        }

        setIsUploading(true);
        setIsDragging(false);
        setTimeout(() => {
            const uniqueId = `${file.name}-${Date.now()}`;

            const fakeResponse = {
                id: uniqueId,
                status: "STARTED",
            };

            const newAnlaysis = {
                id: fakeResponse.id,
                name: file.name,
                createdAt: new Date().toISOString(),
                risk: fakeResponse.status.toUpperCase(),
            };
            addAnalysis(newAnlaysis);

            navigate(`/analysis/${newAnlaysis.id}`);

            setIsUploading(false);
            if(fileInputRef.current){
                fileInputRef.current.value = '';
            }
        }, 1000);
        /*
        try{
            const response = await uploadImage(file, () => {});

            const newAnalysis = {
                id: response.id,
                name: file.name,
                createdAt: Date.now().toISOString(),
                risk: response.status.toUpperCase(),
            };
            addAnalysis(newAnalysis);

            navigate(`/analysis/${newAnalysis.id}`);
        }catch(err){
            alert('업로드에 실패했습니다: ' + err.message);
            console.error('[Upload Error] 업로드 실패:', err);
        }finally{
            setIsUploading(false);
            if(fileInputRef.current){
                fileInputRef.current.value = '';
            }
        }
        */
    };

    const handleFileSelect = (e) => {
        const file = e.target.files[0];
        handleFileUpload(file);      
    };

    const handleDragOver = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(true);
    };

    const handleDragLeave = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);
    };

    const handleDrop = (e) =>{
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);

        const file = e.dataTransfer.files[0];
        if(file){
            handleFileUpload(file);
        }
    }

    console.log('[sidebar 랜더링 ] 현재 analayes 배열:',analyses);

    return(
        <aside
            className="border-r border-border p-3 flex flex-col gap-3 bg-gray-50 text-sm"
                        
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}            
        >
            <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                accept=".tar, .zip"
                className="hidden"
            />

            <button
                onClick={() => fileInputRef.current.click()}
                disabled={isUploading}
                className={`
                    w-full text-left p-2.5 rounded-full border border-border bg-white font-medium
                    haver:bg-gray-50 disabled:opacity-50 transition-colors
                    ${isDragging ? 'border-dashed border-2 border-blue-500 bg-blue-50' : ''}
                `}
            >
                {isUploading ? '분석 중...' : (isDragging ? '여기에 드롭하세요' : '+ 새 Docker 분석')}
            </button>

            <div className="text-xs uppercase tracking-widset text-text-muted mt-1">
                최근 분석
            </div>

            {analyses && analyses.filter(analysis => analysis.id).map((analysis) => (
                <RunItem
                    key={analysis.id}
                    analysis={analysis}
                    isActive={jobId === analysis.id}
                />
            ))}
        </aside>
    );
}
