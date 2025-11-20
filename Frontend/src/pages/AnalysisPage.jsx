import React from 'react';
import { useParams } from 'react-router-dom';
import { useAnalysis } from '../context/AnalysisContext';
import AnalysisSidebar from '../components/AnalysisSidebar';
import ChatPanel from '../components/ChatPanel';
import RiskBadge from '../components/RiskBadge';
import AnalysisMain from '../components/AnalysisMain';

export default function AnalysisPage() {
  const { jobId } = useParams();
  const { analyses } = useAnalysis();

  const currentAnalysis = analyses.find(analysis => analysis.id === jobId);

  const displayName = currentAnalysis
    ? currentAnalysis.name
    : (jobId || "분석");

  const displayRisk = currentAnalysis
    ? currentAnalysis.risk
    : "N/A";

  return (
    <div className="w-screen h-screen">
      <div className="border border-border rounded-panel overflow-hidden shadow-xl h-full flex flex-col">
        <header className="h-14 flex items-center justify-between px-4 border-b border-border bg-white text-sm flex-shrink-0">        
          <div className="font-medium text-text-main truncate">
            {displayName} · 분석 대시보드
          </div>
          <div className="text-xs text-text-muted flex items-center gap-1.5">
            <span>리스크:</span>
            <RiskBadge level={displayRisk} />
          </div>
        </header>

      <div className="flex-1 grid grid-cols-[260px_minmax(0,1fr)_320px] overflow-hidden bg-white">
        <AnalysisSidebar />
        <main className="min-w-0 border-x border-gray-200 bg-white overflow-y-auto">
          <AnalysisMain analysisId={jobId}/>
        </main>

        <ChatPanel />
      </div>
      </div>
    </div>
  );
}
