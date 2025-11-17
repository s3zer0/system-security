import React from 'react';
import AnalysisSidebar from '../components/AnalysisSidebar';
import ChatPanel from '../components/ChatPanel';           

export default function AnalysisPage() {
  return (
    <div className="max-w-7xl mx-auto my-8">
      <div className="border border-border rounded-panel overflow-hidden shadow-xl">
        <header className="h-14 flex items-center px-4 border-b border-border bg-white text-sm">
          분석 대시보드
        </header>

        <div className="grid grid-cols-[260px_minmax(0,1fr)_320px] min-h-[600px]">
          
          <AnalysisSidebar />
          
          <main className="p-4">
            (분석페이지 영역)
          </main>
          
          <ChatPanel />
        </div>
      </div>
    </div>
  );
}