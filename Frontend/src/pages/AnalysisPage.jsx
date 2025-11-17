import AnalysisSidebar from '../components/AnalysisSidebar';
import ChatPanel from '../components/ChatPanel';
import AnalysisMain from '../components/AnalysisMain';

export default function AnalysisPage() {
  return (
    <div className="h-screen flex flex-col bg-white">
      <header className="h-14 border-b border-gray-200 flex items-center justify-between px-4 bg-white">
        <div className="text-[14px] text-gray-900">pyyaml-app.tar · 분석 대시보드</div>
        <div className="flex gap-2.5 text-xs text-gray-600 items-center">
          <span className="flex items-center gap-1">
            리스크:{' '}
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-800">HIGH</span>
          </span>
          <span>모델: gpt-4.x-sec</span>
        </div>
      </header>

      <div className="flex-1 grid grid-cols-[260px_minmax(0,1fr)_320px] overflow-hidden bg-white">
        <AnalysisSidebar />

        <main className="min-w-0 border-x border-gray-200 bg-white">
          <AnalysisMain />
        </main>

        <ChatPanel />
      </div>
    </div>
  );
}
