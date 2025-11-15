import AnalysisMain from '../components/AnalysisMain';

export default function AnalysisPage() {
  return (
    <div className="h-screen flex flex-col bg-white">
      {/* 헤더 */}
      <header className="h-14 border-b border-gray-200 flex items-center justify-between px-4 bg-white">
        <div className="text-[14px] text-gray-900">pyyaml-app.tar · 분석 대시보드</div>
        <div className="flex gap-2.5 text-xs text-gray-600 items-center">
          <span className="flex items-center gap-1">
            리스크: <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-800">HIGH</span>
          </span>
          <span>모델: gpt-4.x-sec</span>
        </div>
      </header>

      {/* 3단 레이아웃: 사이드바 + 중앙 + 채팅 */}
      <div className="flex-1 grid grid-cols-[260px_minmax(0,1fr)_320px] overflow-hidden">
        {/* ========== 왼쪽 사이드바 ========== */}
        <aside className="border-r border-gray-200 p-3 flex flex-col gap-3 bg-gray-50 overflow-y-auto">
          <button className="rounded-full border border-gray-200 bg-white text-gray-900 text-[13px] px-3 py-2 hover:bg-gray-50 transition">
            + 새 Docker 분석
          </button>
          
          <div className="text-[11px] uppercase tracking-wider text-gray-600 mt-1">최근 분석</div>
          
          <div className="px-2.5 py-2 rounded-lg bg-blue-50 border border-blue-600 cursor-pointer flex flex-col gap-0.5">
            <div className="text-[13px] font-medium text-gray-900">pyyaml-app.tar</div>
            <div className="text-[11px] text-gray-600 flex justify-between items-center">
              <span>오늘 · 21:30</span>
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-800">HIGH</span>
            </div>
          </div>

          <div className="px-2.5 py-2 rounded-lg hover:bg-gray-100 cursor-pointer flex flex-col gap-0.5 transition">
            <div className="text-[13px] font-medium text-gray-900">node-api.zip</div>
            <div className="text-[11px] text-gray-600 flex justify-between items-center">
              <span>어제</span>
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-green-100 text-green-800">LOW</span>
            </div>
          </div>

          <div className="px-2.5 py-2 rounded-lg hover:bg-gray-100 cursor-pointer flex flex-col gap-0.5 transition">
            <div className="text-[13px] font-medium text-gray-900">legacy-service.tar</div>
            <div className="text-[11px] text-gray-600 flex justify-between items-center">
              <span>3일 전</span>
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-yellow-100 text-yellow-800">MED</span>
            </div>
          </div>
        </aside>

        {/* ========== 중앙 - AnalysisMain ========== */}
        <AnalysisMain />

        {/* ========== 오른쪽 채팅 ========== */}
        <aside className="border-l border-gray-200 p-3 flex flex-col gap-2 bg-gray-50 overflow-hidden">
          <div className="text-[13px] font-medium text-gray-900">Ask the Security Agent</div>
          <div className="text-[11px] text-gray-600 mb-1">
            현재 컨텍스트: <code className="bg-gray-100 px-1 py-0.5 rounded text-blue-700">pyyaml-app:2025-10-01</code> 분석 결과 전체
          </div>

          <div className="flex-1 overflow-y-auto flex flex-col gap-1.5">
            <div className="px-2.5 py-2 rounded-lg bg-blue-50 text-blue-900 border border-blue-100 text-xs leading-relaxed">
              PyYAML 관련 취약점만 모아서 패치 순서를 정리해 드릴까요?<br/>
              또는 전체 RCE 가능성만 필터링할 수도 있습니다.
            </div>
            <div className="px-2.5 py-2 rounded-lg bg-white text-gray-900 border border-gray-200 text-xs leading-relaxed self-end">
              RCE 가능성이 있는 취약점만 정리하고, 실제 호출 경로도 같이 알려줘.
            </div>
          </div>

          <div className="border-t border-gray-200 pt-2 mt-1 flex gap-1.5 items-center">
            <textarea 
              placeholder="예: RCE 가능성 있는 취약점만 필터링해서 리포트 만들어줘"
              className="flex-1 resize-none rounded-full border border-gray-200 bg-white px-3 py-2 text-[13px] h-9 outline-none focus:border-blue-500"
            />
            <button className="rounded-full border-none px-3 py-2 bg-blue-600 text-white cursor-pointer text-[13px] hover:bg-blue-700 transition">
              전송 ⮞
            </button>
          </div>
        </aside>
      </div>
    </div>
  );
}
