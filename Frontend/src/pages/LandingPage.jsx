// src/pages/LandingPage.jsx (수정된 최종 코드)

import React from 'react';
import { useNavigate } from 'react-router-dom';
import LandingHeader from '../components/LandingHeader';
import UploadPanel from '../components/UploadPanel';
import LandingHero from '../components/LandingHero'; 

const LandingPage = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="landing-shell w-full overflow-hidden shadow-2xl shadow-gray-900/10 border border-gray-200">
        
        <LandingHeader />

        <main className="landing-main p-8 flex flex-col gap-8 bg-gradient-to-br from-indigo-50/50 via-white to-white">
          
          {/* ⚠️ 수정: Grid 12컬럼 -> 10컬럼으로 변경 (6:4 비율) */}
          <section className="landing-hero grid lg:grid-cols-10 gap-8 items-center min-h-[85vh] place-items-center">
            
            {/* ⚠️ 수정: Hero Content 비율을 6/10으로 변경 (60%) */}
            <div className="lg:col-span-6"> 
              <LandingHero /> 
            </div>

            {/* ⚠️ 수정: Upload Panel 비율을 4/10으로 변경 (40%) */}
            <div className="lg:col-span-4">
              <UploadPanel />
            </div>
          </section>

          <section className="landing-features">
            <div className="landing-features-title text-xs uppercase tracking-wider text-gray-500 mb-3 flex justify-between items-center font-medium">
              주요 기능
              <button className="btn-text text-blue-700 hover:text-blue-800 text-sm p-1 font-medium" onClick={() => navigate('/features')}>자세히 보기 →</button>
            </div>
            
            <div className="landing-feature-grid grid sm:grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div className="landing-feature-card rounded-xl border border-gray-200 bg-white p-3">
                <h3 className="text-base font-bold mb-1">자동 취약점 스캔</h3>
                <p className="text-gray-500 text-xs font-normal">Trivy를 기반으로 Docker 이미지를 풀스캔하고, 심각도별로 정리합니다.</p>
              </div>
              <div className="landing-feature-card rounded-xl border border-gray-200 bg-white p-3">
                <h3 className="text-base font-bold mb-1">라이브러리·API 매핑</h3>
                <p className="text-gray-500 text-xs font-normal">사용 중인 라이브러리와 그 API가 어떤 CVE에 연결되는지 한 눈에 보여줍니다.</p>
              </div>
              <div className="landing-feature-card rounded-xl border border-gray-200 bg-white p-3">
                <h3 className="text-base font-bold mb-1">AST 호출 그래프</h3>
                <p className="text-gray-500 text-xs font-normal">실제 코드 경로를 AST로 분석해, 공격 경로에 직접 연결된 부분만 필터링합니다.</p>
              </div>
              <div className="landing-feature-card rounded-xl border border-gray-200 bg-white p-3">
                <h3 className="text-base font-bold mb-1">AI 패치 제안</h3>
                <p className="text-gray-500 text-xs font-normal">LLM이 우선순위 높은 패치 세트를 제안하고, 리포트 형식으로 정리해 줍니다.</p>
              </div>
            </div>
          </section>
        </main>
        
        <footer className="landing-footer border-t border-gray-200 p-3 text-xs text-gray-500 bg-gray-50 text-center font-normal">
          © 2025 System-Security · 내부 PoC 용 UI 시안
        </footer>

      </div>
    </div>
  );
};

export default LandingPage;
