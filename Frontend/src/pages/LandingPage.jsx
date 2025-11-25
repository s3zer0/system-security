// src/pages/LandingPage.jsx (수정된 최종 코드)

import React from 'react';
import { useNavigate } from 'react-router-dom';
import LandingHeader from '../components/LandingHeader';
import UploadPanel from '../components/UploadPanel';
import LandingHero from '../components/LandingHero'; 

const LandingPage = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-100 flex flex-col">
      <div className="w-full border-b border-gray-200 bg-white">
        <div className='max-w-7xl mx-auto'>
          <LandingHeader />
        </div>
      </div>

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col justify-center">
          
        <section className="grid lg:grid-cols-12 gap-8 lg:gap-24 items-center min-h-[60vh] mb-12">
            
          <div className="lg:col-span-7 flex flex-col justify-center"> 
            <LandingHero /> 
          </div>

          <div className="lg:col-span-5 w-full flex justify-center lg:justify-end">
            <div className="w-full max-w-md lg:max-w-[440px]">
                <UploadPanel />
            </div>
          </div>
        </section>

        <section className="landing-features mt-8">
          <div className="text-xs uppercase tracking-wider text-gray-500 mb-4 flex justify-between items-center font-medium px-1">
            주요 기능
            <button className="text-blue-600 hover:text-blue-800 text-sm font-medium transition-colors" onClick={() => navigate('/features')}>자세히 보기 →</button>
          </div>
            
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
              <h3 className="text-base font-bold mb-2 text-gray-900">자동 취약점 스캔</h3>
              <p className="text-gray-500 text-sm leading-relaxed">Trivy를 기반으로 Docker 이미지를 풀스캔하고, 심각도별로 정리합니다.</p>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
              <h3 className="text-base font-bold mb-2 text-gray-900">라이브러리·API 매핑</h3>
              <p className="text-gray-500 text-sm leading-relaxed">사용 중인 라이브러리와 그 API가 어떤 CVE에 연결되는지 시각화합니다.</p>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
              <h3 className="text-base font-bold mb-2 text-gray-900">AST 호출 그래프</h3>
              <p className="text-gray-500 text-sm leading-relaxed">실제 코드 경로를 AST로 분석해, 공격 경로에 직접 연결된 부분만 필터링합니다.</p>
            </div>
            <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm hover:shadow-md transition-shadow">
              <h3 className="text-base font-bold mb-2 text-gray-900">AI 패치 제안</h3>
              <p className="text-gray-500 text-sm leading-relaxed">LLM이 우선순위 높은 패치 세트를 제안하고 리포트로 정리해 줍니다.</p>
            </div>
          </div>
        </section>
      </main>
      <footer className="border-t border-gray-200 py-6 text-center bg-white mt-auto">
         <p className="text-xs text-gray-400">© 2025 System-Security · 4조</p>
      </footer>
    </div>
  );
};

export default LandingPage;
