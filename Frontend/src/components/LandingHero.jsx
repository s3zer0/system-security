// src/components/LandingHero.jsx

import React from 'react';
import { useNavigate } from 'react-router-dom';

const LandingHero = () => {
  const navigate = useNavigate();

  return (
    <div className="text-center lg:text-left">
      <h1 className="text-3xl sm:text-4xl lg:text-5xl xl:text-6xl font-extrabold tracking-tight text-gray-900 leading-[1.2] mb-6 break-keep">
        Docker 이미지를 올리면<br className="hidden lg:block" />
        <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-indigo-600">
          취약점부터 패치 우선순위까지
          </span><br/>
          AI가 한 번에 정리합니다.
      </h1>
      
      <p className="text-base sm:text-lg text-gray-600 mb-8 max-w-2xl mx-auto lg:mx-0 leading-relaxed">
        .tar / .zip 이미지를 업로드하면 Trivy 스캔, 라이브러리·API·AST 분석, CVE 매핑을 자동으로 수행하고
        배포 전에 필요한 조치만 추려서 알려줍니다.
      </p>
      
      <div className="flex gap-4 flex-wrap justify-center lg:justify-start mb-8">
        <button 
          className="px-6 py-3.5 rounded-full text-base font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-lg shadow-blue-500/30 transition-all transform hover:-translate-y-0.5"
          onClick={() => navigate('/analysis/')}
        >
          이미지 업로드로 시작하기
        </button>
        <button 
          className="px-6 py-3.5 rounded-full border border-gray-200 text-base font-semibold text-gray-700 bg-white hover:bg-gray-50 transition-all hover:border-gray-300"
          onClick={() => navigate('/summary/sample-job-id')}
        >
          샘플 분석 미리보기
        </button>
      </div>
      
      <div className="landing-hero-meta flex gap-3 flex-wrap text-xs text-gray-500">
        <span>🔒 로컬·사내망 배포 지원</span>
        <span>⚙️ Trivy 기반 취약점 스캔</span>
        <span>🧠 LLM 기반 패치 제안</span>
      </div>
    </div>
  );
};

export default LandingHero;