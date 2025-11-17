// src/components/LandingHero.jsx

import React from 'react';
import { useNavigate } from 'react-router-dom';

const LandingHero = () => {
  const navigate = useNavigate();

  return (
    <div className="lg:col-span-3">
      <h1 className="landing-hero-title text-4xl font-extrabold leading-tight mb-3">
        Docker 이미지를 올리면<br/>
        <span className="text-blue-700">취약점부터 패치 우선순위까지</span><br/>AI가 한 번에 정리합니다.
      </h1>
      
      <p className="landing-hero-sub text-sm text-gray-500 mb-5 max-w-lg">
        .tar / .zip 이미지를 업로드하면 Trivy 스캔, 라이브러리·API·AST 분석, CVE 매핑을 자동으로 수행하고
        배포 전에 필요한 조치만 추려서 알려줍니다.
      </p>
      
      <div className="landing-hero-actions flex gap-3 flex-wrap mb-4">
        <button 
          className="btn-primary rounded-full px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 transition"
          onClick={() => navigate('/analysis/mock-job-id-1234')}
        >
          이미지 업로드로 시작하기
        </button>
        <button 
          className="btn-ghost rounded-full border border-gray-300 px-4 py-2 text-sm text-gray-700 bg-white hover:bg-gray-50 transition"
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
