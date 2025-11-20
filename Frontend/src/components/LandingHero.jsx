// src/components/LandingHero.jsx (최종 확인 버전)

import React from 'react';
import { useNavigate } from 'react-router-dom';

const LandingHero = () => {
  const navigate = useNavigate();

  return (
    // ⚠️ 수정된 최종 스타일: flex-col, gap-4로 구조화
    <div className="landing-hero-text text-gray-800 flex flex-col gap-4">
      
      {/* ⚠️ 수정된 최종 스타일: text-5xl 로 글자 크기 키움 */}
      <h1 className="text-5xl font-bold leading-tight">
        Docker 이미지를 올리면
        <br />
        취약점부터 패치 우선순위까지
        <br />
        AI가 한 번에 정리합니다.
      </h1>
      
      <p className="text-lg text-gray-500 font-normal">
        .tar / .zip 이미지를 업로드하면 Trivy 스캔, 라이브러리/API AST 분석, CVE 매핑을 자동으로 수행하고
        <br />
        배포 전에 필요한 조치만 추려서 알려줍니다.
      </p>

      {/* 액션 버튼 그룹 */}
      <div className="landing-actions flex gap-3 flex-wrap mt-4">
        <button 
          className="btn-primary rounded-full px-7 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 transition"
          onClick={() => navigate('/analysis/mock-job-id-1234')}
        >
          이미지 업로드로 시작하기
        </button>
        <button 
          className="btn-ghost rounded-full border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 bg-white hover:bg-gray-100 transition"
          onClick={() => navigate('/summary/sample-job-id')}
        >
          샘플 분석 미리보기
        </button>
      </div>

      {/* 메타 정보 */}
      <div className="landing-meta flex gap-3 flex-wrap text-xs text-gray-500 font-normal mt-4">
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-yellow-500 rounded-full"></span>
          🔒 로컬·사내망 배포 지원
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-red-500 rounded-full"></span>
          ⚙️ Trivy 기반 취약점 스캔
        </span>
        <span className="flex items-center gap-1">
          <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
          🧠 LLM 기반 패치 제안
        </span>
      </div>
    </div>
  );
};

export default LandingHero;
