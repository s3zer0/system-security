// src/pages/LandingPage.jsx (모든 환경에서 동일하게 보이도록 최적화)

import React, { useState, useEffect, useRef } from 'react'; 
import { useNavigate } from 'react-router-dom';
import LandingHeader from '../components/LandingHeader';
import UploadPanel from '../components/UploadPanel';
import LandingHero from '../components/LandingHero'; 

// FeatureSlide 컴포넌트
const FeatureSlide = ({ title, description, index }) => {
  const [isVisible, setIsVisible] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.2 }
    );

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => {
      if (ref.current) {
        observer.unobserve(ref.current);
      }
    };
  }, []);

  return (
    <div 
      ref={ref}
      // 🔴 [복구]: 원래의 클래스 유지 (duration-700 및 translate-y-20)
      className={`min-h-screen flex flex-col items-center justify-center p-8 transition-all duration-700 snap-start snap-always ${
        isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-20'
      }`}
    >
      <div className="max-w-4xl text-center">
        <h2 className="text-4xl sm:text-5xl font-extrabold text-gray-900 mb-6">
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-indigo-600">
            {title}
          </span>
        </h2>
        <p className="text-lg text-gray-600 max-w-2xl mx-auto leading-relaxed">
          {description}
        </p>
      </div>
    </div>
  );
};

const FEATURES_DATA = [
    { title: "자동 취약점 스캔", description: "Trivy를 기반으로 Docker 이미지를 풀스캔하고, 심각도별로 정리합니다." },
    { title: "라이브러리·API 매핑", description: "사용 중인 라이브러리와 그 API가 어떤 CVE에 연결되는지 시각화합니다." },
    { title: "AST 호출 그래프", description: "실제 코드 경로를 AST로 분석해, 공격 경로에 직접 연결된 부분만 필터링합니다." },
    { title: "AI 패치 제안", description: "LLM이 우선순위 높은 패치 세트를 제안하고 리포트로 정리해 줍니다." },
];

const LandingPage = () => {
  const navigate = useNavigate();
  const [showScrollHint, setShowScrollHint] = useState(true);
  const heroRef = useRef(null);

  // 스크롤 스냅을 위한 body 스타일 적용
  useEffect(() => {
    document.documentElement.style.scrollSnapType = 'y mandatory';
    document.documentElement.style.scrollBehavior = 'smooth';
    
    return () => {
      document.documentElement.style.scrollSnapType = '';
      document.documentElement.style.scrollBehavior = '';
    };
  }, []);

  // 스크롤 힌트 자동 숨김
  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 100) {
        setShowScrollHint(false);
      } else {
        setShowScrollHint(true);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // 최상단 이동 함수
  const scrollToTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth'
    });
  };

  return (
    // 🔴 [수정]: 기존 bg-white 제거, 배경은 Fixed 레이어에 위임
    <div className="min-h-screen flex flex-col relative"> 
      
      {/* 🔴 [통합]: 강화된 고정 배경화면 코드로 교체 */}
      <div className="fixed inset-0 -z-10 bg-white">
        {/* 상단 은은한 블루 그라데이션 - 색상과 크기 강화 */}
        <div className="absolute top-0 left-0 right-0 h-[800px] bg-gradient-to-b from-blue-200/50 to-transparent"></div>
        {/* 우측 하단 은은한 인디고 도형 - 크기와 블러 조정 */}
        <div className="absolute bottom-0 right-0 w-[1200px] h-[1200px] bg-gradient-to-tl from-indigo-200/40 to-transparent rounded-full blur-2xl lg:blur-3xl"></div> 
      </div>

      {/* Fixed Header */}
      <div className="fixed top-0 left-0 right-0 w-full border-b border-gray-100 bg-white/90 backdrop-blur-sm z-20">
        <div className='max-w-full mx-auto px-4 sm:px-6 lg:px-8'>
          <LandingHeader />
        </div>
      </div>

      <main className="flex-1 w-full max-w-full mx-auto flex flex-col relative z-0 pt-16">
        {/* Hero 섹션 - 환경 독립적 중앙 정렬 */}
        <section 
          ref={heroRef} 
          className="min-h-screen flex items-center justify-center w-full px-4 sm:px-6 lg:px-8 py-8 snap-start snap-always"
        >
          <div className="w-full max-w-7xl mx-auto">
            <div className="grid lg:grid-cols-[1fr_auto] gap-8 items-center">
              {/* 왼쪽: 텍스트 콘텐츠 */}
              <div 
                // 🟢 [수정]: lg:-ml-8을 추가하여 텍스트 컨테이너를 왼쪽으로 32px 오프셋합니다.
                // 중앙 정렬을 깨지 않고 시각적인 위치만 조정합니다.
                className="flex flex-col justify-center relative z-10 lg:-ml-24" 
                style={{
                  animation: 'fadeInLeft 1s ease-out forwards',
                  opacity: 0
                }}
              > 
                <LandingHero /> 
              </div>

              {/* 오른쪽: 업로드 패널 */}
              <div 
                className="w-full flex justify-center lg:justify-end relative z-0 lg:ml-16 xl:ml-24"
                style={{
                  animation: 'fadeInRight 1s ease-out 0.3s forwards',
                  opacity: 0
                }}
              >
                <div className="w-full max-w-md lg:max-w-md xl:max-w-lg">
                  <UploadPanel />
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 스크롤 힌트 */}
        <div 
          className={`fixed bottom-8 left-1/2 -translate-x-1/2 z-20 transition-all duration-500 ${
            showScrollHint ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4 pointer-events-none'
          }`}
        >
          <div className="flex flex-col items-center gap-2 text-gray-400">
            <span className="text-xs font-medium">Scroll to explore</span>
            <div className="animate-bounce">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
              </svg>
            </div>
          </div>
        </div>

        {/* 기능 섹션들 */}
        <div className='max-w-full w-full'> 
          {FEATURES_DATA.map((feature, index) => (
            <FeatureSlide 
              key={index} 
              title={feature.title} 
              description={feature.description}
              index={index}
            />
          ))}
        </div>

        {/* 마지막 CTA 섹션 */}
        <section className="min-h-screen flex flex-col items-center justify-center p-8 bg-gradient-to-b from-transparent to-blue-50/30 snap-start snap-always">
          <div className="max-w-3xl text-center">
            <h2 className="text-4xl sm:text-5xl font-extrabold text-gray-900 mb-6">
              지금 바로 시작하세요
            </h2>
            <p className="text-lg text-gray-600 mb-8 leading-relaxed">
              Docker 이미지를 업로드하고 몇 분 안에 상세한 보안 분석 결과를 받아보세요.
            </p>
            <button 
              onClick={scrollToTop}
              className="px-8 py-4 rounded-full text-lg font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-lg shadow-blue-500/30 transition-all transform hover:-translate-y-0.5"
            >
              시작하기
            </button>
          </div>
        </section>
      </main>

      <style>{`
        @keyframes fadeInLeft {
          from {
            opacity: 0;
            transform: translateX(-40px);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
        
        @keyframes fadeInRight {
          from {
            opacity: 0;
            transform: translateX(40px);
          }
          to {
            opacity: 1;
            transform: translateX(0);
          }
        }
      `}</style>
    </div>
  );
};

export default LandingPage;
