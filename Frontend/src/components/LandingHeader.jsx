// src/components/LandingHeader.jsx

import React from 'react';
import { Link } from 'react-router-dom';

const LandingHeader = () => {
  return (
    <header className="landing-header h-16 flex items-center justify-between px-6 border-b border-gray-200 bg-white">
      
      {/* Logo: .landing-logo (AI Agent 로고와 텍스트) */}
      <Link to="/" className="landing-logo font-semibold tracking-wider flex items-center gap-2 cursor-pointer">
        
        {/* 새로운 AI 칩/두뇌 느낌의 SVG 아이콘 */}
        <div className="flex-shrink-0">
          <svg
            className="w-5 h-5"
            viewBox="0 0 24 24"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            {/* AI 칩/두뇌 느낌의 그라데이션 아이콘 */}
            <path
              d="M12 2C6.48 2 2 6.48 2 12C2 17.52 6.48 22 12 22C17.52 22 22 17.52 22 12C22 6.48 17.52 2 12 2ZM16 12C16 14.21 14.21 16 12 16C9.79 16 8 14.21 8 12C8 9.79 9.79 8 12 8C14.21 8 16 9.79 16 12Z"
              fill="url(#ai-gradient)"
            />
            {/* SVG 내부에 그라데이션 정의 (defs) */}
            <defs>
              <linearGradient id="ai-gradient" x1="2" y1="12" x2="22" y2="12" gradientUnits="userSpaceOnUse">
                <stop stopColor="#2563EB" /> {/* Blue-600 */}
                <stop offset="1" stopColor="#6D28D9" /> {/* Violet-700 */}
              </linearGradient>
            </defs>
          </svg>
        </div>
        
        {/* 텍스트를 "AI Agent"로 변경 */}
        <div className="text-gray-900">AI Agent</div>
      </Link>

      {/* Navigation */}
      <nav>
        <a href="https://github.com/s3zer0/system-security" target="_blank" rel="noopener noreferrer" className="text-sm text-gray-600 hover:text-gray-800 transition ml-4">
          GitHub
        </a>
      </nav>
    </header>
  );
};

export default LandingHeader;
