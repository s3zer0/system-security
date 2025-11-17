// src/pages/LoginPage.jsx

import React from 'react';
import CardLayout from '../components/CardLayout';

const LoginPage = () => {
  // 로그인 페이지에서는 분석 결과 보기 버튼을 숨깁니다.
  return (
    <CardLayout title="로그인" showAnalysisButton={false}> 
      <h2 className="text-xl font-semibold mb-2 text-center">로그인하여 팀 환경에 접속하세요</h2>
      
      <div className="max-w-md mx-auto p-4 border border-gray-200 rounded-xl bg-gray-50 flex flex-col gap-4">
        
        {/* 일반 로그인 폼 (demo.html 기반) */}
        <div className="space-y-3">
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">이메일 주소</label>
            <input type="email" id="email" className="w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" placeholder="user@team.com" />
          </div>
          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">비밀번호</label>
            <input type="password" id="password" className="w-full p-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500" />
          </div>
        </div>
        
        <button className="w-full btn-primary bg-blue-600 text-white py-2 rounded-full font-medium hover:bg-blue-700 transition">
          로그인
        </button>
        
        <div className="relative my-3">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-300"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-2 bg-gray-50 text-gray-500">또는</span>
          </div>
        </div>

        {/* GitHub 로그인 (demo.html 기반) */}
        <button className="w-full btn-github border border-gray-300 bg-white text-gray-700 py-2 rounded-full font-medium hover:bg-gray-100 transition flex items-center justify-center gap-2">
          {/* GitHub 아이콘 Placeholder */}
          <span className="w-5 h-5 inline-block bg-gray-600 rounded-full"></span>
          GitHub로 계속하기
        </button>
      </div>

    </CardLayout>
  );
};

export default LoginPage;
