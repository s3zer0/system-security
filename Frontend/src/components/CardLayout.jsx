// src/components/CardLayout.jsx

import React from 'react';
import { useNavigate } from 'react-router-dom';

const CardLayout = ({ title, showAnalysisButton = true, children }) => {
  const navigate = useNavigate();

  return (
    <section className="page">
      <div className="card-shell max-w-4xl mx-auto my-8 md:my-16">
        {/* Card Header: .card-header */}
        <header className="card-header h-14 border-b border-gray-200 flex items-center justify-between px-5 bg-white">
          <div className="font-medium text-gray-800">{title}</div>
          <div className="flex gap-2">
            <button
              className="btn-ghost rounded-full border border-gray-300 px-3 py-1.5 text-sm bg-white text-gray-700 hover:bg-gray-50 transition"
              onClick={() => navigate('/')}
            >
              랜딩으로
            </button>
            {showAnalysisButton && (
              <button
                className="btn-primary rounded-full px-3 py-1.5 text-sm bg-blue-600 text-white hover:bg-blue-700 transition"
                onClick={() => navigate('/summary/sample-job-id')}
              >
                결과 페이지 보기
              </button>
            )}
          </div>
        </header>

        {/* Card Body: .card-body */}
        <div className="card-body p-5 md:p-6 bg-white text-sm text-gray-900 flex flex-col gap-4">
          {children}
        </div>
      </div>
    </section>
  );
};

export default CardLayout;
