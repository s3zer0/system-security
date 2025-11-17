// src/pages/DocsPage.jsx

import React from 'react';
import CardLayout from '../components/CardLayout';

const DocsPage = () => {
  return (
    <CardLayout title="문서 · Getting Started" showAnalysisButton={true}>
      <h2 className="text-xl font-semibold mb-2">Getting Started 가이드</h2>
      <p className="text-gray-600">
        시스템보안 분석 도구 사용을 위한 시작 가이드입니다.
        아래 단계에 따라 Docker 이미지 분석을 시작하세요.
      </p>

      <ol className="list-decimal list-inside space-y-3 mt-3 ml-3">
        <li>
          <span className="font-medium">준비물 확인:</span> 분석하려는 Docker 이미지가 `docker save` 명령어로 저장된 `.tar` 또는 `.zip` 파일인지 확인합니다.
        </li>
        <li>
          <span className="font-medium">파일 업로드:</span> 랜딩 페이지의 업로드 패널에 파일을 드래그하거나 선택하여 업로드합니다.
        </li>
        <li>
          <span className="font-medium">분석 대시보드 확인:</span> 업로드 후 자동으로 이동하는 분석 페이지에서 진행 상황을 확인합니다.
        </li>
        <li>
          <span className="font-medium">결과 보고서 열람:</span> 분석 완료 후 심각도별 취약점 요약 및 패치 제안을 확인합니다.
        </li>
      </ol>

      <h3 className="text-lg font-semibold mt-4">API 사용 방법</h3>
      <p className="text-gray-600">
        `client.js` 파일에 정의된 API 함수를 사용합니다. 상세한 엔드포인트는 백엔드 가이드를 참조하세요.
      </p>
    </CardLayout>
  );
};

export default DocsPage;
