// src/App.jsx

import { Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
// import AnalysisPage from './pages/AnalysisPage'; // B, C 담당
import CardLayout from './components/CardLayout'; // A 담당

// 서브 페이지를 위한 임시 플레이스홀더
const PlaceholderPage = ({ title }) => (
  <CardLayout title={title} showAnalysisButton={title !== "로그인"}>
    <h2 className="text-xl font-bold">{title}</h2>
    <p>이 페이지는 곧 구현될 예정입니다.</p>
  </CardLayout>
);

function App() {
  return (
    // <main> 태그 제거! <Routes>만 남겨야 LandingPage의 풀 레이아웃이 제대로 나옵니다.
    <Routes>
      {/* A 담당: 랜딩 페이지 */}
      <Route path="/" element={<LandingPage />} />

      {/* A 담당: CardLayout을 사용하는 서브 페이지들 */}
      <Route path="/features" element={<PlaceholderPage title="주요 기능 상세" />} />
      <Route path="/docs" element={<PlaceholderPage title="문서 · Getting Started" />} />
      <Route path="/github" element={<PlaceholderPage title="GitHub Repository 안내" />} />
      <Route path="/login" element={<PlaceholderPage title="로그인" />} />

      {/* B, C 담당: 분석 관련 페이지 (임시 설정) */}
      <Route path="/analysis/:jobId" element={<div>분석 진행 현황 페이지 (B 담당)</div>} />
      <Route path="/summary/:jobId" element={<div>결과 요약 페이지 (C 담당)</div>} />

      {/* 404 처리 */}
      <Route path="*" element={<div>404 Not Found</div>} />
    </Routes>
  );
}

export default App;
