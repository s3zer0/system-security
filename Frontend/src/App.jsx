import { Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import CardLayout from './components/CardLayout';
import AnalysisPage from './pages/AnalysisPage';
import SampleAnalysisPreviewPage from './pages/SampleAnalysisPreviewPage';

const PlaceholderPage = ({ title }) => (
  <CardLayout title={title} showAnalysisButton={title !== "로그인"}>
    <h2 className="text-xl font-bold">{title}</h2>
    <p>이 페이지는 곧 구현될 예정입니다.</p>
  </CardLayout>
);

function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/features" element={<PlaceholderPage title="주요 기능 상세" />} />
      <Route path="/docs" element={<PlaceholderPage title="문서 · Getting Started" />} />
      <Route path="/github" element={<PlaceholderPage title="GitHub Repository 안내" />} />
      <Route path="/login" element={<PlaceholderPage title="로그인" />} />
      <Route path="/analysis" element={<AnalysisPage />} />
      <Route path="/analysis/:jobId" element={<AnalysisPage />} />
      <Route path="/summary/:jobId" element={<SampleAnalysisPreviewPage />} />
      <Route path="*" element={<div>404 Not Found</div>} />
    </Routes>
  );
}

export default App;
