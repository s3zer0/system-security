/*
import { Routes, Route } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import AnalysisPage from './pages/AnalysisPage';

function App() {
  return (
    <main className="container mx-auto p-4">
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/analysis/:jobId" element={<AnalysisPage />} />
      </Routes>
    </main>
  );
}

export default App;
*/

// src/App.jsx
import AnalysisPage from './pages/AnalysisPage';  // 또는 './pages/ProgressPage'

function App() {
  return <AnalysisPage />;
}

export default App;