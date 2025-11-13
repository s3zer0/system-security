import { Routes, Route } from 'react-router-dom';
import UploadPage from './components/UploadPage';
import ProgressPage from './components/ProgressPage';
import SummaryPage from './components/SummaryPage';
import ReportPage from './components/ReportPage';

function App() {
  return (
    <main className="container mx-auto p-4">
      <Routes>
        <Route path="/" element={<UploadPage />} />
        <Route path="/analysis/:jobId" element={<ProgressPage />} />
        <Route path="/summary/:jobId" element={<SummaryPage />} />
        <Route path="/report/:jobId" element={<ReportPage />} />
      </Routes>
    </main>
  );
}

export default App;