import React, { createContext, useContext, useState } from 'react';

const MOCK_DATA = [
  { id: 'pyyaml-app.tar', name: 'pyyaml-app.tar', meta: '오늘 · 21:30', risk: 'Critical' },
  { id: 'node-api.zip', name: 'node-api.zip', meta: '어제', risk: 'Low' },
  { id: 'legacy-service.tar', name: 'legacy-service.tar', meta: '3일 전', risk: 'Medium' },
];

const AnalysisContext = createContext();


export function AnalysisProvider({ children }) {
  const [analyses, setAnalyses] = useState(MOCK_DATA);


  const addAnalysis = (newAnalysis) => {
    setAnalyses((prevAnalyses) => [newAnalysis, ...prevAnalyses]);
  };

  const value = { analyses, addAnalysis };

  return (
    <AnalysisContext.Provider value={value}>
      {children}
    </AnalysisContext.Provider>
  );
}

export const useAnalysis = () => {
    const context = useContext(AnalysisContext);
    if(context === undefined){
        throw new Error('useAnalysis must be used within a AnalysisProvider');
    }
    return context;
}