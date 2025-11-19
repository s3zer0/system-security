import React, { createContext, useContext, useState } from 'react';

const AnalysisContext = createContext();


export function AnalysisProvider({ children }) {
  const [analyses, setAnalyses] = useState([]);

  const [chatMainData, setChatMainData] = useState(null);

  const addAnalysis = (newAnalysis) => {
    setAnalyses((prevAnalyses) => [newAnalysis, ...prevAnalyses]);
  };

  const updateChatData = (newData) => {
    setChatMainData(newData);
  }

  const value = { analyses, addAnalysis, setAnalyses, chatMainData, updateChatData };

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
