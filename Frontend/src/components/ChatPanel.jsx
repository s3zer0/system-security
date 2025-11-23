import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useAnalysis } from '../context/AnalysisContext';
import { getAiChatResponse } from '../api/client';

export default function ChatPanel(){

    const { jobId } = useParams();

    const { analyses, updateChatData } = useAnalysis();

    const [messages, setMessages] = useState([]);
    const [isLoadingHistory, setIsLoadingHistroy] = useState(false);
    const [isAiThinking, setIsAiThinking] = useState(false);
    const [input, setInput] = useState('');

    const currentAnalysis = analyses.find(a => String(a.id) === String(jobId));

    const displayName = currentAnalysis
        ? (currentAnalysis.name || currentAnalysis.original_filename || currentAnalysis.file_name)
        : (jobId ? `분석 ID: ${jobId.substring(0,8)}...` : "분석 선택 안됨");

    useEffect(() => {
        if (!jobId) {
            setMessages([]);
            return;
        }
        
        setIsLoadingHistroy(true);
        setMessages([]);

        const timer = setTimeout(() => {
            setMessages([
                { from: 'agent', text: `안녕하세요! "${displayName}" 분석에 대해 무엇이 궁금하신가요?`}
            ]);
            setIsLoadingHistroy(false);
        }, 300);

        return () => clearInterval(timer);
    }, [jobId, displayName]);

    const handleSendChat = async () => {
        if(!input.trim() || !jobId || isAiThinking) return;
        const userInput = input;
        setInput('');

        setMessages((prev) => [
            ...prev,
            { from: 'user', text: userInput },
            { from: 'agent', text: 'AI 에이전트가 분석 중입니다...'}
        ]);
        setIsAiThinking(true);

        try{
            const response = await getAiChatResponse(jobId, userInput);

            updateChatData(response.mainData);

            setMessages((prev) => [
                ...prev.slice(0, -1),
                { from: 'agent', text: response.summary }
            ]);
        } catch (err){
            console.error("AI 채팅 실패:", err);
            setMessages((prev) => [
                { from: 'agent', text: '죄송합니다. AI 에이전트 응답에 실패했습니다.' }
            ]);
        }finally{
            setIsAiThinking(false);
        }
    };

    return(
        <aside className='border-l border-border rounded-lg p-3 flex flex-col bg-gray-50 min-h-0'>
            <div className='text-sm font-medium text-text-main'>Ask the Security Agent</div>
            <div className='text-xs text-text-muted mb-1 truncate'>
                컨텍스트: <code className='font-semibold'>{ displayName }</code>
            </div>

            <div className='flex-1 overflow-y-auto flex flex-col gap-1.5 text-sm py-2'>
                {isLoadingHistory ? (
                    <div className='text-center text-xs text-text-muted p-4'>
                        `{displayName}` 채팅 내역 로딩 중...
                    </div>
                ) : (

                    messages.map((msg, index) => (
                        <div
                        key={index}
                        className={`p-2.5 rounded-xl max-w-full leading-snug
                            ${msg.from === 'agent'
                                ? 'bg-primary-soft text-primary-text'
                                : 'bg-white border border-border text-text-main self-end'
                            }`}
                        >
                            {msg.text}
                        </div>
                    ))
                )}
            </div>

            <div className='border-t border-border pt-2 mt-1 flex gap-1.5 items-center'>
                <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder={jobId ? "예 : RCE 가능성만 필터링..." : "분석을 선택하세요"}
                    disabled={!jobId || isLoadingHistory || isAiThinking}
                    className='flex-1 resize-none rounded-full border border-border bg-white px-3 py-2 text-sm h-10 outline-none'
                    rows={1}
                />
                <button
                    onClick={handleSendChat}
                    disabled={!jobId || isLoadingHistory || isAiThinking}
                    className='p-2.5 rounded-full bg-primary text-white h-10 w-10 flex-shrink-0'
                >
                    {isAiThinking ? "..." : <span className='text-lg leading-none'>⮞</span>}
                </button>
            </div>
        </aside>
    )
}