import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';

export default function ChatPanel(){

    const { jobId } = useParams();

    const [messages, setMessages] = useState([]);
    const [input, setInput] = useState('');

    const [isLoadingHistory, setIsLoadingHistroy] = useState(false);

    useEffect(() => {
        if (!jobId) {
            setMessages([]);
            return;
        }
        
        setIsLoadingHistroy(true);
        setTimeout(() => {
            setMessages([
                { from: 'agent', text: `안녕하세요! "${jobId}" 분석에 대해 무엇이 궁금하신가요?`}
            ]);
            setIsLoadingHistroy(false);
        }, 300);
    }, [jobId]);

    const handleSendChat = async () => {
        if(!input.trim()) return;
        const userInput = input;
        setInput('');

        setMessages((prev) => [
            ...prev,
            { from: 'user', text: userInput }
        ]);

        const mockResponse = `"${jobId}"에 대해 "${userInput}"라고 질문하셨네요. (데모 응답)`;
        setMessages((prev) => [
            ...prev,
            { from: 'agent', text: mockResponse }
        ]);
    };

    return(
        <aside className='border border-border rounded-lg p-3 flex flex-col bg-gray-50 h-[600px] w-[320px]'>
            <div className='text-sm font-medium text-text-main'>Ask the Security Agent</div>
            <div className='text-xs text-text-muted mb-1 truncate'>
                컨텍스트: <code className='font-semibold'>{ jobId || "분석 선택 안됨" }</code>
            </div>

            <div className='flex-1 overflow-y-auto flex flex-col gap-1.5 text-sm py-2'>
                {isLoadingHistory ? (
                    <div className='text-center text-xs text-text-muted p-4'>
                        `{jobId}` 채팅 내역 로딩 중...
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
                    className='flex-1 resize-none rounded-full border border-border bg-white px-3 py-2 text-sm h-10 outline-none'
                    rows={1}
                />
                <button
                    onClick={handleSendChat}
                    disabled={!jobId || isLoadingHistory}
                    className='p-2.5 rounded-full bg-primary text-white h-10 w-10 flex-shrink-0'
                >
                    <span className='text-lg leading-none'>⮞</span>
                </button>
            </div>
        </aside>
    )
}