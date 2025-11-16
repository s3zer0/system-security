import React, { useState } from 'react'

export default function ChatPanel(){
    const [messages, setMessages] = useState([
        { from: 'agent', text: '봇 초기 메시지입니다.' },
        { from: 'user', text: '사용자 초기 메시지입니다.' },
    ]);
    const [input, setInput] = useState('');

    const handleSendChat = () => {
        if(!input.trim()) return;
        setMessages([
            ...messages,
            { from: 'user', text: input },
            { from: 'agent', text: '데모 응답입니다.' },
        ]);
        setInput('');
    };

    return(
        <aside className='border border-border rounded-lg p-3 flex flex-col bg-gray-50 h-[600px] w-[320px]'>
            <div className='text-sm font-medium text-text-main'>Ask the Security Agent</div>
            <div className='text-xs text-text-muted mb-1'>
                컨텍스트: <code>test-id</code>
            </div>

            <div className='flex-1 overflow-y-auto flex flex-col gap-1.5 text-sm py-2'>
                {messages.map((msg, index) => (
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
                ))}
            </div>

            <div className='border-t border-border pt-2 mt-1 flex gap-1.5 items-center'>
                <textarea
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder='예 : RCE 가능성만 필터링...'
                    className='flex-1 resize-none rounded-full border border-border bg-white px-3 py-2 text-sm h-10 outline-none'
                    rows={1}
                />
                <button
                    onClick={handleSendChat}
                    className='p-2.5 rounded-full bg-primary text-white h-10 w-10 flex-shrink-0'
                    >
                    <span className='text-lg leading-none'>⮞</span>
                </button>
            </div>
        </aside>
    )
}