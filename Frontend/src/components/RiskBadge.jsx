import React from 'react'

export default function RiskBadge({ level }){
    const levelStyles = {
        Critical: 'bg-red-100 text-risk-Critical-text',
        High: 'bg-orange-100 text-risk-High-text',
        Medium: 'bg-yellow-100 text-risk-Medium-text',
        Low: 'bg-green-100 text-risk-Low-text',
        Info: 'bg-blue-100 text-risk-Info-text'
    };
    const baseStyle = 'px-1.5 py-0.5 rounded-full text-[10px] font-semibold';
    const style = levelStyles[level] || levelStyles.Info;

    return (
        <span className={`${baseStyle} ${style}`}>
            {level}
        </span>
    )
}