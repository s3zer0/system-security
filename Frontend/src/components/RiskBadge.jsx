import React from 'react'

export default function RiskBadge({ level }){
    const levelStyles = {
        CRITICAL: 'bg-risk-CRITICAL-bg text-risk-CRITICAL-text',
        HIGH: 'bg-risk-HIGH-bg text-risk-HIGH-text',
        MEDIUM: 'bg-risk-MEDIUM-bg text-risk-MEDIUM-text',
        LOW: 'bg-risk-LOW-bg text-risk-LOW-text',
        INFO: 'bg-risk-INFO-bg text-risk-INFO-text',
        NA: 'bg-risk-NA-bg text-risk-NA-text',
        IMMEDIATE: 'bg-risk-IMMEDIATE-bg text-risk-IMMEDIATE-text',
        PLANNED: 'bg-risk-PLANNED-bg text-risk-PLANNED-text',
    };
    const baseStyle = 'px-1.5 py-0.5 rounded-full text-[10px] font-semibold';
    const style = levelStyles[level] || levelStyles.NA;

    return (
        <span className={`${baseStyle} ${style}`}>
            {level}
        </span>
    )
}