import React from 'react'

export default function RiskBadge({ level }) {
    // Normalize level from uppercase (CRITICAL) to Titlecase (Critical)
    const normalizedLevel = level
        ? level.charAt(0).toUpperCase() + level.slice(1).toLowerCase()
        : 'Info';

    const levelStyles = {
        CRITICAL: 'bg-red-100 text-risk-CRITICAL-text',
        HIGH: 'bg-orange-100 text-risk-HIGH-text',
        MEDIUM: 'bg-yellow-100 text-risk-MEDIUM-text',
        LOW: 'bg-green-100 text-risk-LOW-text',
        SAFE: 'bg-blue-100 text-risk-SAFE-text'
    };
    const baseStyle = 'px-1.5 py-0.5 rounded-full text-[10px] font-semibold';
    const style = levelStyles[level] || levelStyles.SAFE;

    return (
        <span className={`${baseStyle} ${style}`}>
            {normalizedLevel}
        </span>
    )
}