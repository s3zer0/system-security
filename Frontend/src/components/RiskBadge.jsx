import React from 'react'

export default function RiskBadge({ level }) {
    // Normalize level from uppercase (CRITICAL) to Titlecase (Critical) for display
    const normalizedLevel = level
        ? level.charAt(0).toUpperCase() + level.slice(1).toLowerCase()
        : 'Info';

    // Convert to uppercase for consistent style lookup
    const levelKey = level ? level.toUpperCase() : 'SAFE';

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
    const style = levelStyles[levelKey] || levelStyles.SAFE;

    return (
        <span className={`${baseStyle} ${style}`}>
            {normalizedLevel}
        </span>
    )
}