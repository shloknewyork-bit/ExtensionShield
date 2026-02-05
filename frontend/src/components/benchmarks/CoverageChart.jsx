import React from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

const CoverageChart = ({ data }) => {
  // Category definitions for tooltips
  const categoryDefinitions = {
    'Governance': 'Policy/auditability & transparency signals',
    'Privacy': 'Data collection + tracking surface signals',
    'Evidence': 'Reproducible artifacts (hashes, rule hits, IOCs)',
    'ToS Compliance': 'Store policy/deception risk indicators',
    'Reputation': 'Reviews + store reputation signals'
  };

  // Transform data for Recharts, mapping "Reviews" to "Reputation" for display
  const categories = Object.keys(data.extensionshield);
  const formattedData = categories.map(category => {
    const displayCategory = category === 'Reviews' ? 'Reputation' : category;
    return {
      category: displayCategory,
      originalCategory: category, // Keep original for data lookup
      ExtensionShield: data.extensionshield[category],
      'Competitor A': data.competitor_a[category],
      'Competitor B': data.competitor_b[category]
    };
  });

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const definition = categoryDefinitions[label];
      return (
        <div style={{
          background: 'rgba(10, 15, 26, 0.95)',
          border: '1px solid rgba(34, 197, 94, 0.3)',
          borderRadius: '8px',
          padding: '12px',
          color: '#f8fafc'
        }}>
          <p style={{ margin: 0, fontWeight: 600, marginBottom: '8px' }}>{label}</p>
          {definition && (
            <p style={{ 
              margin: '0 0 8px 0', 
              fontSize: '0.75rem', 
              color: '#94a3b8',
              fontStyle: 'italic',
              borderBottom: '1px solid rgba(148, 163, 184, 0.2)',
              paddingBottom: '8px'
            }}>
              {definition}
            </p>
          )}
          {payload.map((entry, index) => (
            <p key={index} style={{ margin: '4px 0', color: entry.color, fontSize: '0.875rem' }}>
              {entry.name}: {entry.value}%
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  // Custom tick component for wrapping text
  const CustomXAxisTick = ({ x, y, payload }) => {
    return (
      <g transform={`translate(${x},${y})`}>
        <text
          x={0}
          y={0}
          dy={10}
          textAnchor="middle"
          fill="#64748b"
          fontSize="0.75rem"
        >
          {payload.value}
        </text>
      </g>
    );
  };

  return (
    <div style={{ width: '100%' }}>
      <h4 style={{ 
        fontSize: '0.9375rem', 
        fontWeight: 600, 
        marginBottom: '0.5rem',
        color: '#f8fafc'
      }}>
        Supported Signals by Category
      </h4>
      <p style={{
        fontSize: '0.8125rem',
        color: '#94a3b8',
        marginBottom: '1rem',
        lineHeight: 1.5
      }}>
        Higher = more checks/signals implemented in that category (not accuracy, not intent).
      </p>
      <ResponsiveContainer width="100%" height={400}>
        <BarChart 
          data={formattedData} 
          margin={{ top: 5, right: 30, left: 20, bottom: 60 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.1)" />
          <XAxis 
            dataKey="category" 
            stroke="#64748b"
            tick={<CustomXAxisTick />}
            height={60}
            interval={0}
          />
          <YAxis 
            stroke="#64748b"
            style={{ fontSize: '0.75rem' }}
            domain={[0, 100]}
            label={{ value: 'Signals supported (0–100)', angle: -90, position: 'insideLeft', style: { fill: '#64748b' } }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            wrapperStyle={{ paddingTop: '20px', fontSize: '0.875rem' }}
            iconType="square"
          />
          <Bar 
            dataKey="ExtensionShield" 
            fill="#22c55e"
            radius={[4, 4, 0, 0]}
            style={{ cursor: 'pointer' }}
          />
          <Bar 
            dataKey="Competitor A" 
            fill="#8b5cf6"
            radius={[4, 4, 0, 0]}
            style={{ cursor: 'pointer' }}
          />
          <Bar 
            dataKey="Competitor B" 
            fill="#3b82f6"
            radius={[4, 4, 0, 0]}
            style={{ cursor: 'pointer' }}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default CoverageChart;

