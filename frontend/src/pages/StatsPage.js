import React, { useState, useEffect } from 'react';
import {
  PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer
} from 'recharts';
import { getSummary, getTimeline } from '../api';

// Colours for the pie chart
const COLOURS = ['#fc8181', '#f6ad55', '#f6e05e', '#68d391', '#63b3ed', '#b794f4'];

function StatsPage() {
  const [summary, setSummary]   = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);

  const fetchData = async () => {
    try {
      setError(null);
      const [sumRes, timeRes] = await Promise.all([getSummary(), getTimeline()]);
      setSummary(sumRes.data);
      setTimeline(timeRes.data.timeline);
    } catch (err) {
      setError('Failed to load statistics. Is the Flask API running?');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="loading">Loading statistics...</div>;
  if (error)   return <div className="error">{error}</div>;

  // Format attack type data for pie chart
  const attackData = summary?.by_attack?.map(item => ({
    name:  item.attack_type.toUpperCase(),
    value: item.count
  })) || [];

  // Format severity data for bar chart
  const severityData = summary?.by_severity?.map(item => ({
    name:  item.severity,
    count: item.count
  })) || [];

  // Format timeline data
  const timelineData = timeline.map(item => ({
    hour:  item.hour ? item.hour.substring(11, 16) : '',
    count: item.count
  }));

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">📊 Statistics</h1>
        <button className="refresh-btn" onClick={fetchData}>Refresh</button>
      </div>

      {/* Summary numbers */}
      <div className="stat-grid">
        <div className="stat-box">
          <div className="stat-number">{summary?.total_alerts || 0}</div>
          <div className="stat-label">Total Alerts</div>
        </div>
        <div className="stat-box">
          <div className="stat-number" style={{ color: '#fc8181' }}>
            {summary?.by_severity?.find(s => s.severity === 'Critical')?.count || 0}
          </div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-box">
          <div className="stat-number" style={{ color: '#f6ad55' }}>
            {summary?.by_severity?.find(s => s.severity === 'High')?.count || 0}
          </div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-box">
          <div className="stat-number" style={{ color: '#f6e05e' }}>
            {summary?.avg_risk_score || 0}
          </div>
          <div className="stat-label">Avg Risk Score</div>
        </div>
        <div className="stat-box">
          <div className="stat-number" style={{ color: '#68d391' }}>
            {summary?.by_method?.find(m => m.detection_method === 'rule')?.count || 0}
          </div>
          <div className="stat-label">Rule Detections</div>
        </div>
        <div className="stat-box">
          <div className="stat-number" style={{ color: '#b794f4' }}>
            {summary?.by_method?.find(m => m.detection_method === 'ml')?.count || 0}
          </div>
          <div className="stat-label">ML Detections</div>
        </div>
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>

        {/* Attack type pie chart */}
        <div className="card">
          <div className="card-title">Attack Types</div>
          {attackData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={attackData}
                  cx="50%" cy="50%"
                  outerRadius={100}
                  dataKey="value"
                  label={({ name, percent }) =>
                    `${name} ${(percent * 100).toFixed(0)}%`
                  }
                >
                  {attackData.map((_, i) => (
                    <Cell key={i} fill={COLOURS[i % COLOURS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#1a1d2e', border: '1px solid #2d3748' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="loading">No data yet</div>
          )}
        </div>

        {/* Severity bar chart */}
        <div className="card">
          <div className="card-title">Alerts by Severity</div>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
                <XAxis dataKey="name" stroke="#a0aec0" />
                <YAxis stroke="#a0aec0" />
                <Tooltip
                  contentStyle={{ background: '#1a1d2e', border: '1px solid #2d3748' }}
                />
                <Bar dataKey="count" fill="#63b3ed" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="loading">No data yet</div>
          )}
        </div>
      </div>

      {/* Timeline chart */}
      {timelineData.length > 0 && (
        <div className="card">
          <div className="card-title">Alert Timeline (Last 24 Hours)</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={timelineData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2d3748" />
              <XAxis dataKey="hour" stroke="#a0aec0" />
              <YAxis stroke="#a0aec0" />
              <Tooltip
                contentStyle={{ background: '#1a1d2e', border: '1px solid #2d3748' }}
              />
              <Bar dataKey="count" fill="#b794f4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

export default StatsPage;
