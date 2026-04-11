import React, { useState, useEffect } from 'react';
import { getAlerts } from '../api';
import AlertBadge from '../components/AlertBadge';

function AlertsPage() {
  const [alerts, setAlerts]     = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [filter, setFilter]     = useState('all');
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchAlerts = async () => {
    try {
      setError(null);
      const params = filter !== 'all' ? { severity: filter } : {};
      const res    = await getAlerts({ ...params, limit: 100 });
      setAlerts(res.data.alerts);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      setError('Failed to load alerts. Is the Flask API running?');
    } finally {
      setLoading(false);
    }
  };

  // Fetch on load and when filter changes
  useEffect(() => {
    fetchAlerts();
  }, [filter]);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, [filter]);

  const formatTime = (timestamp) => {
    if (!timestamp) return '—';
    return new Date(timestamp).toLocaleString();
  };

  const severityFilters = ['all', 'Critical', 'High', 'Medium', 'Low'];

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">🚨 Alerts</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          {lastUpdated && (
            <span style={{ color: '#a0aec0', fontSize: '0.85rem' }}>
              Last updated: {lastUpdated}
            </span>
          )}
          <button className="refresh-btn" onClick={fetchAlerts}>
            Refresh
          </button>
        </div>
      </div>

      {/* Severity filter buttons */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        {severityFilters.map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={filter === f ? 'nav-btn active' : 'nav-btn'}
          >
            {f === 'all' ? 'All' : f}
          </button>
        ))}
      </div>

      {error && <div className="error">{error}</div>}

      <div className="card">
        <div className="card-title">
          {alerts.length} alert{alerts.length !== 1 ? 's' : ''}
          {filter !== 'all' ? ` — ${filter}` : ''}
        </div>

        {loading ? (
          <div className="loading">Loading alerts...</div>
        ) : alerts.length === 0 ? (
          <div className="loading">No alerts found.</div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Target</th>
                  <th>Attack Type</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Method</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(alert => (
                  <tr key={alert.alert_id}>
                    <td style={{ whiteSpace: 'nowrap' }}>
                      {formatTime(alert.timestamp)}
                    </td>
                    <td>{alert.source_ip}</td>
                    <td>
                      {alert.dest_ip}
                      {alert.dest_port ? `:${alert.dest_port}` : ''}
                    </td>
                    <td style={{ textTransform: 'uppercase', fontWeight: 600 }}>
                      {alert.attack_type}
                    </td>
                    <td>
                      <AlertBadge severity={alert.severity} />
                    </td>
                    <td>
                      <span style={{
                        color: alert.risk_score >= 86 ? '#fc8181' :
                               alert.risk_score >= 61 ? '#f6ad55' :
                               alert.risk_score >= 31 ? '#f6e05e' : '#68d391'
                      }}>
                        {alert.risk_score}/100
                      </span>
                    </td>
                    <td style={{ textTransform: 'uppercase', fontSize: '0.8rem' }}>
                      {alert.detection_method}
                    </td>
                    <td style={{ color: '#a0aec0', fontSize: '0.85rem', maxWidth: '250px' }}>
                      {alert.additional_context}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default AlertsPage;
