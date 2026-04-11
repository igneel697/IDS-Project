import React, { useState, useEffect } from 'react';
import AlertsPage from './pages/AlertsPage';
import StatsPage from './pages/StatsPage';
import { getSummary } from './api';
import './App.css';

function App() {
  const [page, setPage]           = useState('alerts');
  const [alertCount, setAlertCount] = useState(null);
  const [prevCount, setPrevCount]   = useState(null);
  const [newAlerts, setNewAlerts]   = useState(false);

  // Poll alert count every 10 seconds
  useEffect(() => {
    const fetchCount = async () => {
      try {
        const res = await getSummary();
        const count = res.data.total_alerts;
        if (prevCount !== null && count > prevCount) {
          setNewAlerts(true);
          setTimeout(() => setNewAlerts(false), 3000);
        }
        setPrevCount(count);
        setAlertCount(count);
      } catch (e) {}
    };
    fetchCount();
    const interval = setInterval(fetchCount, 10000);
    return () => clearInterval(interval);
  }, [prevCount]);

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-brand">
          <span className="nav-icon">🛡️</span>
          <span>IDS Dashboard</span>
          {newAlerts && (
            <span style={{
              background: '#fc8181', color: 'white',
              fontSize: '0.7rem', padding: '0.1rem 0.4rem',
              borderRadius: '4px', marginLeft: '0.5rem'
            }}>
              NEW
            </span>
          )}
        </div>
        <div className="nav-links">
          <button
            className={page === 'alerts' ? 'nav-btn active' : 'nav-btn'}
            onClick={() => setPage('alerts')}
          >
            Alerts {alertCount !== null ? `(${alertCount})` : ''}
          </button>
          <button
            className={page === 'stats' ? 'nav-btn active' : 'nav-btn'}
            onClick={() => setPage('stats')}
          >
            Statistics
          </button>
        </div>
      </nav>

      <main className="main-content">
        {page === 'alerts' ? <AlertsPage /> : <StatsPage />}
      </main>
    </div>
  );
}

export default App;