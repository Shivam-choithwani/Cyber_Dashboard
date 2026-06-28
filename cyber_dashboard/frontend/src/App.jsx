import React, { useState, useEffect, useRef } from 'react';

// Configuration
const BACKEND_HTTP_URL = 'http://localhost:8001';
const BACKEND_WS_URL = 'ws://localhost:8001/ws';
const ECOMMERCE_API_URL = 'http://localhost:8000';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [events, setEvents] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [stats, setStats] = useState({
    total_events: 0,
    total_anomalies: 0,
    anomaly_rate: 0,
    avg_latency: 0,
    status_distribution: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 },
    anomalies_by_type: {},
    top_ips: [],
    slowest_paths: []
  });
  
  const [wsStatus, setWsStatus] = useState('disconnected');
  const [flashScreen, setFlashScreen] = useState(false);
  const [selectedLog, setSelectedLog] = useState(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  
  // Rules Settings State
  const [settings, setSettings] = useState({
    zScoreThreshold: 3.5,
    rateLimitThreshold: 40,
    bruteForceLimit: 5,
    scanningLimit: 10
  });

  const wsRef = useRef(null);
  const chartContainerRef = useRef(null);

  // Fetch initial data
  const fetchData = async () => {
    try {
      const statsRes = await fetch(`${BACKEND_HTTP_URL}/api/stats`);
      const statsData = await statsRes.json();
      if (!statsData.error) setStats(statsData);

      const eventsRes = await fetch(`${BACKEND_HTTP_URL}/api/events?limit=100`);
      const eventsData = await eventsRes.json();
      setEvents(eventsData);

      const anomaliesRes = await fetch(`${BACKEND_HTTP_URL}/api/anomalies?limit=100`);
      const anomaliesData = await anomaliesRes.json();
      setAnomalies(anomaliesData);
    } catch (error) {
      console.error("Error loading initial dashboard data:", error);
    }
  };

  // Setup WebSocket connection
  const connectWebSocket = () => {
    setWsStatus('connecting');
    const ws = new WebSocket(BACKEND_WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsStatus('connected');
      console.log('WebSocket connection established.');
    };

    ws.onmessage = (message) => {
      const payload = JSON.parse(message.data);
      if (payload.type === 'log_event') {
        setEvents(prev => [payload.event, ...prev.slice(0, 99)]);
        // Incrementally update quick metrics to keep UI immediate
        setStats(prev => {
          const status = payload.event.status_code;
          let statusGrp = '2xx';
          if (status >= 500) statusGrp = '5xx';
          else if (status >= 400) statusGrp = '4xx';
          else if (status >= 300) statusGrp = '3xx';
          
          const newTotal = prev.total_events + 1;
          const newRate = ((prev.total_anomalies / newTotal) * 100).toFixed(2);
          
          return {
            ...prev,
            total_events: newTotal,
            anomaly_rate: parseFloat(newRate),
            status_distribution: {
              ...prev.status_distribution,
              [statusGrp]: prev.status_distribution[statusGrp] + 1
            }
          };
        });
      } else if (payload.type === 'anomaly_alert') {
        const anomaly = payload.anomaly;
        setAnomalies(prev => [anomaly, ...prev.slice(0, 99)]);
        
        // Trigger alert visual flashing
        if (anomaly.severity === 'CRITICAL' || anomaly.severity === 'HIGH') {
          setFlashScreen(true);
          setTimeout(() => setFlashScreen(false), 1500);
        }

        setStats(prev => {
          const newAnoms = prev.total_anomalies + 1;
          const newRate = ((newAnoms / prev.total_events) * 100).toFixed(2);
          const newTypes = { ...prev.anomalies_by_type };
          newTypes[anomaly.anomaly_type] = (newTypes[anomaly.anomaly_type] || 0) + 1;
          
          return {
            ...prev,
            total_anomalies: newAnoms,
            anomaly_rate: parseFloat(newRate),
            anomalies_by_type: newTypes
          };
        });
      }
    };

    ws.onclose = () => {
      setWsStatus('disconnected');
      console.log('WebSocket disconnected. Reconnecting in 3s...');
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
      ws.close();
    };
  };

  useEffect(() => {
    fetchData();
    connectWebSocket();
    
    // Poll stats occasionally to get calculated averages and distributions
    const interval = setInterval(fetchData, 10000);

    return () => {
      clearInterval(interval);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Attack Simulations
  const simulateAttack = async (type) => {
    try {
      console.log(`Starting simulation: ${type}`);
      if (type === 'SQLI') {
        await fetch(`${ECOMMERCE_API_URL}/products/slug/test-slug?q=%27%20UNION%20SELECT%20*%20FROM%20users%20--`);
      } else if (type === 'XSS') {
        await fetch(`${ECOMMERCE_API_URL}/products/slug/test-slug?q=%3Cscript%3Ealert(%27hacked%27)%3C/script%3E`);
      } else if (type === 'BRUTE') {
        // Run 5 failed logins rapidly
        for (let i = 0; i < 5; i++) {
          fetch(`${ECOMMERCE_API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: 'malicious_actor@verify.dev', password: `wrong-pass-${i}` })
          }).catch(() => {});
          await new Promise(r => setTimeout(r, 100));
        }
      } else if (type === 'SCANNER') {
        // Hit 12 non-existent paths rapidly to trigger 404 alarms
        const paths = ['/wp-admin', '/phpmyadmin', '/.env', '/config.json', '/setup.php', '/admin-login', '/db.sql', '/backup.tar.gz', '/config/db', '/v1/users', '/shell.sh', '/secret'];
        for (const p of paths) {
          fetch(`${ECOMMERCE_API_URL}${p}`).catch(() => {});
          await new Promise(r => setTimeout(r, 80));
        }
      } else if (type === 'SLOW') {
        // High latency event simulation (trigger endpoint or delay request)
        // verify_endpoints cleanup runs multiple db queries which can take some milliseconds,
        // or we hit '/' public endpoint continuously, or we let z-score detect baseline outliers normally.
        // We'll just alert the user that high latency anomaly activates on any route taking >3.5 stddev.
        alert("Latency anomalies are calculated in real-time. Make multiple slow requests manually to flag Z-Score latency spikes!");
      }
    } catch (err) {
      console.error("Simulation failed:", err);
    }
  };

  // Helper to format timestamps nicely
  const formatTime = (isoString) => {
    if (!isoString) return '';
    const date = new Date(isoString);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  // Render SVG Chart using SVG coordinates
  const renderSVGChart = () => {
    // Generate data points from the last 15 seconds or group events
    // For visual simulation, we project the status log over 10 ticks
    const pointsCount = 10;
    const ticks = Array.from({ length: pointsCount }).map((_, idx) => idx);
    
    const width = 600;
    const height = 180;
    const padding = 20;
    
    const getCoordinates = (dataList, maxVal = 10) => {
      if (dataList.length === 0) return [];
      
      const step = (width - padding * 2) / (pointsCount - 1);
      const values = Array(pointsCount).fill(0);
      
      // Populate coordinates mapping
      dataList.forEach((item, index) => {
        const bin = Math.min(Math.floor(index / (dataList.length / pointsCount)), pointsCount - 1);
        values[bin] += 1;
      });

      const maxObserved = Math.max(...values, 1);
      const points = values.map((val, idx) => {
        const x = padding + idx * step;
        // project Y coordinate inverted (since 0,0 is top-left in SVG)
        const y = height - padding - (val / maxObserved) * (height - padding * 2);
        return `${x},${y}`;
      });
      
      return points;
    };

    const logPoints = getCoordinates(events.slice(0, 15).reverse());
    const anomalyPoints = getCoordinates(anomalies.slice(0, 15).reverse());

    const logPathD = logPoints && logPoints.length ? `M ${logPoints.join(' L ')}` : '';
    const anomalyPathD = anomalyPoints && anomalyPoints.length ? `M ${anomalyPoints.join(' L ')}` : '';

    // Area Paths
    const logAreaD = logPoints ? `${logPathD} L ${width - padding},${height - padding} L ${padding},${height - padding} Z` : '';
    const anomalyAreaD = anomalyPoints ? `${anomalyPathD} L ${width - padding},${height - padding} L ${padding},${height - padding} Z` : '';

    return (
      <svg className="svg-chart" viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <linearGradient id="chartGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--neon-blue)" stopOpacity="0.4"/>
            <stop offset="100%" stopColor="var(--neon-blue)" stopOpacity="0"/>
          </linearGradient>
          <linearGradient id="chartGradientSecondary" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--neon-pink)" stopOpacity="0.3"/>
            <stop offset="100%" stopColor="var(--neon-pink)" stopOpacity="0"/>
          </linearGradient>
        </defs>
        
        {/* Grid lines */}
        <line x1={padding} y1={padding} x2={width-padding} y2={padding} className="chart-grid-line" />
        <line x1={padding} y1={height/2} x2={width-padding} y2={height/2} className="chart-grid-line" />
        <line x1={padding} y1={height-padding} x2={width-padding} y2={height-padding} className="chart-grid-line" />

        {/* Areas */}
        {logAreaD && <path d={logAreaD} className="chart-area" />}
        {anomalyAreaD && <path d={anomalyAreaD} className="chart-area-secondary" />}

        {/* Lines */}
        {logPathD && <path d={logPathD} className="chart-path-line" />}
        {anomalyPathD && <path d={anomalyPathD} className="chart-path-line-secondary" />}

        {/* Data points */}
        {logPoints && logPoints.map((pt, idx) => {
          const [x, y] = pt.split(',');
          return <circle key={`log-dot-${idx}`} cx={x} cy={y} r="4" className="chart-dot" />;
        })}
        {anomalyPoints && anomalyPoints.map((pt, idx) => {
          const [x, y] = pt.split(',');
          return <circle key={`anom-dot-${idx}`} cx={x} cy={y} r="4" className="chart-dot-secondary" />;
        })}
      </svg>
    );
  };

  // Filters for events and anomalies
  const filteredEvents = events.filter(e => {
    const query = searchQuery.toLowerCase();
    return (
      e.path?.toLowerCase().includes(query) ||
      e.ip_address?.toLowerCase().includes(query) ||
      e.method?.toLowerCase().includes(query) ||
      e.status_code?.toString().includes(query)
    );
  });

  const filteredAnomalies = anomalies.filter(a => {
    const severityMatches = severityFilter === 'ALL' || a.severity === severityFilter;
    const query = searchQuery.toLowerCase();
    const queryMatches = (
      a.description?.toLowerCase().includes(query) ||
      a.ip_address?.toLowerCase().includes(query) ||
      a.anomaly_type?.toLowerCase().includes(query)
    );
    return severityMatches && queryMatches;
  });

  return (
    <div className={`app-container ${flashScreen ? 'app-flash-critical' : ''}`}>
      
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-container">
          <div className="logo-icon">Æ</div>
          <span className="logo-text">AETHER SECURE</span>
        </div>

        <nav>
          <ul className="nav-links">
            <li className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="9"></rect><rect x="14" y="3" width="7" height="5"></rect><rect x="14" y="12" width="7" height="9"></rect><rect x="3" y="16" width="7" height="5"></rect></svg>
              Overview
            </li>
            <li className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`} onClick={() => { setActiveTab('logs'); setSearchQuery(''); }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              Log Stream
            </li>
            <li className={`nav-item ${activeTab === 'anomalies' ? 'active' : ''}`} onClick={() => { setActiveTab('anomalies'); setSearchQuery(''); }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
              Threat Center
            </li>
            <li className={`nav-item ${activeTab === 'rules' ? 'active' : ''}`} onClick={() => setActiveTab('rules')}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
              Security Rules
            </li>
          </ul>
        </nav>

        {/* Real-time Connection Health */}
        <div className="status-panel">
          <div className="status-row">
            <span>Kafka Ingestion</span>
            <span className={`status-indicator ${wsStatus === 'connected' ? 'connected' : wsStatus === 'connecting' ? 'connecting' : 'disconnected'}`}></span>
          </div>
          <div className="status-row">
            <span>E-Commerce API</span>
            <span className="status-indicator connected"></span>
          </div>
          <div className="status-row" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            <span>Telemetry Broker Port: 9092</span>
          </div>
        </div>
      </aside>

      {/* Main Panel Content */}
      <main className="main-content">
        
        {/* Header Section */}
        <header className="header">
          <div className="header-title">
            <h1>Cyber Threat Analytics Dashboard</h1>
            <p>Real-time anomaly detection and log streaming console</p>
          </div>
          <div className="header-actions">
            <div className="glass-card" style={{ padding: '8px 16px', display: 'flex', gap: '8px', fontSize: '14px', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-secondary)' }}>System Time:</span>
              <span style={{ fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        </header>

        {/* Metric Cards Row */}
        <section className="metrics-grid">
          <div className="glass-card metric-card">
            <div className="metric-details">
              <p>Logs Ingested</p>
              <h3>{stats.total_events}</h3>
            </div>
            <div className="metric-icon metric-blue">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="21" y1="10" x2="3" y2="10"></line><line x1="21" y1="6" x2="3" y2="6"></line><line x1="21" y1="14" x2="3" y2="14"></line><line x1="21" y1="18" x2="3" y2="18"></line></svg>
            </div>
          </div>

          <div className="glass-card metric-card">
            <div className="metric-details">
              <p>Threat Alerts</p>
              <h3 style={{ color: stats.total_anomalies > 0 ? 'var(--neon-pink)' : 'inherit' }}>{stats.total_anomalies}</h3>
            </div>
            <div className="metric-icon metric-pink">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"></polygon><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            </div>
          </div>

          <div className="glass-card metric-card">
            <div className="metric-details">
              <p>Avg Latency Baseline</p>
              <h3>{stats.avg_latency} ms</h3>
            </div>
            <div className="metric-icon metric-green">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            </div>
          </div>

          <div className="glass-card metric-card">
            <div className="metric-details">
              <p>Telemetry Ratio</p>
              <h3>{stats.anomaly_rate}%</h3>
            </div>
            <div className="metric-icon metric-purple">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
            </div>
          </div>
        </section>

        {/* Tab 1: Dashboard Overview */}
        {activeTab === 'dashboard' && (
          <>
            <div className="dashboard-grid">
              
              {/* Traffic Volume Chart */}
              <div className="glass-card" style={{ gridColumn: 'span 2' }}>
                <div className="panel-header">
                  <h3 className="panel-title">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                    Real-time Ingestion Stream Activity
                  </h3>
                  <div className="chart-legend">
                    <div className="legend-item"><span className="legend-color" style={{ background: 'var(--neon-blue)' }}></span> Log Throughput</div>
                    <div className="legend-item"><span className="legend-color" style={{ background: 'var(--neon-pink)' }}></span> Flagged Anomalies</div>
                  </div>
                </div>
                <div className="chart-container" ref={chartContainerRef}>
                  {renderSVGChart()}
                </div>
              </div>
            </div>

            <div className="dashboard-grid">
              
              {/* Live Log Stream Snippet */}
              <div className="glass-card">
                <div className="panel-header">
                  <h3 className="panel-title">
                    <span className="status-indicator connected" style={{ marginRight: '6px' }}></span>
                    Recent API Logs
                  </h3>
                  <button className="nav-item" style={{ background: 'none', border: 'none', padding: 0, fontSize: '13px' }} onClick={() => setActiveTab('logs')}>
                    View All
                  </button>
                </div>
                <div className="table-container">
                  <table className="custom-table">
                    <thead>
                      <tr>
                        <th>Method</th>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {events.slice(0, 7).map((e, index) => (
                        <tr key={index} onClick={() => setSelectedLog(e)}>
                          <td><span className={`badge badge-${e.method?.toLowerCase()}`}>{e.method}</span></td>
                          <td style={{ maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'JetBrains Mono', fontSize: '13px' }}>{e.path}</td>
                          <td><span className={`status-badge status-${Math.floor(e.status_code / 100)}xx`}>{e.status_code}</span></td>
                          <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{formatTime(e.timestamp)}</td>
                        </tr>
                      ))}
                      {events.length === 0 && (
                        <tr>
                          <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '24px' }}>No events logged yet.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Anomaly Alerts Snippet */}
              <div className="glass-card">
                <div className="panel-header">
                  <h3 className="panel-title" style={{ color: 'var(--neon-pink)' }}>
                    🚨 Active Threat Alerts
                  </h3>
                  <button className="nav-item" style={{ background: 'none', border: 'none', padding: 0, fontSize: '13px' }} onClick={() => setActiveTab('anomalies')}>
                    Threat Center
                  </button>
                </div>
                
                <div className="anomaly-list">
                  {anomalies.slice(0, 5).map((a, index) => (
                    <div key={index} className={`anomaly-item severity-${a.severity}`} onClick={() => setSelectedAnomaly(a)}>
                      <div className="anomaly-icon-indicator">
                        {a.severity === 'CRITICAL' || a.severity === 'HIGH' ? '☠️' : '⚠️'}
                      </div>
                      <div className="anomaly-body">
                        <div className="anomaly-meta">
                          <span style={{ fontWeight: 700 }}>{a.anomaly_type}</span>
                          <span>{formatTime(a.timestamp)}</span>
                        </div>
                        <p className="anomaly-desc">{a.description}</p>
                      </div>
                    </div>
                  ))}
                  {anomalies.length === 0 && (
                    <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '48px 0' }}>
                      No threats detected. System secure.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </>
        )}

        {/* Tab 2: Full Log Stream Table */}
        {activeTab === 'logs' && (
          <div className="glass-card">
            <div className="panel-header">
              <h3 className="panel-title">Telemetry log Stream</h3>
              <input
                type="text"
                placeholder="Search by Path, IP, Status..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--border-color)',
                  color: 'white',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  outline: 'none',
                  width: '280px'
                }}
              />
            </div>
            
            <div className="table-container">
              <table className="custom-table">
                <thead>
                  <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Status</th>
                    <th>Latency</th>
                    <th>Client IP</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEvents.map((e, index) => (
                    <tr key={index} onClick={() => setSelectedLog(e)}>
                      <td><span className={`badge badge-${e.method?.toLowerCase()}`}>{e.method}</span></td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: '13px' }}>{e.path}</td>
                      <td><span className={`status-badge status-${Math.floor(e.status_code / 100)}xx`}>{e.status_code}</span></td>
                      <td style={{ fontFamily: 'JetBrains Mono' }}>{e.response_time_ms} ms</td>
                      <td style={{ fontFamily: 'JetBrains Mono', fontSize: '13px' }}>{e.ip_address}</td>
                      <td>{e.timestamp ? new Date(e.timestamp).toLocaleString() : ''}</td>
                    </tr>
                  ))}
                  {filteredEvents.length === 0 && (
                    <tr>
                      <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '32px' }}>No matching log items found.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Tab 3: Threat Center */}
        {activeTab === 'anomalies' && (
          <div className="glass-card">
            <div className="panel-header">
              <h3 className="panel-title">Threat Center Intelligence</h3>
              <div style={{ display: 'flex', gap: '16px' }}>
                <select 
                  value={severityFilter} 
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={{
                    background: '#0d121f',
                    border: '1px solid var(--border-color)',
                    color: '#fff',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    outline: 'none'
                  }}
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
                <input
                  type="text"
                  placeholder="Filter threats..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    background: 'rgba(255,255,255,0.05)',
                    border: '1px solid var(--border-color)',
                    color: 'white',
                    padding: '8px 16px',
                    borderRadius: '6px',
                    outline: 'none',
                    width: '240px'
                  }}
                />
              </div>
            </div>

            <div className="anomaly-list" style={{ maxHeight: 'none' }}>
              {filteredAnomalies.map((a, index) => (
                <div key={index} className={`anomaly-item severity-${a.severity}`} onClick={() => setSelectedAnomaly(a)}>
                  <div className="anomaly-icon-indicator" style={{ fontSize: '24px' }}>
                    {a.severity === 'CRITICAL' ? '☠️' : a.severity === 'HIGH' ? '🔥' : '⚠️'}
                  </div>
                  <div className="anomaly-body">
                    <div className="anomaly-meta">
                      <span style={{ fontSize: '15px', fontWeight: 800, color: '#fff' }}>{a.anomaly_type}</span>
                      <span style={{ fontFamily: 'JetBrains Mono' }}>{new Date(a.timestamp).toLocaleString()}</span>
                    </div>
                    <p className="anomaly-desc" style={{ fontSize: '14px', margin: '6px 0 10px 0' }}>{a.description}</p>
                    <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                      <span><strong>Target Path:</strong> <code style={{ color: 'var(--neon-blue)' }}>{a.path}</code></span>
                      <span><strong>Attacker IP:</strong> <code>{a.ip_address}</code></span>
                      <span><strong>Severity:</strong> <span style={{ color: a.severity === 'CRITICAL' ? 'var(--neon-pink)' : a.severity === 'HIGH' ? '#f97316' : 'var(--neon-yellow)' }}>{a.severity}</span></span>
                    </div>
                  </div>
                </div>
              ))}
              {filteredAnomalies.length === 0 && (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '64px 0' }}>
                  No threats found fitting selection parameters.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 4: Security Rules and simulations */}
        {activeTab === 'rules' && (
          <div className="rules-container">
            
            {/* Rules Threshold Adjustment */}
            <div className="glass-card">
              <div className="panel-header">
                <h3 className="panel-title">Detection Threshold settings</h3>
              </div>
              <div className="rule-group">
                <div className="switch-row">
                  <div className="switch-details">
                    <h4>Statistical Z-Score Boundary</h4>
                    <p>Standard deviations above mean to flag latency anomalies (Default 3.5)</p>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <input 
                      type="range" min="2" max="6" step="0.5" 
                      value={settings.zScoreThreshold} 
                      onChange={(e) => setSettings(prev => ({ ...prev, zScoreThreshold: parseFloat(e.target.value) }))}
                    />
                    <span style={{ fontFamily: 'JetBrains Mono', fontWeight: 700, minWidth: '30px' }}>{settings.zScoreThreshold}</span>
                  </div>
                </div>

                <div className="switch-row">
                  <div className="switch-details">
                    <h4>Volumetric Rate Limits</h4>
                    <p>Max requests allowed in a 10-second sliding window per client IP</p>
                  </div>
                  <input 
                    type="number" className="slider-input" style={{ width: '80px', marginTop: 0 }}
                    value={settings.rateLimitThreshold} 
                    onChange={(e) => setSettings(prev => ({ ...prev, rateLimitThreshold: parseInt(e.target.value) }))}
                  />
                </div>

                <div className="switch-row">
                  <div className="switch-details">
                    <h4>Brute Force Trigger Limit</h4>
                    <p>Maximum failed login attempts within 30s before generating alarm</p>
                  </div>
                  <input 
                    type="number" className="slider-input" style={{ width: '80px', marginTop: 0 }}
                    value={settings.bruteForceLimit} 
                    onChange={(e) => setSettings(prev => ({ ...prev, bruteForceLimit: parseInt(e.target.value) }))}
                  />
                </div>

                <div className="switch-row">
                  <div className="switch-details">
                    <h4>SQL Injection Signature Rules</h4>
                    <p>Active matching for SQL schema and execution queries</p>
                  </div>
                  <label className="toggle-switch">
                    <input type="checkbox" defaultChecked />
                    <span className="slider"></span>
                  </label>
                </div>

                <div className="switch-row">
                  <div className="switch-details">
                    <h4>XSS Payload Filter</h4>
                    <p>Active signature regex auditing for script injection attempts</p>
                  </div>
                  <label className="toggle-switch">
                    <input type="checkbox" defaultChecked />
                    <span className="slider"></span>
                  </label>
                </div>
              </div>
            </div>

            {/* Ingestion Stream Simulation */}
            <div className="glass-card">
              <div className="panel-header">
                <h3 className="panel-title">Ingestion Attack Simulator</h3>
              </div>
              <p style={{ color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '24px' }}>
                Use the quick buttons below to trigger simulated traffic events directly to the E-Commerce API (Port 8000). The telemetry middleware will intercept and stream them for processing.
              </p>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <button className="nav-item" style={{ color: '#fff', border: '1px solid var(--neon-blue)', background: 'none', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} onClick={() => simulateAttack('SQLI')}>
                  <span>💉 Inject SQLi Payload</span>
                  <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--neon-blue)' }}>Path Signature test</span>
                </button>

                <button className="nav-item" style={{ color: '#fff', border: '1px solid var(--neon-purple)', background: 'none', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} onClick={() => simulateAttack('XSS')}>
                  <span>🎭 Inject XSS Script tag</span>
                  <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--neon-purple)' }}>Payload auditor test</span>
                </button>

                <button className="nav-item" style={{ color: '#fff', border: '1px solid #f97316', background: 'none', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} onClick={() => simulateAttack('BRUTE')}>
                  <span>🔑 Run Login Brute-Force</span>
                  <span style={{ fontSize: '11px', textTransform: 'uppercase', color: '#f97316' }}>Volumetric auth test</span>
                </button>

                <button className="nav-item" style={{ color: '#fff', border: '1px solid var(--neon-pink)', background: 'none', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} onClick={() => simulateAttack('SCANNER')}>
                  <span>🌐 Simulate Path Scanner / Fuzzer</span>
                  <span style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--neon-pink)' }}>Rate of 404s test</span>
                </button>
              </div>
            </div>
          </div>
        )}

      </main>

      {/* Log Detail Modal */}
      {selectedLog && (
        <div className="modal-overlay" onClick={() => setSelectedLog(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>HTTP Request Detail</h3>
              <button className="close-btn" onClick={() => setSelectedLog(null)}>&times;</button>
            </div>
            <div className="modal-body">
              <p><strong>Trace ID:</strong> <code>{selectedLog.trace_id}</code></p>
              <p><strong>Endpoint:</strong> <span className={`badge badge-${selectedLog.method?.toLowerCase()}`}>{selectedLog.method}</span> <code>{selectedLog.path}</code></p>
              <p><strong>Status:</strong> <span className={`status-badge status-${Math.floor(selectedLog.status_code / 100)}xx`}>{selectedLog.status_code}</span></p>
              <p><strong>Latency:</strong> {selectedLog.response_time_ms} ms</p>
              <p><strong>IP Address:</strong> {selectedLog.ip_address}</p>
              <p><strong>Timestamp:</strong> {new Date(selectedLog.timestamp).toString()}</p>
              <p><strong>User Agent:</strong> {selectedLog.user_agent}</p>
              <div style={{ marginTop: '16px' }}>
                <p><strong>Full telemetry JSON Event:</strong></p>
                <pre className="json-block">{JSON.stringify(selectedLog, null, 2)}</pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Anomaly Detail Modal */}
      {selectedAnomaly && (
        <div className="modal-overlay" onClick={() => setSelectedAnomaly(null)}>
          <div className="modal-content" style={{ borderColor: 'var(--neon-pink)' }} onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3 style={{ color: 'var(--neon-pink)' }}>🚨 Threat Alert details</h3>
              <button className="close-btn" onClick={() => setSelectedAnomaly(null)}>&times;</button>
            </div>
            <div className="modal-body">
              <p><strong>Anomaly ID:</strong> <code>{selectedAnomaly.anomaly_id}</code></p>
              <p><strong>Threat Type:</strong> <span style={{ color: 'var(--neon-pink)', fontWeight: 800 }}>{selectedAnomaly.anomaly_type}</span></p>
              <p><strong>Severity:</strong> <span style={{ color: selectedAnomaly.severity === 'CRITICAL' ? 'var(--neon-pink)' : '#f97316', fontWeight: 700 }}>{selectedAnomaly.severity}</span></p>
              <p><strong>Timestamp:</strong> {new Date(selectedAnomaly.timestamp).toString()}</p>
              <p><strong>Target Endpoint:</strong> <code>{selectedAnomaly.path}</code></p>
              <p><strong>Client IP address:</strong> <code>{selectedAnomaly.ip_address}</code></p>
              <p><strong>Threat Summary:</strong></p>
              <div style={{ background: 'rgba(255, 0, 127, 0.05)', border: '1px solid rgba(255, 0, 127, 0.2)', padding: '12px', borderRadius: '6px', color: '#fff', fontSize: '14px', marginBottom: '16px' }}>
                {selectedAnomaly.description}
              </div>
              <div>
                <p><strong>Original Payload Meta:</strong></p>
                <pre className="json-block" style={{ color: '#fca5a5' }}>{JSON.stringify(selectedAnomaly.details, null, 2)}</pre>
              </div>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
