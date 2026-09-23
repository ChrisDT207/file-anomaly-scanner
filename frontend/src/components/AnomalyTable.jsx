import React, { useState } from 'react';

export default function AnomalyTable({ anomalies, summary }) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const severityLabels = {
    4: 'CRITICAL',
    3: 'HIGH',
    2: 'MEDIUM',
    1: 'LOW',
    0: 'INFO'
  };

  const filteredAnomalies = (anomalies || []).filter((item) => {
    if (severityFilter !== 'ALL') {
      const targetSeverity = parseInt(severityFilter, 10);
      if (item.severity !== targetSeverity) return false;
    }

    if (searchTerm.trim() !== '') {
      const term = searchTerm.toLowerCase();
      const inPath = (item.filePath || '').toLowerCase().includes(term);
      const inCat = (item.category || '').toLowerCase().includes(term);
      const inDetails = (item.details || '').toLowerCase().includes(term);
      const inTitle = (item.title || '').toLowerCase().includes(term);
      if (!inPath && !inCat && !inDetails && !inTitle) return false;
    }

    return true;
  });

  const exportReportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({ summary, anomalies }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `AnomalyReport_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="section-card anomaly-section">
      <div className="anomaly-header">
        <div className="section-title">Anomaly Results &amp; Structural Findings</div>
        {anomalies && anomalies.length > 0 && (
          <button type="button" className="btn btn-sm" onClick={exportReportJson}>
            Export JSON Report
          </button>
        )}
      </div>

      {/* Summary Metrics Bar */}
      {summary && (
        <div className="summary-bar">
          <div className="summary-item">
            <span className="summary-label">Scanned Files:</span>
            <span className="summary-val">{summary.totalFilesScanned}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Anomalies:</span>
            <span className="summary-val font-bold">{summary.totalAnomaliesFound}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Critical:</span>
            <span className="summary-val val-critical">{summary.criticalCount || 0}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">High:</span>
            <span className="summary-val val-high">{summary.highCount || 0}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Medium:</span>
            <span className="summary-val val-medium">{summary.mediumCount || 0}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Low:</span>
            <span className="summary-val">{summary.lowCount || 0}</span>
          </div>
          <div className="summary-item">
            <span className="summary-label">Duration:</span>
            <span className="summary-val">{summary.durationMs} ms</span>
          </div>
        </div>
      )}

      {/* Table Filters */}
      <div className="table-controls">
        <div className="filter-group">
          <label htmlFor="severitySelect">Filter Severity:</label>
          <select
            id="severitySelect"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="filter-select"
          >
            <option value="ALL">All Severities</option>
            <option value="4">Critical</option>
            <option value="3">High</option>
            <option value="2">Medium</option>
            <option value="1">Low</option>
            <option value="0">Info</option>
          </select>
        </div>

        <div className="filter-group">
          <label htmlFor="searchInput">Search:</label>
          <input
            id="searchInput"
            type="text"
            className="search-input"
            placeholder="Search by filename, path, or rule..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="filter-count">
          Showing {filteredAnomalies.length} of {anomalies ? anomalies.length : 0} items
        </div>
      </div>

      {/* Results Table */}
      <div className="table-container">
        <table className="anomaly-table">
          <thead>
            <tr>
              <th style={{ width: '90px' }}>Severity</th>
              <th style={{ width: '220px' }}>File Path</th>
              <th style={{ width: '160px' }}>Category</th>
              <th style={{ width: '80px' }}>Entropy</th>
              <th style={{ width: '140px' }}>Magic Mismatch</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {!anomalies || anomalies.length === 0 ? (
              <tr>
                <td colSpan="6" className="table-empty">
                  No scan performed yet, or all scanned files passed without anomalies.
                </td>
              </tr>
            ) : filteredAnomalies.length === 0 ? (
              <tr>
                <td colSpan="6" className="table-empty">
                  No anomalies match the current filter criteria.
                </td>
              </tr>
            ) : (
              filteredAnomalies.map((item, index) => {
                const sevName = severityLabels[item.severity] || 'INFO';
                return (
                  <tr key={index} className={`row-sev-${item.severity}`}>
                    <td>
                      <span className={`badge badge-sev-${item.severity}`}>{sevName}</span>
                    </td>
                    <td className="cell-filepath" title={item.filePath}>
                      {item.filePath}
                    </td>
                    <td>
                      <strong>{item.category}</strong>
                      <div className="item-sub-title">{item.title}</div>
                    </td>
                    <td className="cell-entropy">
                      {item.entropy ? `${item.entropy.toFixed(2)} / 8.0` : '—'}
                    </td>
                    <td>
                      {item.isMagicByteMismatch ? (
                        <span className="badge-flag">MISMATCH</span>
                      ) : (
                        <span className="badge-pass">Matched / N/A</span>
                      )}
                    </td>
                    <td className="cell-details">{item.details}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
