import React, { useRef, useEffect, useState } from 'react';

export default function ConsoleDashboard({ logs, onClearLogs }) {
  const consoleEndRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (autoScroll && consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const handleCopyLogs = () => {
    navigator.clipboard.writeText(logs.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="section-card console-section">
      <div className="console-header">
        <div className="section-title">Console Output &amp; Scan Status</div>
        <div className="console-actions">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            Auto-scroll
          </label>
          <button type="button" className="btn btn-sm" onClick={handleCopyLogs}>
            {copied ? 'Copied!' : 'Copy Logs'}
          </button>
          <button type="button" className="btn btn-sm" onClick={onClearLogs}>
            Clear Output
          </button>
        </div>
      </div>

      <div className="console-box" id="consoleOutput">
        {logs.length === 0 ? (
          <div className="console-empty">Console ready. Select or drop a folder to begin.</div>
        ) : (
          logs.map((log, idx) => {
            let lineClass = 'console-line';
            if (log.includes('[CRITICAL]') || log.includes('[ALERT]')) {
              lineClass += ' line-critical';
            } else if (log.includes('[WARN]') || log.includes('ATTENTION')) {
              lineClass += ' line-warn';
            } else if (log.includes('[ERROR]')) {
              lineClass += ' line-error';
            } else if (log.includes('[REPORT]') || log.includes('CLEAN')) {
              lineClass += ' line-report';
            }
            return (
              <div key={idx} className={lineClass}>
                {log}
              </div>
            );
          })
        )}
        <div ref={consoleEndRef} />
      </div>
    </div>
  );
}
