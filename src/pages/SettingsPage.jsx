import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Shield,
  Bell,
  Radio,
  Send,
  RotateCcw,
  CheckCircle2,
  Sun,
  Moon,
  ShieldAlert,
  Server,
  Zap,
  Mail,
  Smartphone,
  Activity,
  Play,
  Pause,
  RefreshCw,
  Terminal
} from 'lucide-react';
import { useTheme } from '../context/ThemeContext';
import api from '../services/api';

const DEFAULT_COLLECTORS = [
  {
    id: 'endpoint_auth',
    name: 'Host OS Authentication Sensor',
    type: 'os_auth',
    description: 'Collects Windows Security Logs (IDs 4624/4625/4672) & Linux PAM auth events.',
    source_target: 'Monitored Endpoints (WS-FIN-091, WS-ENG-402, WS-OPS-114)',
    status: 'Active',
    collection_interval_sec: 15,
    events_collected: 4281,
    throughput_eps: 14.2,
    last_ping: 'Just now',
    supported_event_types: ['login_success', 'failed_login', 'privilege_escalation', 'mfa_challenge']
  },
  {
    id: 'removable_media',
    name: 'Plug-and-Play USB Storage Sensor',
    type: 'removable_media',
    description: 'Monitors USB Mass Storage insertions, PnP device mounts, and unapproved serial numbers.',
    source_target: 'Endpoint PnP Device Bus (Kernel DLP Driver)',
    status: 'Active',
    collection_interval_sec: 10,
    events_collected: 912,
    throughput_eps: 2.8,
    last_ping: 'Just now',
    supported_event_types: ['usb_device_mounted', 'usb_mass_copy', 'usb_unmount']
  },
  {
    id: 'data_egress',
    name: 'Network Data Movement & Git Egress Sensor',
    type: 'data_egress',
    description: 'Captures high-volume document downloads, bulk git repository clones, and DMS vault pulls.',
    source_target: 'GitHub Enterprise & Corporate DMS Vault (//legal-dms)',
    status: 'Active',
    collection_interval_sec: 20,
    events_collected: 2840,
    throughput_eps: 8.5,
    last_ping: 'Just now',
    supported_event_types: ['git_clone_mass', 'mass_file_download', 'sensitive_data_export']
  },
  {
    id: 'cloud_audit',
    name: 'AWS CloudTrail IAM Audit Sensor',
    type: 'cloud_audit',
    description: 'Audits AWS IAM policy changes, root token usage, and permission boundary tampering.',
    source_target: 'AWS CloudTrail Event Stream (eu-west-1, us-east-1)',
    status: 'Active',
    collection_interval_sec: 30,
    events_collected: 1489,
    throughput_eps: 5.1,
    last_ping: 'Just now',
    supported_event_types: ['iam_policy_modification', 'role_elevation_attempt', 'api_key_generated']
  },
  {
    id: 'network_vpn',
    name: 'Enterprise Zero-Trust VPN Gateway Sensor',
    type: 'vpn_gateway',
    description: 'Monitors remote perimeter VPN ingress, foreign IP geolocation, and off-hours sessions.',
    source_target: 'Global VPN Concentrator (194.26.29.4 Berlin, 10.200.5.21 London)',
    status: 'Active',
    collection_interval_sec: 15,
    events_collected: 3672,
    throughput_eps: 11.4,
    last_ping: 'Just now',
    supported_event_types: ['vpn_connection_established', 'vpn_foreign_ip_detected', 'vpn_session_terminated']
  }
];

const DEFAULT_SETTINGS = {
  riskThreshold: 75,
  autoContainment: true,
  sensitivity: 'Standard',
  autoRefreshInterval: '30s',
  defaultTimeframe: '30d',
  denseTableMode: false,
  webhookUrl: 'https://hooks.slack.com/services/T00/B00/SEC-OPS-ALERTS',
  splunkEndpoint: 'https://splunk.internal.threat.ai:8088/services/collector',
  pagerdutyKey: 'pd-live-sec-8849201a',
  continuousTelemetry: true,
  emailDigest: true,
  smsEscalation: false
};

export default function SettingsPage() {
  const { theme, darkMode, toggleDarkMode } = useTheme();

  // Active configuration sub-tab
  const [activeTab, setActiveTab] = useState('thresholds'); // 'thresholds' | 'dashboard' | 'integrations' | 'notifications'

  // Settings State initialized from defaults
  const [settings, setSettings] = useState(() => {
    try {
      const saved = localStorage.getItem('threat_ai_soc_settings');
      return saved ? { ...DEFAULT_SETTINGS, ...JSON.parse(saved) } : DEFAULT_SETTINGS;
    } catch {
      return DEFAULT_SETTINGS;
    }
  });

  // Feedback toast state
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleSettingChange = (field, value) => {
    setSettings((prev) => ({ ...prev, [field]: value }));
  };

  const handleSave = () => {
    try {
      localStorage.setItem('threat_ai_soc_settings', JSON.stringify(settings));
    } catch (e) {
      console.error(e);
    }
    showToast('SOC security parameters successfully applied and committed.');
  };

  const handleResetDefaults = () => {
    setSettings(DEFAULT_SETTINGS);
    try {
      localStorage.setItem('threat_ai_soc_settings', JSON.stringify(DEFAULT_SETTINGS));
    } catch (e) {
      console.error(e);
    }
    showToast('Configuration reverted to baseline factory defaults.');
  };

  const handleTestPing = (integrationName) => {
    showToast(`Dispatched test payload to ${integrationName} — status 200 OK.`);
  };

  const tabs = [
    { id: 'thresholds', label: 'Risk & Thresholds', icon: Shield },
    { id: 'dashboard', label: 'Interface & Display', icon: Sliders },
    { id: 'collectors', label: 'Log Collectors & Sensors', icon: Radio },
    { id: 'integrations', label: 'SIEM & Webhooks', icon: Server },
    { id: 'notifications', label: 'Notification Rules', icon: Bell }
  ];

  // Log Collectors State
  const [collectors, setCollectors] = useState(DEFAULT_COLLECTORS);
  const [isPulsing, setIsPulsing] = useState({});
  const [collectorStats, setCollectorStats] = useState({
    total_events_collected: 13194,
    active_count: 5,
    fleet_health: 'Operational // Nominal'
  });

  useEffect(() => {
    let isMounted = true;
    api.getCollectors()
      .then((res) => {
        if (isMounted && res?.collectors && res.collectors.length > 0) {
          setCollectors(res.collectors);
          setCollectorStats({
            total_events_collected: res.total_events_collected,
            active_count: res.active_count,
            fleet_health: res.fleet_health
          });
        }
      })
      .catch((err) => {
        console.warn('Collectors live fetch fallback to default:', err);
      });
    return () => {
      isMounted = false;
    };
  }, []);

  const handleTriggerPulse = async (collectorId, simulateAnomaly = false) => {
    setIsPulsing((prev) => ({ ...prev, [collectorId]: true }));
    try {
      const res = await api.triggerCollectorPulse(collectorId, simulateAnomaly);
      showToast(
        `${res.collector_name}: Ingested ${res.events_ingested} event(s)${
          res.anomalies_flagged > 0 ? ' [ANOMALY FLAGGED & NOTIFIED]' : ' [Nominal Telemetry]'
        }`
      );
      const updated = await api.getCollectors();
      if (updated?.collectors) {
        setCollectors(updated.collectors);
        setCollectorStats({
          total_events_collected: updated.total_events_collected,
          active_count: updated.active_count,
          fleet_health: updated.fleet_health
        });
      }
    } catch (err) {
      showToast(`Collector pulse failed: ${err.message}`);
    } finally {
      setIsPulsing((prev) => ({ ...prev, [collectorId]: false }));
    }
  };

  const handleToggleCollector = async (collectorId) => {
    try {
      const res = await api.toggleCollector(collectorId);
      showToast(res.message);
      setCollectors((prev) =>
        prev.map((c) => (c.id === collectorId ? { ...c, status: res.status } : c))
      );
    } catch (err) {
      showToast(`Toggle failed: ${err.message}`);
    }
  };

  return (
    <div className="animate-fade-in" style={{ display: 'flex', flexDirection: 'column', gap: '24px', maxWidth: '960px' }}>
      {/* ================================================= */}
      {/* 1. TOAST FEEDBACK NOTIFICATION                    */}
      {/* ================================================= */}
      {toastMessage && (
        <div
          style={{
            position: 'fixed',
            bottom: '28px',
            right: '28px',
            zIndex: 1000,
            backgroundColor: theme.surface,
            border: `1px solid ${theme.border}`,
            boxShadow: '0 10px 30px rgba(0,0,0,0.35)',
            borderRadius: '10px',
            padding: '14px 20px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            animation: 'fadeIn 0.2s ease-out'
          }}
        >
          <div
            style={{
              width: '28px',
              height: '28px',
              borderRadius: '8px',
              backgroundColor: 'rgba(16, 185, 129, 0.15)',
              color: '#10b981',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
          >
            <CheckCircle2 size={16} />
          </div>
          <span style={{ fontSize: '13px', fontWeight: '600', color: theme.textPrimary }}>
            {toastMessage}
          </span>
        </div>
      )}

      {/* ================================================= */}
      {/* 2. HEADER BANNER & TAB NAVIGATION                 */}
      {/* ================================================= */}
      <div
        style={{
          backgroundColor: theme.surface,
          borderRadius: '14px',
          border: `1px solid ${theme.border}`,
          padding: '24px 28px',
          boxShadow: theme.shadow
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Sliders size={22} color={theme.primary} />
              <h1 style={{ fontSize: '20px', fontWeight: '800', margin: 0, color: theme.textPrimary }}>
                SOC Configuration & Telemetry Parameters
              </h1>
            </div>
            <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: theme.textSecondary }}>
              Manage behavioral detection benchmarks, webhook integrations, and monitoring preferences.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button
              onClick={handleResetDefaults}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 14px',
                borderRadius: '8px',
                border: `1px solid ${theme.border}`,
                backgroundColor: theme.surfaceVariant,
                color: theme.textSecondary,
                fontSize: '12.5px',
                fontWeight: '600',
                cursor: 'pointer'
              }}
            >
              <RotateCcw size={13} />
              Reset Defaults
            </button>

            <button
              onClick={handleSave}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 18px',
                borderRadius: '8px',
                border: 'none',
                backgroundColor: theme.primary,
                color: '#ffffff',
                fontSize: '12.5px',
                fontWeight: '700',
                cursor: 'pointer'
              }}
            >
              <Send size={13} />
              Save Configuration
            </button>
          </div>
        </div>

        {/* Sub-Tabs */}
        <div style={{ display: 'flex', gap: '8px', marginTop: '22px', borderTop: `1px solid ${theme.borderSubtle}`, paddingTop: '16px', flexWrap: 'wrap' }}>
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isSelected = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: `1px solid ${isSelected ? theme.primary : 'transparent'}`,
                  backgroundColor: isSelected ? theme.primaryContainer : 'transparent',
                  color: isSelected ? theme.primary : theme.textSecondary,
                  fontSize: '13px',
                  fontWeight: isSelected ? '700' : '500',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease'
                }}
              >
                <Icon size={15} />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* ================================================= */}
      {/* 3. TAB 1: RISK & THRESHOLDS                       */}
      {/* ================================================= */}
      {activeTab === 'thresholds' && (
        <div
          style={{
            backgroundColor: theme.surface,
            borderRadius: '14px',
            border: `1px solid ${theme.border}`,
            padding: '28px',
            boxShadow: theme.shadow,
            display: 'flex',
            flexDirection: 'column',
            gap: '24px'
          }}
        >
          {/* Threshold Slider */}
          <div style={{ padding: '20px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div>
                <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary, display: 'block' }}>
                  High-Risk Anomaly Escalation Threshold
                </label>
                <span style={{ fontSize: '12px', color: theme.textSecondary }}>
                  Identities exceeding this benchmark trigger automated Priority Critical incident dispatch.
                </span>
              </div>
              <span
                style={{
                  padding: '4px 12px',
                  borderRadius: '6px',
                  backgroundColor: theme.primary,
                  color: '#ffffff',
                  fontWeight: '800',
                  fontSize: '14px'
                }}
              >
                {settings.riskThreshold} / 100
              </span>
            </div>

            <input
              type="range"
              min="50"
              max="95"
              value={settings.riskThreshold}
              onChange={(e) => handleSettingChange('riskThreshold', Number(e.target.value))}
              style={{ width: '100%', accentColor: theme.primary, cursor: 'pointer', margin: '8px 0' }}
            />

            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: theme.textSecondary }}>
              <span>50 (Permissive)</span>
              <span>75 (Standard Recommended)</span>
              <span>95 (Strict SOC Isolation)</span>
            </div>
          </div>

          {/* Automatic Containment Checkbox */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '20px',
              backgroundColor: theme.surfaceVariant,
              borderRadius: '10px',
              border: `1px solid ${theme.borderSubtle}`
            }}
          >
            <div>
              <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary, display: 'block' }}>
                Automated Containment Directives
              </label>
              <span style={{ fontSize: '12px', color: theme.textSecondary }}>
                Temporarily lock credentials and isolate endpoint workstations when composite score exceeds 90.
              </span>
            </div>
            <input
              type="checkbox"
              checked={settings.autoContainment}
              onChange={(e) => handleSettingChange('autoContainment', e.target.checked)}
              style={{ width: '18px', height: '18px', accentColor: theme.primary, cursor: 'pointer' }}
            />
          </div>

          {/* Behavioral Sensitivity Radio Group */}
          <div style={{ padding: '20px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
            <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary, display: 'block', marginBottom: '12px' }}>
              UEBA Anomaly Scoring Sensitivity
            </label>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
              {['Permissive', 'Standard', 'Strict'].map((lvl) => {
                const isSelected = settings.sensitivity === lvl;
                return (
                  <div
                    key={lvl}
                    onClick={() => handleSettingChange('sensitivity', lvl)}
                    style={{
                      padding: '14px',
                      borderRadius: '8px',
                      border: `1px solid ${isSelected ? theme.primary : theme.border}`,
                      backgroundColor: isSelected ? theme.surface : 'transparent',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <Radio size={14} color={isSelected ? theme.primary : theme.textSecondary} />
                      <strong style={{ fontSize: '13px', color: theme.textPrimary }}>{lvl}</strong>
                    </div>
                    <span style={{ fontSize: '11.5px', color: theme.textSecondary }}>
                      {lvl === 'Permissive'
                        ? 'Tolerates higher activity variations.'
                        : lvl === 'Standard'
                        ? 'Recommended baseline for corporate environments.'
                        : 'Immediate alerts on any deviation.'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ================================================= */}
      {/* 4. TAB 2: INTERFACE & DISPLAY                     */}
      {/* ================================================= */}
      {activeTab === 'dashboard' && (
        <div
          style={{
            backgroundColor: theme.surface,
            borderRadius: '14px',
            border: `1px solid ${theme.border}`,
            padding: '28px',
            boxShadow: theme.shadow,
            display: 'flex',
            flexDirection: 'column',
            gap: '24px'
          }}
        >
          {/* Theme Mode Selector */}
          <div style={{ padding: '20px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
            <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary, display: 'block', marginBottom: '6px' }}>
              Color Theme Appearance
            </label>
            <span style={{ fontSize: '12px', color: theme.textSecondary, display: 'block', marginBottom: '14px' }}>
              Choose between high-contrast dark cybersecurity mode and bright executive light mode.
            </span>

            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={() => {
                  if (!darkMode) toggleDarkMode();
                }}
                style={{
                  flex: 1,
                  padding: '14px',
                  borderRadius: '8px',
                  border: `2px solid ${darkMode ? theme.primary : theme.border}`,
                  backgroundColor: '#0f172a',
                  color: '#ffffff',
                  fontWeight: '700',
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px'
                }}
              >
                <Moon size={16} color="#818cf8" />
                Cyber Dark Mode {darkMode && '✓'}
              </button>

              <button
                onClick={() => {
                  if (darkMode) toggleDarkMode();
                }}
                style={{
                  flex: 1,
                  padding: '14px',
                  borderRadius: '8px',
                  border: `2px solid ${!darkMode ? theme.primary : theme.border}`,
                  backgroundColor: '#ffffff',
                  color: '#0f172a',
                  fontWeight: '700',
                  fontSize: '13px',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px'
                }}
              >
                <Sun size={16} color="#f59e0b" />
                Executive Light Mode {!darkMode && '✓'}
              </button>
            </div>
          </div>

          {/* Telemetry Refresh & Timeframe */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
            <div style={{ padding: '18px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
              <label style={{ fontSize: '13.5px', fontWeight: '700', color: theme.textPrimary, display: 'block', marginBottom: '6px' }}>
                Telemetry Polling Interval
              </label>
              <select
                value={settings.autoRefreshInterval}
                onChange={(e) => handleSettingChange('autoRefreshInterval', e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: '7px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontSize: '13px',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                <option value="15s">Every 15 seconds (Near Real-Time)</option>
                <option value="30s">Every 30 seconds (Standard)</option>
                <option value="60s">Every 60 seconds</option>
                <option value="manual">Manual Refresh Only</option>
              </select>
            </div>

            <div style={{ padding: '18px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
              <label style={{ fontSize: '13.5px', fontWeight: '700', color: theme.textPrimary, display: 'block', marginBottom: '6px' }}>
                Default Analytics Lookback
              </label>
              <select
                value={settings.defaultTimeframe}
                onChange={(e) => handleSettingChange('defaultTimeframe', e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 12px',
                  borderRadius: '7px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontSize: '13px',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                <option value="7d">Past 7 Days</option>
                <option value="30d">Past 30 Days (Recommended)</option>
                <option value="90d">Past 90 Days (Quarterly)</option>
              </select>
            </div>
          </div>

          {/* Compact Layout Toggle */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '18px',
              backgroundColor: theme.surfaceVariant,
              borderRadius: '10px',
              border: `1px solid ${theme.borderSubtle}`
            }}
          >
            <div>
              <label style={{ fontSize: '13.5px', fontWeight: '700', color: theme.textPrimary, display: 'block' }}>
                Dense Table Mode
              </label>
              <span style={{ fontSize: '12px', color: theme.textSecondary }}>
                Reduces row padding in directory and alert lists to maximize screen real estate.
              </span>
            </div>
            <input
              type="checkbox"
              checked={settings.denseTableMode}
              onChange={(e) => handleSettingChange('denseTableMode', e.target.checked)}
              style={{ width: '18px', height: '18px', accentColor: theme.primary, cursor: 'pointer' }}
            />
          </div>
        </div>
      )}

      {/* ================================================= */}
      {/* 4. TAB 3: LOG COLLECTORS & SENSORS               */}
      {/* ================================================= */}
      {activeTab === 'collectors' && (
        <div
          style={{
            backgroundColor: theme.surface,
            borderRadius: '14px',
            border: `1px solid ${theme.border}`,
            padding: '28px',
            boxShadow: theme.shadow,
            display: 'flex',
            flexDirection: 'column',
            gap: '24px'
          }}
        >
          {/* Header Fleet Banner */}
          <div
            style={{
              padding: '20px',
              backgroundColor: theme.surfaceVariant,
              borderRadius: '12px',
              border: `1px solid ${theme.borderSubtle}`,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '16px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
              <div
                style={{
                  width: '44px',
                  height: '44px',
                  borderRadius: '10px',
                  backgroundColor: theme.primaryContainer,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: theme.primary
                }}
              >
                <Radio size={22} className="animate-pulse" />
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <h3 style={{ margin: 0, fontSize: '16px', fontWeight: '800', color: theme.textPrimary }}>
                    Distributed Telemetry Ingestion Fleet
                  </h3>
                  <span
                    style={{
                      padding: '3px 10px',
                      borderRadius: '12px',
                      backgroundColor: '#10b98122',
                      color: '#10b981',
                      fontSize: '11px',
                      fontWeight: '700'
                    }}
                  >
                    ● {collectorStats.fleet_health || 'Fleet Operational'}
                  </span>
                </div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12.5px', color: theme.textSecondary }}>
                  5 active sensor daemons streaming OS, USB, CloudTrail, Git, and VPN events into SOC event pipelines.
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '20px', alignItems: 'center' }}>
              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '11px', color: theme.textSecondary, textTransform: 'uppercase', letterSpacing: '0.5px', display: 'block' }}>
                  Total Ingested Events
                </span>
                <span style={{ fontSize: '18px', fontWeight: '800', color: theme.primary }}>
                  {collectorStats.total_events_collected?.toLocaleString() || '13,194'}
                </span>
              </div>
              <div style={{ textAlign: 'right' }}>
                <span style={{ fontSize: '11px', color: theme.textSecondary, textTransform: 'uppercase', letterSpacing: '0.5px', display: 'block' }}>
                  Active Sensor Daemons
                </span>
                <span style={{ fontSize: '18px', fontWeight: '800', color: '#10b981' }}>
                  {collectorStats.active_count ?? 5} / 5
                </span>
              </div>
            </div>
          </div>

          {/* Standalone Agent CLI Callout Box */}
          <div
            style={{
              padding: '16px 20px',
              backgroundColor: '#0a0f1d',
              borderRadius: '10px',
              border: '1px solid #1e293b',
              color: '#94a3b8',
              fontSize: '12.5px',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#38bdf8', fontWeight: '700' }}>
                <Terminal size={15} />
                <span>Live Shipper Agent CLI (Automated SOC Pipeline Execution)</span>
              </div>
              <span style={{ fontSize: '11px', color: '#64748b' }}>Python 3.10+ Executable</span>
            </div>
            <div style={{ backgroundColor: '#030712', padding: '10px 14px', borderRadius: '6px', fontFamily: 'monospace', color: '#4ade80', fontSize: '12px', overflowX: 'auto' }}>
              <code>python backend/collectors/agent.py --collector all --interval 10 --iterations 5</code>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: '#64748b' }}>
              <span>Simulate high-risk anomalous exfiltration: <code style={{ color: '#f87171' }}>python backend/collectors/agent.py --collector endpoint_auth --simulate-anomaly</code></span>
            </div>
          </div>

          {/* Collectors Sensor Grid */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {collectors.map((c) => {
              const isActive = c.status === 'Active';
              const pulsing = isPulsing[c.id];

              return (
                <div
                  key={c.id}
                  style={{
                    padding: '20px',
                    backgroundColor: theme.surfaceVariant,
                    borderRadius: '12px',
                    border: `1px solid ${theme.borderSubtle}`,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '14px',
                    transition: 'border-color 0.2s ease'
                  }}
                >
                  {/* Card Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                      <div
                        style={{
                          width: '36px',
                          height: '36px',
                          borderRadius: '8px',
                          backgroundColor: isActive ? '#10b98118' : '#f59e0b18',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          color: isActive ? '#10b981' : '#f59e0b'
                        }}
                      >
                        <Activity size={18} />
                      </div>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                          <h4 style={{ margin: 0, fontSize: '14.5px', fontWeight: '700', color: theme.textPrimary }}>
                            {c.name}
                          </h4>
                          <span
                            style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              backgroundColor: isActive ? '#10b98122' : '#f59e0b22',
                              color: isActive ? '#10b981' : '#f59e0b',
                              fontSize: '11px',
                              fontWeight: '700'
                            }}
                          >
                            ● {c.status}
                          </span>
                          <span
                            style={{
                              padding: '2px 8px',
                              borderRadius: '4px',
                              backgroundColor: theme.surface,
                              border: `1px solid ${theme.border}`,
                              color: theme.textSecondary,
                              fontSize: '10.5px',
                              fontWeight: '600',
                              fontFamily: 'monospace'
                            }}
                          >
                            {c.id}
                          </span>
                        </div>
                        <p style={{ margin: '4px 0 0 0', fontSize: '12.5px', color: theme.textSecondary, lineHeight: '1.4' }}>
                          {c.description}
                        </p>
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <button
                        onClick={() => handleToggleCollector(c.id)}
                        title={isActive ? 'Pause Sensor Daemon' : 'Resume Sensor Daemon'}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          padding: '6px 12px',
                          borderRadius: '6px',
                          border: `1px solid ${theme.border}`,
                          backgroundColor: theme.surface,
                          color: theme.textSecondary,
                          fontSize: '12px',
                          fontWeight: '600',
                          cursor: 'pointer'
                        }}
                      >
                        {isActive ? <Pause size={12} /> : <Play size={12} />}
                        {isActive ? 'Pause' : 'Resume'}
                      </button>

                      <button
                        onClick={() => handleTriggerPulse(c.id, false)}
                        disabled={pulsing || !isActive}
                        title="Ingest fresh nominal telemetry pulse now"
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          padding: '6px 14px',
                          borderRadius: '6px',
                          border: `1px solid ${theme.border}`,
                          backgroundColor: theme.surface,
                          color: theme.textPrimary,
                          fontSize: '12px',
                          fontWeight: '600',
                          cursor: isActive && !pulsing ? 'pointer' : 'not-allowed',
                          opacity: !isActive ? 0.5 : 1
                        }}
                      >
                        <RefreshCw size={12} className={pulsing ? 'animate-spin' : ''} />
                        {pulsing ? 'Ingesting...' : 'Pulse Telemetry'}
                      </button>

                      <button
                        onClick={() => handleTriggerPulse(c.id, true)}
                        disabled={pulsing || !isActive}
                        title="Simulate anomalous high-risk exfiltration event"
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                          padding: '6px 12px',
                          borderRadius: '6px',
                          border: '1px solid #ef444444',
                          backgroundColor: '#ef444415',
                          color: '#ef4444',
                          fontSize: '12px',
                          fontWeight: '700',
                          cursor: isActive && !pulsing ? 'pointer' : 'not-allowed',
                          opacity: !isActive ? 0.5 : 1
                        }}
                      >
                        <ShieldAlert size={12} />
                        Simulate Anomaly
                      </button>
                    </div>
                  </div>

                  {/* Metadata and Supported Events */}
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      paddingTop: '10px',
                      borderTop: `1px solid ${theme.borderSubtle}`,
                      fontSize: '11.5px',
                      color: theme.textSecondary,
                      flexWrap: 'wrap',
                      gap: '12px'
                    }}
                  >
                    <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
                      <span>
                        Target: <strong style={{ color: theme.textPrimary }}>{c.source_target}</strong>
                      </span>
                      <span>
                        Throughput: <strong style={{ color: theme.primary }}>{c.throughput_eps} EPS</strong>
                      </span>
                      <span>
                        Harvested: <strong style={{ color: theme.textPrimary }}>{c.events_collected?.toLocaleString()}</strong>
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '10.5px', color: theme.textSecondary }}>Sensors:</span>
                      {c.supported_event_types?.map((evt) => (
                        <span
                          key={evt}
                          style={{
                            padding: '2px 7px',
                            borderRadius: '4px',
                            backgroundColor: theme.surface,
                            border: `1px solid ${theme.borderSubtle}`,
                            fontSize: '10.5px',
                            fontFamily: 'monospace',
                            color: theme.textSecondary
                          }}
                        >
                          {evt}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ================================================= */}
      {/* 5. TAB 3: SIEM & WEBHOOK INTEGRATIONS             */}
      {/* ================================================= */}
      {activeTab === 'integrations' && (
        <div
          style={{
            backgroundColor: theme.surface,
            borderRadius: '14px',
            border: `1px solid ${theme.border}`,
            padding: '28px',
            boxShadow: theme.shadow,
            display: 'flex',
            flexDirection: 'column',
            gap: '20px'
          }}
        >
          {/* Slack Webhook */}
          <div style={{ padding: '20px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Zap size={16} color={theme.primary} />
                <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary }}>
                  Slack Incident Escalation Webhook
                </label>
              </div>
              <span style={{ fontSize: '11px', color: '#10b981', fontWeight: '700' }}>Active</span>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                value={settings.webhookUrl}
                onChange={(e) => handleSettingChange('webhookUrl', e.target.value)}
                style={{
                  flex: 1,
                  padding: '9px 12px',
                  borderRadius: '8px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontSize: '12.5px',
                  outline: 'none'
                }}
              />
              <button
                type="button"
                onClick={() => handleTestPing('Slack Webhook')}
                style={{
                  padding: '9px 16px',
                  borderRadius: '8px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontWeight: '600',
                  fontSize: '12.5px',
                  cursor: 'pointer'
                }}
              >
                Test Ping
              </button>
            </div>
          </div>

          {/* Splunk SIEM */}
          <div style={{ padding: '20px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Server size={16} color={theme.primary} />
                <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary }}>
                  Splunk / Elastic SIEM HTTP Event Collector
                </label>
              </div>
              <span style={{ fontSize: '11px', color: '#10b981', fontWeight: '700' }}>Connected</span>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                value={settings.splunkEndpoint}
                onChange={(e) => handleSettingChange('splunkEndpoint', e.target.value)}
                style={{
                  flex: 1,
                  padding: '9px 12px',
                  borderRadius: '8px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontSize: '12.5px',
                  outline: 'none'
                }}
              />
              <button
                type="button"
                onClick={() => handleTestPing('Splunk Collector')}
                style={{
                  padding: '9px 16px',
                  borderRadius: '8px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontWeight: '600',
                  fontSize: '12.5px',
                  cursor: 'pointer'
                }}
              >
                Test Ping
              </button>
            </div>
          </div>

          {/* PagerDuty Key */}
          <div style={{ padding: '20px', backgroundColor: theme.surfaceVariant, borderRadius: '10px', border: `1px solid ${theme.borderSubtle}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={16} color="#ef4444" />
                <label style={{ fontSize: '14px', fontWeight: '700', color: theme.textPrimary }}>
                  PagerDuty On-Call Integration Routing Key
                </label>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <input
                type="text"
                value={settings.pagerdutyKey}
                onChange={(e) => handleSettingChange('pagerdutyKey', e.target.value)}
                style={{
                  flex: 1,
                  padding: '9px 12px',
                  borderRadius: '8px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontSize: '12.5px',
                  outline: 'none'
                }}
              />
              <button
                type="button"
                onClick={() => handleTestPing('PagerDuty Routing')}
                style={{
                  padding: '9px 16px',
                  borderRadius: '8px',
                  border: `1px solid ${theme.border}`,
                  backgroundColor: theme.surface,
                  color: theme.textPrimary,
                  fontWeight: '600',
                  fontSize: '12.5px',
                  cursor: 'pointer'
                }}
              >
                Test Ping
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ================================================= */}
      {/* 6. TAB 4: NOTIFICATION RULES                      */}
      {/* ================================================= */}
      {activeTab === 'notifications' && (
        <div
          style={{
            backgroundColor: theme.surface,
            borderRadius: '14px',
            border: `1px solid ${theme.border}`,
            padding: '28px',
            boxShadow: theme.shadow,
            display: 'flex',
            flexDirection: 'column',
            gap: '16px'
          }}
        >
          {/* Continuous Stream Push */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '20px',
              backgroundColor: theme.surfaceVariant,
              borderRadius: '10px',
              border: `1px solid ${theme.borderSubtle}`
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Radio size={18} color={theme.primary} />
              <div>
                <label style={{ fontSize: '13.5px', fontWeight: '700', color: theme.textPrimary, display: 'block' }}>
                  Continuous Threat Telemetry Alerts
                </label>
                <span style={{ fontSize: '12px', color: theme.textSecondary }}>
                  Stream real-time incident dispatches directly into the Notification Center.
                </span>
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.continuousTelemetry}
              onChange={(e) => handleSettingChange('continuousTelemetry', e.target.checked)}
              style={{ width: '18px', height: '18px', accentColor: theme.primary, cursor: 'pointer' }}
            />
          </div>

          {/* Email Digest */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '20px',
              backgroundColor: theme.surfaceVariant,
              borderRadius: '10px',
              border: `1px solid ${theme.borderSubtle}`
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Mail size={18} color={theme.primary} />
              <div>
                <label style={{ fontSize: '13.5px', fontWeight: '700', color: theme.textPrimary, display: 'block' }}>
                  Daily CISO Executive Briefing Digest
                </label>
                <span style={{ fontSize: '12px', color: theme.textSecondary }}>
                  Automated morning summary covering top high-risk identities and resolved incidents.
                </span>
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.emailDigest}
              onChange={(e) => handleSettingChange('emailDigest', e.target.checked)}
              style={{ width: '18px', height: '18px', accentColor: theme.primary, cursor: 'pointer' }}
            />
          </div>

          {/* SMS Escalation */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '20px',
              backgroundColor: theme.surfaceVariant,
              borderRadius: '10px',
              border: `1px solid ${theme.borderSubtle}`
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <Smartphone size={18} color="#ef4444" />
              <div>
                <label style={{ fontSize: '13.5px', fontWeight: '700', color: theme.textPrimary, display: 'block' }}>
                  Critical Priority SMS Escalation
                </label>
                <span style={{ fontSize: '12px', color: theme.textSecondary }}>
                  Emergency SMS notification to on-call security leadership for Severity: Critical data egress.
                </span>
              </div>
            </div>
            <input
              type="checkbox"
              checked={settings.smsEscalation}
              onChange={(e) => handleSettingChange('smsEscalation', e.target.checked)}
              style={{ width: '18px', height: '18px', accentColor: theme.primary, cursor: 'pointer' }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
