import { useState, useEffect } from 'react';
import '@/App.css';
import axios from 'axios';
import { Shield, AlertTriangle, CheckCircle, XCircle, Lock, Unlock, Activity, FileText, History, Target, TrendingUp, Server } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [activeTab, setActiveTab] = useState('vulnerable');
  const [vulnerableConfig, setVulnerableConfig] = useState(null);
  const [secureConfig, setSecureConfig] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [checklist, setChecklist] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showComparison, setShowComparison] = useState(false);

  useEffect(() => {
    loadVulnerableConfig();
    loadStats();
  }, []);

  const loadVulnerableConfig = async () => {
    try {
      const response = await axios.get(`${API}/security-groups/vulnerable`);
      setVulnerableConfig(response.data);
      analyzeConfiguration(response.data);
    } catch (error) {
      console.error('Error loading vulnerable config:', error);
    }
  };

  const loadSecureConfig = async () => {
    try {
      const response = await axios.get(`${API}/security-groups/secure`);
      setSecureConfig(response.data);
      return response.data;
    } catch (error) {
      console.error('Error loading secure config:', error);
    }
  };

  const analyzeConfiguration = async (config) => {
    try {
      setLoading(true);
      const response = await axios.post(`${API}/security-groups/analyze`, config);
      setAnalysisResult(response.data);
      
      // Generate checklist
      const checklistResponse = await axios.post(`${API}/security-groups/checklist`, config);
      setChecklist(checklistResponse.data);
      
      // Log audit
      await axios.post(`${API}/audit-logs`, {
        action: 'analyzed',
        user_id: 'student',
        details: { group_id: config.group_id, security_score: response.data.overall_security_score },
        security_score_before: response.data.overall_security_score
      });
      
      setLoading(false);
    } catch (error) {
      console.error('Error analyzing configuration:', error);
      setLoading(false);
    }
  };

  const applySecurityFix = async () => {
    try {
      setLoading(true);
      const secureConf = await loadSecureConfig();
      
      // Analyze secure configuration
      const response = await axios.post(`${API}/security-groups/analyze`, secureConf);
      const checklistResponse = await axios.post(`${API}/security-groups/checklist`, secureConf);
      
      // Log audit
      await axios.post(`${API}/audit-logs`, {
        action: 'fixed',
        user_id: 'student',
        details: { 
          group_id: secureConf.group_id, 
          improvement: response.data.overall_security_score - (analysisResult?.overall_security_score || 0)
        },
        security_score_before: analysisResult?.overall_security_score || 0,
        security_score_after: response.data.overall_security_score
      });
      
      setShowComparison(true);
      setActiveTab('comparison');
      loadAuditLogs();
      loadStats();
      setLoading(false);
    } catch (error) {
      console.error('Error applying fix:', error);
      setLoading(false);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const response = await axios.get(`${API}/audit-logs`);
      setAuditLogs(response.data);
    } catch (error) {
      console.error('Error loading audit logs:', error);
    }
  };

  const loadStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'Critical': 'bg-red-100 text-red-800 border-red-300',
      'High': 'bg-orange-100 text-orange-800 border-orange-300',
      'Medium': 'bg-yellow-100 text-yellow-800 border-yellow-300',
      'Low': 'bg-blue-100 text-blue-800 border-blue-300'
    };
    return colors[severity] || 'bg-gray-100 text-gray-800 border-gray-300';
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      {/* Header */}
      <header className="bg-slate-800/50 backdrop-blur-sm border-b border-slate-700 sticky top-0 z-50">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-blue-400" />
              <div>
                <h1 className="text-2xl font-bold text-white" data-testid="app-title">Security Group Analyzer</h1>
                <p className="text-sm text-slate-400">Cloud VM Firewall Misconfiguration Simulator</p>
              </div>
            </div>
            {analysisResult && (
              <div className="flex items-center space-x-4" data-testid="security-score-display">
                <div className="text-right">
                  <p className="text-sm text-slate-400">Security Score</p>
                  <p className={`text-3xl font-bold ${getScoreColor(analysisResult.overall_security_score)}`}>
                    {analysisResult.overall_security_score}/100
                  </p>
                </div>
                <div className={`px-4 py-2 rounded-lg ${getSeverityColor(analysisResult.security_posture)}`}>
                  <p className="font-semibold">{analysisResult.security_posture}</p>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* Stats Bar */}
      {stats && (
        <div className="bg-slate-800/30 border-b border-slate-700" data-testid="stats-bar">
          <div className="container mx-auto px-6 py-3">
            <div className="flex items-center justify-around text-center">
              <div>
                <p className="text-slate-400 text-sm">Total Audits</p>
                <p className="text-white text-xl font-bold">{stats.total_audits}</p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Fixes Applied</p>
                <p className="text-green-400 text-xl font-bold">{stats.total_fixes_applied}</p>
              </div>
              <div>
                <p className="text-slate-400 text-sm">Avg Improvement</p>
                <p className="text-blue-400 text-xl font-bold">+{stats.average_improvement}%</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        {/* Tabs */}
        <div className="flex space-x-2 mb-6 overflow-x-auto" data-testid="navigation-tabs">
          <TabButton
            active={activeTab === 'vulnerable'}
            onClick={() => setActiveTab('vulnerable')}
            icon={<Unlock className="w-4 h-4" />}
            label="Vulnerable Config"
            dataTestId="tab-vulnerable"
          />
          <TabButton
            active={activeTab === 'analysis'}
            onClick={() => setActiveTab('analysis')}
            icon={<AlertTriangle className="w-4 h-4" />}
            label="Risk Analysis"
            dataTestId="tab-analysis"
          />
          <TabButton
            active={activeTab === 'checklist'}
            onClick={() => setActiveTab('checklist')}
            icon={<FileText className="w-4 h-4" />}
            label="Security Checklist"
            dataTestId="tab-checklist"
          />
          {showComparison && (
            <TabButton
              active={activeTab === 'comparison'}
              onClick={() => setActiveTab('comparison')}
              icon={<Target className="w-4 h-4" />}
              label="Before/After"
              dataTestId="tab-comparison"
            />
          )}
          <TabButton
            active={activeTab === 'audit'}
            onClick={() => { setActiveTab('audit'); loadAuditLogs(); }}
            icon={<History className="w-4 h-4" />}
            label="Audit Logs"
            dataTestId="tab-audit"
          />
        </div>

        {/* Vulnerable Configuration Tab */}
        {activeTab === 'vulnerable' && vulnerableConfig && (
          <div className="space-y-6" data-testid="vulnerable-config-view">
            <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-red-500/30">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <Unlock className="w-6 h-6 text-red-400" />
                  <h2 className="text-xl font-bold text-white">Vulnerable Security Group</h2>
                </div>
                <span className="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-sm font-semibold">
                  INSECURE
                </span>
              </div>
              <p className="text-slate-300 mb-4">Group Name: <span className="font-mono text-blue-400">{vulnerableConfig.group_name}</span></p>
              
              {/* Rules Table */}
              <div className="overflow-x-auto">
                <table className="w-full" data-testid="vulnerable-rules-table">
                  <thead>
                    <tr className="border-b border-slate-700">
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Protocol</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Port Range</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Source IP</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Description</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vulnerableConfig.rules.map((rule, index) => (
                      <tr key={rule.rule_id} className="border-b border-slate-700/50 hover:bg-slate-700/30" data-testid={`rule-row-${index}`}>
                        <td className="py-3 px-4 text-white font-mono">{rule.protocol}</td>
                        <td className="py-3 px-4 text-white font-mono">{rule.port_range}</td>
                        <td className="py-3 px-4 text-red-400 font-mono font-bold">{rule.source_ip}</td>
                        <td className="py-3 px-4 text-slate-300">{rule.description}</td>
                        <td className="py-3 px-4">
                          <span className="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs flex items-center space-x-1 w-fit">
                            <XCircle className="w-3 h-3" />
                            <span>Vulnerable</span>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Action Button */}
            <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-lg p-6 border border-blue-500">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xl font-bold text-white mb-2">Apply Security Fix</h3>
                  <p className="text-blue-100">Implement least privilege principle and harden your security group</p>
                </div>
                <button
                  onClick={applySecurityFix}
                  disabled={loading}
                  className="px-6 py-3 bg-white text-blue-600 font-semibold rounded-lg hover:bg-blue-50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2"
                  data-testid="apply-fix-button"
                >
                  <Lock className="w-5 h-5" />
                  <span>{loading ? 'Applying...' : 'Apply Fix Now'}</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Risk Analysis Tab */}
        {activeTab === 'analysis' && analysisResult && (
          <div className="space-y-6" data-testid="risk-analysis-view">
            <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-orange-500/30">
              <div className="flex items-center space-x-3 mb-6">
                <AlertTriangle className="w-6 h-6 text-orange-400" />
                <h2 className="text-xl font-bold text-white">Risk Analysis Results</h2>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <p className="text-slate-400 text-sm mb-1">Total Rules</p>
                  <p className="text-3xl font-bold text-white">{analysisResult.total_rules}</p>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <p className="text-slate-400 text-sm mb-1">Vulnerable Rules</p>
                  <p className="text-3xl font-bold text-red-400">{analysisResult.vulnerable_rules}</p>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <p className="text-slate-400 text-sm mb-1">Security Posture</p>
                  <p className={`text-2xl font-bold ${getScoreColor(analysisResult.overall_security_score)}`}>
                    {analysisResult.security_posture}
                  </p>
                </div>
              </div>

              {/* Risk Assessments */}
              <div className="space-y-4">
                {analysisResult.risk_assessments.map((risk, index) => (
                  <div
                    key={risk.rule_id}
                    className={`border rounded-lg p-5 ${getSeverityColor(risk.severity)} bg-opacity-20`}
                    data-testid={`risk-assessment-${index}`}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex items-center space-x-3">
                        <span className={`px-3 py-1 rounded-full text-sm font-bold ${getSeverityColor(risk.severity)}`}>
                          {risk.severity}
                        </span>
                        <h3 className="font-bold text-lg text-white">{risk.vulnerability_type}</h3>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-slate-400">Risk Score</p>
                        <p className="text-2xl font-bold text-red-400">{risk.risk_score}/100</p>
                      </div>
                    </div>

                    <div className="space-y-3 text-slate-200">
                      <div>
                        <p className="font-semibold text-white mb-2">Attack Scenarios:</p>
                        <ul className="list-disc list-inside space-y-1 ml-2">
                          {risk.attack_scenarios.map((scenario, idx) => (
                            <li key={idx} className="text-sm">{scenario}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="bg-slate-900/30 rounded p-3">
                        <p className="font-semibold text-yellow-400 mb-1">💰 Financial Risk:</p>
                        <p className="text-sm">{risk.financial_risk}</p>
                      </div>

                      <div className="bg-blue-900/30 rounded p-3">
                        <p className="font-semibold text-blue-400 mb-1">✅ Recommendation:</p>
                        <p className="text-sm">{risk.recommendation}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Security Checklist Tab */}
        {activeTab === 'checklist' && checklist.length > 0 && (
          <div className="space-y-6" data-testid="security-checklist-view">
            <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-slate-700">
              <div className="flex items-center space-x-3 mb-6">
                <FileText className="w-6 h-6 text-blue-400" />
                <h2 className="text-xl font-bold text-white">Security Configuration Checklist</h2>
              </div>

              <div className="space-y-3">
                {checklist.map((item, index) => (
                  <div
                    key={item.item_id}
                    className={`border rounded-lg p-4 flex items-start space-x-4 ${
                      item.is_compliant
                        ? 'bg-green-900/20 border-green-500/30'
                        : 'bg-red-900/20 border-red-500/30'
                    }`}
                    data-testid={`checklist-item-${index}`}
                  >
                    <div className="flex-shrink-0 mt-1">
                      {item.is_compliant ? (
                        <CheckCircle className="w-6 h-6 text-green-400" />
                      ) : (
                        <XCircle className="w-6 h-6 text-red-400" />
                      )}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-3 mb-2">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          item.priority === 'Critical' ? 'bg-red-500 text-white' :
                          item.priority === 'High' ? 'bg-orange-500 text-white' :
                          item.priority === 'Medium' ? 'bg-yellow-500 text-white' :
                          'bg-blue-500 text-white'
                        }`}>
                          {item.priority}
                        </span>
                        <span className="text-slate-400 text-sm">{item.category}</span>
                      </div>
                      <p className="text-white font-medium">{item.check_description}</p>
                      <p className={`text-sm mt-1 ${
                        item.is_compliant ? 'text-green-400' : 'text-red-400'
                      }`}>
                        {item.is_compliant ? '✓ Compliant' : '✗ Non-Compliant'}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Comparison Tab */}
        {activeTab === 'comparison' && secureConfig && (
          <div className="space-y-6" data-testid="comparison-view">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Before */}
              <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-red-500/30">
                <div className="flex items-center space-x-3 mb-4">
                  <XCircle className="w-6 h-6 text-red-400" />
                  <h3 className="text-lg font-bold text-white">Before (Vulnerable)</h3>
                </div>
                <div className="space-y-2">
                  {vulnerableConfig?.rules.map((rule, index) => (
                    <div key={index} className="bg-red-900/20 border border-red-500/30 rounded p-3" data-testid={`before-rule-${index}`}>
                      <p className="text-white font-mono text-sm">
                        {rule.protocol} | Port {rule.port_range} | {rule.source_ip}
                      </p>
                      <p className="text-red-400 text-xs mt-1">{rule.description}</p>
                    </div>
                  ))}
                </div>
                {analysisResult && (
                  <div className="mt-4 pt-4 border-t border-slate-700">
                    <p className="text-slate-400 text-sm">Security Score</p>
                    <p className="text-3xl font-bold text-red-400">{analysisResult.overall_security_score}/100</p>
                  </div>
                )}
              </div>

              {/* After */}
              <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-green-500/30">
                <div className="flex items-center space-x-3 mb-4">
                  <CheckCircle className="w-6 h-6 text-green-400" />
                  <h3 className="text-lg font-bold text-white">After (Secured)</h3>
                </div>
                <div className="space-y-2">
                  {secureConfig.rules.map((rule, index) => (
                    <div key={index} className="bg-green-900/20 border border-green-500/30 rounded p-3" data-testid={`after-rule-${index}`}>
                      <p className="text-white font-mono text-sm">
                        {rule.protocol} | Port {rule.port_range} | {rule.source_ip}
                      </p>
                      <p className="text-green-400 text-xs mt-1">{rule.description}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-4 pt-4 border-t border-slate-700">
                  <p className="text-slate-400 text-sm">Security Score</p>
                  <p className="text-3xl font-bold text-green-400">100/100</p>
                </div>
              </div>
            </div>

            {/* Improvements */}
            <div className="bg-gradient-to-r from-green-600 to-green-700 rounded-lg p-6">
              <div className="flex items-center space-x-3 mb-4">
                <TrendingUp className="w-6 h-6 text-white" />
                <h3 className="text-xl font-bold text-white">Security Improvements</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-white">
                <div>
                  <p className="text-green-100 text-sm">Vulnerable Rules Removed</p>
                  <p className="text-3xl font-bold">{analysisResult?.vulnerable_rules || 0}</p>
                </div>
                <div>
                  <p className="text-green-100 text-sm">Score Improvement</p>
                  <p className="text-3xl font-bold">+{100 - (analysisResult?.overall_security_score || 0)}</p>
                </div>
                <div>
                  <p className="text-green-100 text-sm">Compliance Status</p>
                  <p className="text-3xl font-bold">100%</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Audit Logs Tab */}
        {activeTab === 'audit' && (
          <div className="space-y-6" data-testid="audit-logs-view">
            <div className="bg-slate-800/50 backdrop-blur rounded-lg p-6 border border-slate-700">
              <div className="flex items-center space-x-3 mb-6">
                <History className="w-6 h-6 text-purple-400" />
                <h2 className="text-xl font-bold text-white">Audit History</h2>
              </div>

              {auditLogs.length === 0 ? (
                <p className="text-slate-400 text-center py-8">No audit logs yet. Perform some actions to see history.</p>
              ) : (
                <div className="space-y-3">
                  {auditLogs.map((log, index) => (
                    <div
                      key={log.id}
                      className="bg-slate-700/30 border border-slate-600 rounded-lg p-4 hover:bg-slate-700/50 transition-colors"
                      data-testid={`audit-log-${index}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center space-x-3">
                          <Activity className="w-5 h-5 text-blue-400" />
                          <span className={`px-2 py-1 rounded text-xs font-semibold ${
                            log.action === 'fixed' ? 'bg-green-500 text-white' :
                            log.action === 'analyzed' ? 'bg-blue-500 text-white' :
                            'bg-slate-500 text-white'
                          }`}>
                            {log.action.toUpperCase()}
                          </span>
                          <span className="text-white font-medium">User: {log.user_id}</span>
                        </div>
                        <span className="text-slate-400 text-sm">
                          {new Date(log.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div className="text-slate-300 text-sm">
                        {log.security_score_before !== null && log.security_score_after !== null && (
                          <p>Score: {log.security_score_before} → {log.security_score_after} (+{log.security_score_after - log.security_score_before})</p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-slate-800/50 border-t border-slate-700 mt-12">
        <div className="container mx-auto px-6 py-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-slate-300 text-sm">
            <div>
              <h4 className="font-semibold text-white mb-2">About This Project</h4>
              <p>Educational simulation for BTech CSE - Cybersecurity</p>
              <p className="mt-1 text-slate-400">Case Study 88: Security Group Misconfiguration</p>
            </div>
            <div>
              <h4 className="font-semibold text-white mb-2">Key Concepts</h4>
              <ul className="space-y-1 text-slate-400">
                <li>• Principle of Least Privilege</li>
                <li>• Cloud VM Security</li>
                <li>• Firewall Configuration</li>
                <li>• Risk Assessment</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold text-white mb-2">Zero-Cost Security</h4>
              <p className="text-slate-400">Demonstrates security hardening without additional infrastructure costs.</p>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

function TabButton({ active, onClick, icon, label, dataTestId }) {
  return (
    <button
      onClick={onClick}
      data-testid={dataTestId}
      className={`flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors whitespace-nowrap ${
        active
          ? 'bg-blue-600 text-white'
          : 'bg-slate-800/50 text-slate-300 hover:bg-slate-700/50'
      }`}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

export default App;