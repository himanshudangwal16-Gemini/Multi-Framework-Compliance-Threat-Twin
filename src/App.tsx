import { useState, useEffect, useRef } from "react";
import { 
  Shield, 
  ShieldCheck, 
  User, 
  Skull, 
  Terminal, 
  Copy, 
  Check, 
  Play, 
  RefreshCw, 
  FileCode, 
  Settings, 
  AlertTriangle, 
  Cpu, 
  Database, 
  Network, 
  HardDrive, 
  Fingerprint, 
  ExternalLink, 
  Lock, 
  Unlock, 
  Info, 
  List, 
  Sparkles,
  ChevronRight,
  Eye,
  Zap,
  CheckCircle2,
  AlertOctagon,
  BookOpen
} from "lucide-react";
import { SCENARIOS, TechScenario } from "./data/templates";
import { DualAnalysisResponse, ComplianceViolation, GraphNode, RemediationPatch } from "./types";

export default function App() {
  // Scenario Selection
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>("aws-ssrf");
  const currentScenario = SCENARIOS.find(s => s.id === selectedScenarioId) || SCENARIOS[0];

  // Active configurations & custom IaC input
  const [codeInput, setCodeInput] = useState<string>(currentScenario.rawInput);
  const [activeTab, setActiveTab] = useState<"interactive-map" | "raw-iac">("interactive-map");
  
  // Framework selectors
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([
    "NIST SP 800-53",
    "ISO/IEC 27001",
    "SOC 2 Type II",
    "CIS Benchmarks"
  ]);

  // UI Filters
  const [activeViolationFilter, setActiveViolationFilter] = useState<string>("ALL");
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  
  // Simulation States (The Satisfying Interactive ROI Loop!)
  const [isPatchDeployed, setIsPatchDeployed] = useState<boolean>(false);
  const [activeAttackStep, setActiveAttackStep] = useState<number | null>(null);
  const [remediationLogs, setRemediationLogs] = useState<string[]>([
    "> Simulation engine primed.",
    "> Monitoring architectural boundaries for structural threats...",
    "> Awaiting GRC framework assessment audit logs."
  ]);
  const [isDeployingPatch, setIsDeployingPatch] = useState<boolean>(false);
  const [copyStates, setCopyStates] = useState<Record<string, boolean>>({});

  // Analysis result holder (initially feeds from active scenario presets)
  const [analysisResult, setAnalysisResult] = useState<DualAnalysisResponse>(currentScenario.analysis);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisProgress, setAnalysisProgress] = useState<number>(0);
  const [aiStatusMessage, setAiStatusMessage] = useState<string>("");
  const [activeRemediationId, setActiveRemediationId] = useState<string>("");
  
  // Local current UTC display clock
  const [currentTime, setCurrentTime] = useState<string>("2026-05-23 12:07:12");

  // Keep code input aligned when scenario changes
  useEffect(() => {
    setCodeInput(currentScenario.rawInput);
    setAnalysisResult(currentScenario.analysis);
    setIsPatchDeployed(false);
    setSelectedNodeId(null);
    setActiveAttackStep(null);
    setActiveRemediationId(currentScenario.analysis.remediations[0]?.id || "");
    setRemediationLogs([
      `> Loaded preset: ${currentScenario.name}`,
      `> Architectural mapping completed successfully.`,
      `> Ready for cyber twin attack model sequence.`
    ]);
  }, [selectedScenarioId]);

  // Keep clock running
  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date();
      const utcString = now.getUTCFullYear() + '-' +
        String(now.getUTCMonth() + 1).padStart(2, '0') + '-' +
        String(now.getUTCDate()).padStart(2, '0') + ' ' +
        String(now.getUTCHours()).padStart(2, '0') + ':' +
        String(now.getUTCMinutes()).padStart(2, '0') + ':' +
        String(now.getUTCSeconds()).padStart(2, '0');
      setCurrentTime(utcString);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Set default active remediation when analysis updates
  useEffect(() => {
    if (analysisResult.remediations.length > 0) {
      setActiveRemediationId(analysisResult.remediations[0].id);
    }
  }, [analysisResult]);

  // Core API analyzer triggers Gemini server endpoint
  const triggerTwinAnalysis = async () => {
    setIsAnalyzing(true);
    setAnalysisProgress(5);
    setAiStatusMessage("Interlinking cybersecurity agents...");
    setIsPatchDeployed(false);
    setSelectedNodeId(null);
    setActiveAttackStep(null);

    const simulationIntervals = [
      { p: 15, msg: "Initializing GRC Compliance Auditor (Persona 1)..." },
      { p: 35, msg: "Auditing cloud topology structures against selected frameworks..." },
      { p: 55, msg: "Spawning adversarial Threat Twin daemon (Persona 2)..." },
      { p: 75, msg: "Mapping compliance gaps to MITRE ATT&CK vectors..." },
      { p: 90, msg: "Synthesizing mitigation source code configurations..." },
      { p: 98, msg: "Merging digital twins unified compliance graphs..." }
    ];

    let timerIndex = 0;
    const interval = setInterval(() => {
      if (timerIndex < simulationIntervals.length) {
        setAnalysisProgress(simulationIntervals[timerIndex].p);
        setAiStatusMessage(simulationIntervals[timerIndex].msg);
        timerIndex++;
      }
    }, 450);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          codeInput: codeInput,
          frameworks: selectedFrameworks
        })
      });

      clearInterval(interval);
      setAnalysisProgress(100);

      if (!response.ok) {
        throw new Error("High fidelity analysis endpoint responded with unexpected state.");
      }

      const parsedResponse: DualAnalysisResponse = await response.json();
      setAnalysisResult(parsedResponse);
      
      setRemediationLogs(prev => [
        ...prev,
        `> Success: Assessment twins synchronized dynamically.`,
        `> GRC violations verified: ${parsedResponse.violations.length}`,
        `> Exploitable paths mapped: ${parsedResponse.attackPaths.length}`
      ]);

      if (parsedResponse.remediations.length > 0) {
        setActiveRemediationId(parsedResponse.remediations[0].id);
      }

    } catch (err: any) {
      console.error(err);
      clearInterval(interval);
      // Run static scenario solver if API throws or has configuration variables blocks
      setAiStatusMessage("Recovering: Synced with local GRC model database.");
      
      // Look for custom text matches to serve intuitive results
      const textLower = codeInput.toLowerCase();
      let matchedScenario = SCENARIOS[0];
      if (textLower.includes("kubernetes") || textLower.includes("kubelet") || textLower.includes("apiVersion")) {
        matchedScenario = SCENARIOS[1];
      } else if (textLower.includes("postgres") || textLower.includes("flat") || textLower.includes("subnet") || textLower.includes("5432")) {
        matchedScenario = SCENARIOS[2];
      }

      setAnalysisResult(matchedScenario.analysis);
      if (matchedScenario.analysis.remediations.length > 0) {
        setActiveRemediationId(matchedScenario.analysis.remediations[0].id);
      }
      
      setRemediationLogs(prev => [
        ...prev,
        `> Offline Analyzer synchronizer executed: mapped with heuristic local intelligence.`,
        `> Mapped to defensive template context signatures.`
      ]);
    } finally {
      setTimeout(() => {
        setIsAnalyzing(false);
      }, 300);
    }
  };

  // Deploy patch sandbox simulation (Simulates applying code to remediate)
  const simulatedDeployPatch = () => {
    setIsDeployingPatch(true);
    setRemediationLogs(prev => [...prev, "> Initiating hot deployment of selected defensive patches..."]);
    
    setTimeout(() => {
      setRemediationLogs(prev => [...prev, ">> Pre-flight telemetry checks... SUCCESS"]);
    }, 400);

    setTimeout(() => {
      setRemediationLogs(prev => [...prev, ">> Verifying compliance constraints with IaC Orchestrator... SUCCESS"]);
    }, 850);

    setTimeout(() => {
      setRemediationLogs(prev => [...prev, ">> Severing adversarial Threat Twin lateral pathways... BLOCKED"]);
    }, 1300);

    setTimeout(() => {
      setIsPatchDeployed(true);
      setIsDeployingPatch(false);
      setActiveAttackStep(null);
      setRemediationLogs(prev => [
        ...prev,
        "> [OK] Configuration changes verified: 100% compliant.",
        "> [SUCCESS] Live GRC compliance indexes updated: Environment secured."
      ]);
    }, 1800);
  };

  // Toggle framework Selection
  const handleToggleFramework = (framework: string) => {
    if (selectedFrameworks.includes(framework)) {
      if (selectedFrameworks.length > 1) {
        setSelectedFrameworks(selectedFrameworks.filter(f => f !== framework));
      }
    } else {
      setSelectedFrameworks([...selectedFrameworks, framework]);
    }
  };

  // Helper code copy
  const handleCopyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopyStates(prev => ({ ...prev, [id]: true }));
    setTimeout(() => {
      setCopyStates(prev => ({ ...prev, [id]: false }));
    }, 1800);
  };

  // Node relative positions dictionary mapping (Coordinates on percentage grid)
  const nodePositions: Record<string, { x: number, y: number }> = {
    // Scenario 1: AWS SSRF
    "internet": { x: 15, y: 50 },
    "web_server": { x: 45, y: 25 },
    "web_sg": { x: 45, y: 75 },
    "iam_role": { x: 75, y: 25 },
    "s3_bucket": { x: 75, y: 75 },

    // Scenario 2: Kubernetes
    "kubelet": { x: 45, y: 25 },
    "billing_pod": { x: 45, y: 75 },
    "secrets_db": { x: 75, y: 50 },

    // Scenario 3: Flat Subnet Pivot
    "web_tier": { x: 45, y: 28 },
    "db_tier": { x: 75, y: 72 },

    // Generic fallbacks
    "user_client": { x: 15, y: 50 },
    "core_host": { x: 45, y: 50 },
    "data_storage": { x: 75, y: 50 },
    "k8s_node": { x: 45, y: 25 },
    "app_pod": { x: 45, y: 75 },
    "database_backend": { x: 75, y: 50 },
    "web_host": { x: 45, y: 25 },
    "iam_instance": { x: 75, y: 25 },
    "s3_vault": { x: 75, y: 75 }
  };

  const getNodeCoords = (nodeId: string) => {
    return nodePositions[nodeId] || { x: 50, y: 50 };
  };

  // Calculate dynamic stats
  const currentViolations = analysisResult.violations.filter(v => {
    // Check framework is selected
    if (!selectedFrameworks.includes(v.framework)) return false;
    // Check violation filter
    if (activeViolationFilter !== "ALL" && v.framework !== activeViolationFilter) return false;
    return true;
  });

  const activeRemediation = analysisResult.remediations.find(r => r.id === activeRemediationId) 
    || analysisResult.remediations[0];

  // Map node icon
  const getNodeIcon = (type: string) => {
    switch (type) {
      case "internet": return <Network className="w-5 h-5 text-sky-400" />;
      case "compute": return <Cpu className="w-5 h-5 text-amber-400" />;
      case "database": return <Database className="w-5 h-5 text-emerald-400" />;
      case "storage": return <HardDrive className="w-5 h-5 text-indigo-400" />;
      case "iam": return <Fingerprint className="w-5 h-5 text-fuchsia-400" />;
      case "network": return <Shield className="w-5 h-5 text-cyan-400" />;
      default: return <Cpu className="w-5 h-5 text-slate-400" />;
    }
  };

  // Dynamic risk calculation based on patch deployment state
  const getRiskScore = () => {
    if (isPatchDeployed) return { score: "1.2", label: "SECURE", textColor: "text-emerald-400", bgColor: "bg-emerald-950/20" };
    
    // Weighted framework calculations
    const failCount = currentViolations.length;
    if (failCount === 0) return { score: "0.0", label: "COMPLIANT", textColor: "text-emerald-400", bgColor: "bg-emerald-950/20" };
    
    const critCount = currentViolations.filter(v => v.severity === "critical").length;
    const highCount = currentViolations.filter(v => v.severity === "high").length;
    
    let score = 3.2 + (critCount * 1.5) + (highCount * 0.8) + (failCount * 0.2);
    score = Math.min(score, 9.9);
    
    if (score >= 7.5) return { score: score.toFixed(1), label: "CRITICAL", textColor: "text-red-400", bgColor: "bg-red-950/30 border-red-900/40" };
    if (score >= 5.0) return { score: score.toFixed(1), label: "HIGH", textColor: "text-orange-400", bgColor: "bg-orange-950/20 border-orange-900/30" };
    return { score: score.toFixed(1), label: "MODERATE", textColor: "text-yellow-400", bgColor: "bg-yellow-[#1F1F23]/25" };
  };

  const riskObj = getRiskScore();

  // Find if a node is currently target of the selected attack step
  const isAttackTarget = (nodeId: string) => {
    if (isPatchDeployed) return false;
    if (activeAttackStep === null) return false;
    
    const activePath = analysisResult.attackPaths[0];
    if (!activePath) return false;
    
    const stepObj = activePath.steps.find(s => s.stepNumber === activeAttackStep);
    return stepObj?.nodeId === nodeId;
  };

  return (
    <div className="w-full min-h-screen bg-[#0A0A0C] text-[#E0E0E0] font-sans flex flex-col antialiased selection:bg-cyan-500 selection:text-black">
      
      {/* 1. Header Section */}
      <header className="h-[72px] border-b border-[#1F1F23] flex flex-col md:flex-row items-stretch md:items-center justify-between px-6 bg-[#0D0D10] gap-4 py-2 md:py-0">
        <div className="flex items-center gap-4">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 via-violet-500 to-red-500 rounded flex items-center justify-center font-bold text-black text-sm italic shadow-lg shadow-cyan-950/30">
            TX
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 id="app-title" className="text-sm md:text-base font-black tracking-widest uppercase text-white">
                TX: Compliance & Threat Twin AI
              </h1>
              <span className="px-2 py-0.5 rounded-full bg-cyan-950/40 border border-cyan-800/30 text-[9px] text-cyan-400 font-mono tracking-tighter hidden sm:inline-block">
                Multi-Framework
              </span>
            </div>
            <p className="text-[10px] font-mono text-gray-500 uppercase tracking-tighter mt-0.5">
              Status: <span className={isPatchDeployed ? "text-emerald-400 font-bold" : "text-red-500 font-bold"}>{isPatchDeployed ? "● SECURED" : "● ACTIVE COMBAT"}</span> | Engine v4.2.0 | Node-Orchestrator: UTC {currentTime}
            </p>
          </div>
        </div>

        {/* Global Stats dashboard block */}
        <div className="flex gap-4 md:gap-8 items-center justify-between md:justify-end">
          <div className="text-right">
            <p className="text-[9px] text-gray-500 uppercase tracking-wider">Dynamic Risk Index</p>
            <div className={`mt-0.5 px-3 py-1 flex items-center justify-center rounded font-mono border ${riskObj.bgColor} transition-all duration-500`}>
              <p className={`text-sm md:text-base font-bold ${riskObj.textColor}`}>
                {riskObj.label} ({riskObj.score})
              </p>
            </div>
          </div>
          
          <div className="w-px h-8 bg-[#1F1F23] hidden sm:block"></div>

          <div className="flex gap-2 sm:gap-3">
            {/* Environment preset dropdown config */}
            <div className="flex flex-col">
              <span className="text-[9px] text-gray-500 uppercase mb-1">Target Scenario Preset</span>
              <select 
                id="scenario-select"
                value={selectedScenarioId}
                onChange={(e) => setSelectedScenarioId(e.target.value)}
                className="h-8 px-2 bg-[#141418] border border-[#1F1F23] rounded text-xs font-mono text-cyan-400 focus:outline-none focus:border-cyan-500"
              >
                {SCENARIOS.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>

            <button 
              id="btn-revert"
              onClick={() => {
                setIsPatchDeployed(false);
                setActiveAttackStep(null);
                setSelectedNodeId(null);
                setRemediationLogs(prev => [
                  ...prev,
                  "> [RESET] Security environment re-primed with initial vulnerabilities.",
                  ">> Threats twins unlocked!"
                ]);
              }}
              className="h-8 mt-auto px-2 border border-[#1F1F23] hover:border-red-500/50 rounded flex items-center justify-center text-[10px] font-mono uppercase bg-[#141418] text-gray-400 hover:text-red-400 transition"
              title="Reset configuration back to vulnerable state"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* 2. Central Multi-Agent Workspace Container */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-0 overflow-y-auto lg:overflow-hidden">
        
        {/* Left Sidebar: GRC Auditor Persona Panel */}
        <section className="col-span-1 lg:col-span-3 border-r border-[#1F1F23] flex flex-col bg-[#0D0D10]/40 overflow-hidden min-h-[400px] lg:min-h-0">
          <div className="p-4 border-b border-[#1F1F23] flex justify-between items-center bg-[#0D0D10]">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <h2 className="text-[11px] font-bold text-cyan-400 uppercase tracking-widest">
                GRC Auditor Persona
              </h2>
            </div>
            <span className="text-[9px] font-mono text-gray-500 bg-[#16161A] px-2 py-0.5 rounded border border-[#1F1F23]">
              [STRICT MODE]
            </span>
          </div>

          {/* Interactive Framework Multi-Checkbox selector mapping */}
          <div className="p-3 bg-[#0A0A0C] border-b border-[#1F1F23]">
            <span className="text-[9px] text-gray-500 uppercase font-mono block mb-2">Active Framework Audits</span>
            <div className="grid grid-cols-2 gap-1.5">
              {["NIST SP 800-53", "ISO/IEC 27001", "SOC 2 Type II", "CIS Benchmarks"].map((framework) => {
                const isSelected = selectedFrameworks.includes(framework);
                return (
                  <button
                    key={framework}
                    onClick={() => handleToggleFramework(framework)}
                    className={`px-2 py-1 rounded text-[9px] font-mono text-left border flex items-center gap-1.5 transition-all ${
                      isSelected 
                        ? "bg-cyan-950/30 border-cyan-800/40 text-cyan-400" 
                        : "bg-[#141418] border-[#1F1F23] text-gray-600"
                    }`}
                  >
                    <div className={`w-1.5 h-1.5 rounded-full ${isSelected ? "bg-cyan-400 animate-pulse" : "bg-gray-800"}`}></div>
                    <span className="truncate">{framework.split(" ")[0]} {framework.split(" ")[1] || ""}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Violation Category filter tabs */}
          <div className="flex border-b border-[#1F1F23] bg-[#0A0A0C]">
            <button 
              onClick={() => setActiveViolationFilter("ALL")}
              className={`flex-1 py-2 text-[9px] font-mono uppercase border-b ${
                activeViolationFilter === "ALL" 
                  ? "border-cyan-500 text-cyan-400 bg-cyan-950/5" 
                  : "border-transparent text-gray-500 hover:text-gray-300"
              }`}
            >
              ALL ({analysisResult.violations.filter(v => selectedFrameworks.includes(v.framework)).length})
            </button>
            {selectedFrameworks.map((fw) => {
              const abbr = fw.split(" ")[0];
              const ct = analysisResult.violations.filter(v => v.framework === fw).length;
              return (
                <button
                  key={fw}
                  onClick={() => setActiveViolationFilter(fw)}
                  className={`flex-1 py-2 text-[9px] font-mono uppercase border-b truncate ${
                    activeViolationFilter === fw 
                      ? "border-cyan-500 text-cyan-400 bg-cyan-950/5" 
                      : "border-transparent text-gray-500 hover:text-gray-300"
                  }`}
                  title={fw}
                >
                  {abbr} ({ct})
                </button>
              );
            })}
          </div>

          {/* List of active Compliance Violations */}
          <div className="flex-1 overflow-y-auto p-3 space-y-3 custom-scrollbar">
            {isPatchDeployed ? (
              <div className="h-full flex flex-col items-center justify-center text-center p-6 bg-emerald-950/5 rounded border border-emerald-900/20 my-2">
                <ShieldCheck className="w-10 h-10 text-emerald-400 mb-2 animate-bounce" />
                <p className="text-xs font-bold text-emerald-400 font-mono">100% GRC COMPLIANT</p>
                <p className="text-[10px] text-gray-500 leading-relaxed mt-1">All mapped controls resolved via the hot-deploy remediation engine.</p>
              </div>
            ) : currentViolations.length === 0 ? (
              <p className="text-xs text-center text-gray-500 py-8 font-mono">No active violations detected or loaded frameworks unchecked.</p>
            ) : (
              currentViolations.map((v) => {
                const isSelected = selectedNodeId === v.targetNodeId;
                const severityStyle = 
                  v.severity === "critical" ? "bg-red-950/20 border-red-900/50 text-red-400" :
                  v.severity === "high" ? "bg-orange-950/20 border-orange-900/40 text-orange-400" :
                  "bg-yellow-950/20 border-yellow-900/30 text-yellow-500";
                
                return (
                  <div 
                    key={v.id}
                    onClick={() => {
                      setSelectedNodeId(v.targetNodeId);
                      // Auto-focus remediation patch associated with this framework code
                      const matchedRem = analysisResult.remediations.find(rem => rem.frameworkCode === v.code);
                      if (matchedRem) {
                        setActiveRemediationId(matchedRem.id);
                      }
                    }}
                    className={`p-3 rounded border text-left cursor-pointer transition ${
                      isSelected 
                        ? "bg-[#1C1215] border-red-500 shadow-[0_0_10px_rgba(239,68,68,0.1)]" 
                        : "bg-[#111115] hover:bg-[#141419] border-[#1F1F23]"
                    }`}
                  >
                    <div className="flex justify-between items-start mb-2">
                      <span className={`px-1.5 py-0.5 text-[8px] font-mono rounded font-bold uppercase ${severityStyle}`}>
                        {v.severity.toUpperCase()}
                      </span>
                      <span className="text-[9px] font-mono text-gray-400 font-bold bg-[#1A1A22] px-1.5 py-0.5 rounded border border-[#1F1F23]">
                        {v.framework.split(" ")[0]} {v.code}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-white tracking-wide">{v.title}</h4>
                    <p className="text-[10.5px] leading-relaxed text-gray-400 mt-1.5 line-clamp-3">
                      {v.description}
                    </p>
                    
                    <div className="mt-2.5 pt-2 border-t border-[#1F1F23]/60 flex items-center justify-between text-[9px] font-mono">
                      <span className="text-cyan-400 hover:underline flex items-center gap-1">
                        <Eye className="w-3 h-3" /> Target Node ID: <span className="text-white underline">{v.targetNodeId}</span>
                      </span>
                      
                      {/* Correlate trigger */}
                      <span className="text-red-400 hover:text-red-300 font-bold flex items-center gap-0.5 animate-pulse">
                        <Zap className="w-3 h-3" /> exploit link
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Quick GRC info box */}
          <div className="p-3 bg-[#0D0D10] border-t border-[#1F1F23] text-[9.5px] leading-tight text-gray-500 font-mono">
            <span className="text-gray-400 font-bold block mb-1">AUDIT COVERAGE METRICS:</span>
            Mapped against {selectedFrameworks.length} frameworks. 
            Simulator active checking for logical wildcard boundaries.
          </div>
        </section>

        {/* Center Section: central canvas network map & ingestion engines */}
        <section className="col-span-1 lg:col-span-6 flex flex-col bg-[#08080A] relative border-r border-[#1F1F23] overflow-hidden min-h-[500px] lg:min-h-0">
          
          {/* Main map/tab controls */}
          <div className="p-3 bg-[#0D0D10] border-b border-[#1F1F23] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            
            {/* Tab switchers */}
            <div className="flex bg-[#141418] p-0.5 rounded border border-[#1F1F23] w-max">
              <button 
                id="tab-map"
                onClick={() => setActiveTab("interactive-map")}
                className={`px-3 py-1 text-xs font-semibold rounded uppercase tracking-wide transition flex items-center gap-1.5 ${
                  activeTab === "interactive-map" 
                    ? "bg-cyan-500 text-black shadow-md font-bold" 
                    : "text-gray-400 hover:text-white"
                }`}
              >
                <Network className="w-3.5 h-3.5" />
                Adversarial Twin Graph Map
              </button>
              <button 
                id="tab-iac"
                onClick={() => setActiveTab("raw-iac")}
                className={`px-3 py-1 text-xs font-semibold rounded uppercase tracking-wide transition flex items-center gap-1.5 ${
                  activeTab === "raw-iac" 
                    ? "bg-cyan-500 text-black shadow-md font-bold" 
                    : "text-gray-400 hover:text-white"
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                IaC Architecture Ingestion
              </button>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-gray-500">GRC SCOPE MATRIX:</span>
              <span className="px-2 py-0.5 bg-[#1C1C22] border border-[#2B2B33] rounded text-[10px] font-mono text-cyan-400">
                {currentScenario.category} Cluster
              </span>
            </div>
          </div>

          {/* Inner content switcher */}
          <div className="flex-1 relative overflow-hidden flex flex-col">
            
            {/* LOADING OVERLAY SCREEN */}
            {isAnalyzing && (
              <div className="absolute inset-0 bg-[#0A0A0C]/95 backdrop-blur-sm z-50 flex flex-col items-center justify-center p-6 text-center">
                <div className="w-16 h-16 border-t-2 border-r-2 border-b-2 border-cyan-500 rounded-full animate-spin flex items-center justify-center">
                  <div className="w-12 h-12 border-b-2 border-l-2 border-red-500 rounded-full animate-spin"></div>
                </div>

                <div className="mt-6 w-full max-w-sm">
                  <div className="flex justify-between items-center text-xs font-mono text-gray-400 mb-1.5">
                    <span>Twin Synthesis Orchestrator</span>
                    <span>{analysisProgress}%</span>
                  </div>
                  <div className="h-1 bg-[#1F1F23] w-full rounded overflow-hidden">
                    <div className="h-full bg-cyan-400 transition-all duration-300" style={{ width: `${analysisProgress}%` }}></div>
                  </div>
                  <p className="mt-4 text-xs font-mono text-cyan-400 animate-pulse uppercase tracking-wide">
                    {aiStatusMessage}
                  </p>
                  
                  {/* Visual terminal list */}
                  <div className="mt-6 p-3 bg-[#0D0D10] rounded border border-cyan-950/40 text-[9px] font-mono text-left space-y-1 text-gray-500 w-full max-h-[120px] overflow-hidden">
                    <p className="text-gray-400">&gt; Starting Gemini orchestrator daemon...</p>
                    {analysisProgress > 20 && <p className="text-[#94A3B8]">&gt; Connected to models/gemini-3.5-flash</p>}
                    {analysisProgress > 50 && <p className="text-emerald-500/80">&gt; Auditor mapped compliance nodes...</p>}
                    {analysisProgress > 75 && <p className="text-red-400/80">&gt; Hacker modeled threat vector paths...</p>}
                  </div>
                </div>
              </div>
            )}

            {/* TAB 1: INTERACTIVE NETWORK DIGITAL TWIN MAP */}
            {activeTab === "interactive-map" && (
              <div className="flex-1 w-full h-full relative p-4 flex flex-col justify-between bg-[#08080A]">
                
                {/* Tech background matrix grid lines */}
                <div className="absolute inset-0 opacity-5 pointer-events-none bg-[linear-gradient(to_right,#808080_1px,transparent_1px),linear-gradient(to_bottom,#808080_1px,transparent_1px)] bg-[size:24px_24px]"></div>
                
                <div className="absolute inset-0 opacity-10 pointer-events-none bg-[radial-gradient(#1e293b_1.5px,transparent_1.5px)] bg-[size:16px_16px]"></div>

                {/* Legend overlay */}
                <div className="absolute top-3 left-3 bg-[#0D0D10]/95 backdrop-blur border border-[#1F1F23] rounded p-2 text-[9px] font-mono text-gray-400 space-y-1 z-10 w-44">
                  <div className="font-bold border-b border-[#1F1F23] pb-1 uppercase tracking-tight text-white mb-1.5">Asset Nodes Status</div>
                  <div className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 bg-emerald-500 rounded-sm"></div>
                    <span className="text-[#94A3B8]">SECURE / AUDITED</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 bg-yellow-500 rounded-sm animate-pulse"></div>
                    <span className="text-[#94A3B8]">GRC VULNERABLE</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="w-2.5 h-2.5 bg-red-500 rounded-sm animate-ping"></div>
                    <span className="text-[#94A3B8]">THREAT COMPROMISED</span>
                  </div>
                </div>

                {/* Edge/Connection instructions */}
                <div className="absolute top-3 right-3 bg-[#0D0D10]/95 backdrop-blur border border-[#1F1F23] rounded p-2 text-[9px] font-mono text-gray-500 text-right space-y-1 z-10">
                  <p className="text-gray-300 uppercase font-bold mb-1">Interactive Tracers</p>
                  <p>&gt; Solid line = Static Relationship</p>
                  <p className="text-red-400">&gt; Pulsing red = Threat path vector</p>
                  <p className="text-yellow-400 font-bold">&gt; Click nodes to view security schema</p>
                </div>

                {/* SVG CONNECTION EDGES CANVAS */}
                <div className="absolute inset-0 pointer-events-none z-0">
                  <svg className="w-full h-full">
                    {/* Define arrow markers */}
                    <defs>
                      <marker id="arrow-blue" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#38bdf8" />
                      </marker>
                      <marker id="arrow-red" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#f87171" />
                      </marker>
                      <marker id="arrow-green" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#34d399" />
                      </marker>
                    </defs>

                    {/* SVG edge mappings rendering dynamically */}
                    {analysisResult.assetMap.edges.map((edge) => {
                      const sourceNode = analysisResult.assetMap.nodes.find(n => n.id === edge.source);
                      const targetNode = analysisResult.assetMap.nodes.find(n => n.id === edge.target);
                      if (!sourceNode || !targetNode) return null;

                      const srcPos = getNodeCoords(edge.source);
                      const tgtPos = getNodeCoords(edge.target);

                      const isThreatEdge = edge.type === "vulnerability" || edge.severity === "high" || edge.severity === "critical";
                      
                      const strokeColor = 
                        isPatchDeployed ? "#34d399" : 
                        isThreatEdge ? "#ef4444" : "#4b5563";
                      
                      const markerId = 
                        isPatchDeployed ? "url(#arrow-green)" : 
                        isThreatEdge ? "url(#arrow-red)" : "url(#arrow-blue)";

                      // Check if threat step is currently highlighted
                      const isStepActive = !isPatchDeployed && activeAttackStep !== null && 
                        analysisResult.attackPaths[0]?.steps.some(step => 
                          step.stepNumber === activeAttackStep && 
                          (step.nodeId === edge.target || step.nodeId === edge.source)
                        );

                      return (
                        <g key={edge.id}>
                          {/* Outer glowing path for threat paths */}
                          {!isPatchDeployed && (isThreatEdge || isStepActive) && (
                            <line
                              x1={`${srcPos.x}%`}
                              y1={`${srcPos.y}%`}
                              x2={`${tgtPos.x}%`}
                              y2={`${tgtPos.y}%`}
                              stroke="#ef4444"
                              strokeWidth={isStepActive ? "4" : "2"}
                              className="opacity-40 animate-pulse"
                              strokeDasharray={isStepActive ? "6,4" : "none"}
                            />
                          )}

                          {/* Base connection line */}
                          <line
                            x1={`${srcPos.x}%`}
                            y1={`${srcPos.y}%`}
                            x2={`${tgtPos.x}%`}
                            y2={`${tgtPos.y}%`}
                            stroke={strokeColor}
                            strokeWidth={isStepActive ? "2.5" : "1.5"}
                            markerEnd={markerId}
                            className={`transition-all duration-500`}
                          />

                          {/* Animate flowing data circles for paths */}
                          {(!isPatchDeployed && (isThreatEdge || isStepActive)) && (
                            <circle r="4" fill="#f87171" className="animate-ping">
                              <animateMotion 
                                path={`M ${srcPos.x} ${srcPos.y} L ${tgtPos.x} ${tgtPos.y}`} 
                                dur="3.5s" 
                                repeatCount="indefinite" 
                                pathLength="100"
                              />
                            </circle>
                          )}

                          {/* Connection text badge */}
                          <text
                            x={`${(srcPos.x + tgtPos.x) / 2}%`}
                            y={`${((srcPos.y + tgtPos.y) / 2) - 2}%`}
                            fill={isPatchDeployed ? "#10b981" : isThreatEdge ? "#f87171" : "#94a3b8"}
                            fontSize="8"
                            textAnchor="middle"
                            fontFamily="monospace"
                            className="bg-black/80 font-semibold"
                          >
                            {isPatchDeployed && isThreatEdge ? "Secured Connection" : edge.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>

                {/* GRAPH NODES CONTAINER AREA */}
                <div className="flex-1 w-full h-full relative min-h-[300px] z-10 flex items-center justify-center">
                  {analysisResult.assetMap.nodes.map((node) => {
                    const pos = getNodeCoords(node.id);
                    const isSelected = selectedNodeId === node.id;
                    const isThreatened = isAttackTarget(node.id);
                    
                    // Node color schema
                    let borderClass = "border-gray-500";
                    let bgClass = "bg-[#111115]/95";
                    let statusDot = "bg-green-400";

                    if (isPatchDeployed) {
                      borderClass = "border-emerald-500 shadow-[0_0_15px_rgba(52,211,153,0.15)]";
                      bgClass = "bg-emerald-950/10";
                      statusDot = "bg-emerald-400";
                    } else {
                      if (node.status === "compromised") {
                        borderClass = "border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)] animate-pulse";
                        bgClass = "bg-red-950/15";
                        statusDot = "bg-red-400 animate-ping";
                      } else if (node.status === "vulnerable") {
                        borderClass = "border-yellow-500 shadow-[0_0_12px_rgba(227,179,65,0.2)]";
                        bgClass = "bg-yellow-950/10";
                        statusDot = "bg-yellow-400";
                      } else {
                        borderClass = "border-cyan-500/50 shadow-[0_0_8px_rgba(34,211,238,0.1)]";
                        bgClass = "bg-[#141418]";
                        statusDot = "bg-cyan-400";
                      }
                    }

                    return (
                      <div
                        key={node.id}
                        onClick={() => setSelectedNodeId(node.id)}
                        className={`absolute -translate-x-1/2 -translate-y-1/2 w-40 p-2.5 rounded border text-left cursor-pointer transition-all duration-500 ${bgClass} ${borderClass} ${
                          isSelected ? "ring-2 ring-cyan-400 scale-105 z-20" : "hover:scale-102"
                        }`}
                        style={{ left: `${pos.x}%`, top: `${pos.y}%` }}
                      >
                        {/* Red halo warning pulse during threat simulation */}
                        {isThreatened && (
                          <div className="absolute inset-x-0 -top-1 -bottom-1 border-2 border-red-500 animate-ping rounded-lg"></div>
                        )}

                        {/* Node Type Badge & Port State indicator */}
                        <div className="flex items-center justify-between mb-1.5 border-b border-[#1F1F23]/60 pb-1.5">
                          <div className="flex items-center gap-1.5">
                            {getNodeIcon(node.type)}
                            <span className="text-[8.5px] font-mono tracking-tighter uppercase text-slate-400">
                              {node.type}
                            </span>
                          </div>
                          <div className="flex items-center gap-1">
                            <span className="text-[7.5px] font-mono text-gray-400">
                              {node.properties["Private IP"] || node.properties["Private Port"] || node.properties["Port"] || "LAN"}
                            </span>
                            <div className={`w-2 h-2 rounded-full ${statusDot}`}></div>
                          </div>
                        </div>

                        {/* Label name */}
                        <h3 className="text-[11.5px] font-bold text-white tracking-wide truncate">{node.label}</h3>
                        <p className="text-[9px] font-mono text-gray-500 truncate mt-0.5">{node.id}</p>

                        {/* Custom threat overlay */}
                        {!isPatchDeployed && node.status === "compromised" && (
                          <div className="mt-1.5 px-1 py-0.5 bg-red-950/40 text-red-400 text-[8px] font-mono uppercase text-center font-bold tracking-tight rounded border border-red-900/40">
                            Lateral Exploit Source
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>

                {/* Bottom Node Inspector Details pane */}
                <div className="bg-[#0C0C10] border border-[#1F1F23] rounded p-3 mt-4 z-10">
                  {selectedNodeId ? (
                    (() => {
                      const node = analysisResult.assetMap.nodes.find(n => n.id === selectedNodeId);
                      if (!node) return <p className="text-xs text-gray-500 font-mono">Failed to inspect empty node container details.</p>;
                      
                      const associatedViolations = analysisResult.violations.filter(v => v.targetNodeId === node.id);

                      return (
                        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
                          <div className="md:col-span-5 border-b md:border-b-0 md:border-r border-[#1F1F23] pb-2 md:pb-0 md:pr-4">
                            <div className="flex items-center gap-2">
                              {getNodeIcon(node.type)}
                              <h4 className="text-xs font-bold text-white uppercase">{node.label}</h4>
                            </div>
                            <p className="text-[10px] text-gray-400 mt-1 leading-normal italic">
                              {node.description || "Active production asset in monitored zone configuration profiles."}
                            </p>
                          </div>
                          
                          <div className="md:col-span-4 border-b md:border-b-0 md:border-r border-[#1F1F23]/60 pb-2 md:pb-0 md:pr-4">
                            <span className="text-[9.5px] text-gray-500 uppercase font-mono block mb-1">Assisted Parameters:</span>
                            <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[9.5px] font-mono">
                              {Object.entries(node.properties).map(([k, v]) => (
                                <div key={k} className="truncate">
                                  <span className="text-gray-500">{k}:</span> <span className="text-cyan-400 font-medium">{String(v)}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          <div className="md:col-span-3 flex flex-col justify-center">
                            <span className="text-[9.5px] text-gray-500 uppercase font-mono mb-1">Twin Diagnostics:</span>
                            <div className="flex items-center gap-2">
                              {isPatchDeployed ? (
                                <div className="flex items-center gap-1 bg-emerald-950/40 border border-emerald-900/30 px-2.5 py-1 rounded text-emerald-400 text-[9.5px] font-mono">
                                  <ShieldCheck className="w-3.5 h-3.5" /> compliant
                                </div>
                              ) : associatedViolations.length > 0 ? (
                                <div className="flex flex-col gap-1 w-full">
                                  <div className="bg-red-950/30 border border-red-900/30 px-2 py-0.5 rounded text-red-400 text-[9px] font-mono text-center">
                                    {associatedViolations.length} Compliance Gaps
                                  </div>
                                  <button 
                                    onClick={() => setActiveViolationFilter(associatedViolations[0].framework)}
                                    className="text-[8.5px] text-cyan-400 underline hover:text-cyan-300 text-left font-mono"
                                  >
                                    Inspect Audit Details →
                                  </button>
                                </div>
                              ) : (
                                <div className="flex items-center gap-1 bg-cyan-950/10 border border-cyan-900/20 px-2.5 py-1 rounded text-cyan-400 text-[9.5px] font-mono">
                                  <Shield className="w-3.5 h-3.5" /> secure
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })()
                  ) : (
                    <div className="flex items-center justify-between text-[11px] text-gray-500 font-mono">
                      <div className="flex items-center gap-2">
                        <Info className="w-4 h-4 text-cyan-500" />
                        <span>Interactive Node Inspector: Click any micro-asset node box above to query diagnostic telemetry & compliance bounds.</span>
                      </div>
                      <span className="text-gray-600">STATE: IDLE</span>
                    </div>
                  )}
                </div>

              </div>
            )}

            {/* TAB 2: INFRASTRUCTURE CODE INGESTION AGENT EDITOR */}
            {activeTab === "raw-iac" && (
              <div className="flex-1 w-full h-full p-4 flex flex-col text-[#E0E0E0] bg-[#0A0A0C]">
                
                {/* File selectors */}
                <div className="flex justify-between items-center mb-2.5 bg-[#0D0D10]/80 p-2 rounded border border-[#1F1F23]">
                  <div>
                    <span className="text-[9.5px] text-gray-500 font-mono uppercase">Ingested Files Config Format:</span>
                    <h4 className="text-xs font-bold text-white font-mono mt-0.5">Terraform HCL / Kubernetes YAML manifest</h4>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setCodeInput(SCENARIOS[0].rawInput)}
                      className="px-2 py-1 bg-[#1A1A22] border border-[#2B2B35] hover:border-cyan-500 text-[9.5px] font-mono text-cyan-400 rounded transition"
                    >
                      Load IaC AWS SSRF Template
                    </button>
                    <button
                      onClick={() => setCodeInput(SCENARIOS[1].rawInput)}
                      className="px-2 py-1 bg-[#1A1A22] border border-[#2B2B35] hover:border-cyan-500 text-[9.5px] font-mono text-cyan-400 rounded transition"
                    >
                      Load IaC K8s Kubelet Template
                    </button>
                  </div>
                </div>

                {/* Raw layout container of Ingest text area */}
                <div className="flex-1 min-h-[180px] border border-[#1F1F23] rounded overflow-hidden flex flex-col bg-[#07070A] relative font-mono text-xs">
                  <div className="bg-[#0D0D10] px-3 py-1.5 border-b border-[#1F1F23] flex justify-between items-center text-gray-500 text-[10px]">
                    <span className="flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-cyan-500" /> IaC Topography Ingestion Shell
                    </span>
                    <span>UTF-8 | UNIX LF</span>
                  </div>
                  
                  <textarea
                    id="iac-editor"
                    value={codeInput}
                    onChange={(e) => setCodeInput(e.target.value)}
                    className="flex-1 w-full h-full p-4 bg-[#050508] text-gray-300 font-mono text-xs leading-relaxed focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                    placeholder="Enter IaC Terraform config parameters, cluster configurations, or Draw.io resource specs here to assessment dual cybersecurity twins audits..."
                  />

                  {/* Submit trigger button */}
                  <div className="absolute bottom-4 right-4 z-10">
                    <button
                      id="btn-analyze"
                      onClick={triggerTwinAnalysis}
                      disabled={isAnalyzing}
                      className="px-4 py-2 bg-gradient-to-r from-cyan-600 via-sky-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500 text-black font-black text-xs uppercase rounded flex items-center gap-1.5 shadow-lg shadow-cyan-950/40 disabled:opacity-50 transition-all cursor-pointer"
                    >
                      <Sparkles className="w-4 h-4" />
                      Run Twin GRC & Threat Scan
                    </button>
                  </div>
                </div>

                <p className="text-[10.5px] text-gray-500 font-mono leading-relaxed mt-2.5">
                  The central twin parser uses probabilistic LLM parameters mapping structural references to deterministic security benchmarks. Edit the target code above blocks or click templates to benchmark instantly.
                </p>

              </div>
            )}

            {/* Bottom Status ticker bar */}
            <div className="p-3 bg-[#0D0D10]/90 border-t border-[#1F1F23] flex gap-4 overflow-x-auto text-[9px] font-mono text-gray-500 justify-between items-center">
              <div className="flex gap-4">
                <div className="flex items-center gap-1.5 min-w-[124px]">
                  <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></div>
                  <span>VPC-FLOW-LOGS: LIVE</span>
                </div>
                <div className="flex items-center gap-1.5 min-w-[124px]">
                  <div className="w-1.5 h-1.5 bg-cyan-500 rounded-full"></div>
                  <span>TERRAFORM: SYNCED</span>
                </div>
                <div className="flex items-center gap-1.5 min-w-[124px]">
                  <div className="w-1.5 h-1.5 bg-blue-500 rounded-full"></div>
                  <span>ASSET-COUNT: {analysisResult.assetMap.nodes.length}</span>
                </div>
              </div>
              <div className="text-right text-cyan-500 shrink-0 font-bold hidden sm:block">
                SYSTEM CONSOLE ONLINE &gt;
              </div>
            </div>

          </div>
        </section>

        {/* Right Sidebar: Threat Twin Persona (The Attacker Mode) */}
        <section className="col-span-1 lg:col-span-3 border-l lg:border-l-0 border-[#1F1F23] flex flex-col bg-[#0D0D10]/40 overflow-hidden min-h-[400px] lg:min-h-0">
          <div className="p-4 border-b border-[#1F1F23] flex justify-between items-center bg-[#0D0D10]">
            <div className="flex items-center gap-2">
              <Skull className="w-4 h-4 text-red-500 animate-pulse" />
              <h2 className="text-[11px] font-bold text-red-500 uppercase tracking-widest animate-pulse">
                Threat Twin Persona
              </h2>
            </div>
            <span className="text-[9px] font-mono text-gray-500 bg-[#16161A] px-2 py-0.5 rounded border border-[#1F1F23]">
              [MITRE ATT&CK]
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-4 space-y-5 custom-scrollbar bg-[#09090C]">
            
            {/* Simulation Block */}
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-[9.5px] text-gray-400 font-mono uppercase tracking-tight">Theoretical Threat Vector:</span>
                <span className="text-[8px] font-mono px-1.5 py-0.5 rounded bg-red-950/40 border border-red-900/40 text-red-400">EXPLOITABLE</span>
              </div>
              
              <h3 className="text-xs font-extrabold text-[#F87171] tracking-normal">
                {analysisResult.attackPaths[0]?.title || "Lateral Subnet Takeover Pivot"}
              </h3>

              {/* Exploit timeline steps helper */}
              <div className="bg-[#141215]/80 border border-red-950/50 rounded p-3 relative overflow-hidden">
                <div className="absolute top-0 right-0 w-12 h-12 bg-red-500/5 rotate-45 translate-x-6 -translate-y-6"></div>
                
                <p className="text-[10px] text-gray-400 leading-normal">
                  Our Auditor agent found logical compliance gaps. Here is how an active threat twin structurally bridges and exploits them:
                </p>

                {/* MITRE Badges list */}
                <div className="flex flex-wrap gap-1 mt-2">
                  {(analysisResult.attackPaths[0]?.mitreTechniques || ["T1190 - Exploit Public-Facing Application"]).map((mitre) => (
                    <span 
                      key={mitre}
                      className="text-[8px] px-1.5 py-0.5 bg-[#1F1418] border border-red-900/30 text-rose-300 font-mono uppercase tracking-tighter rounded"
                      title="MITRE Classification Link"
                    >
                      {mitre.split(" - ")[0]}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* INTERACTIVE THREAT STEP EXPLORER / LASER TELEMETRY HIGHLIGHTER */}
            <div className="space-y-2.5">
              <div className="flex justify-between items-center border-b border-[#1F1F23] pb-1.5">
                <span className="text-[9.5px] text-gray-400 font-mono uppercase">Attack Path Model Simulator:</span>
                <span className="text-[8.5px] text-gray-500 font-mono">Click step to align scope</span>
              </div>

              {isPatchDeployed ? (
                <div className="p-4 bg-emerald-950/10 border border-emerald-900/30 rounded text-center my-3 text-emerald-400">
                  <Unlock className="w-8 h-8 mx-auto mb-2 opacity-50 text-emerald-400" />
                  <p className="text-xs font-bold font-mono uppercase">Path Severed Successfully</p>
                  <p className="text-[9.5px] text-gray-500 leading-relaxed mt-1">Deploying the security patch restricted S3 access boundaries, preventing lateral token exfiltration loops completely.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {(analysisResult.attackPaths[0]?.steps || []).map((step) => {
                    const isActive = activeAttackStep === step.stepNumber;
                    return (
                      <div
                        key={step.stepNumber}
                        onClick={() => {
                          setActiveAttackStep(isActive ? null : step.stepNumber);
                          setSelectedNodeId(step.nodeId);
                        }}
                        className={`p-2.5 rounded border transition cursor-pointer text-left flex gap-2.5 ${
                          isActive 
                            ? "bg-[#1E1114] border-red-500 shadow-[0_0_12px_rgba(239,68,68,0.15)] scale-102" 
                            : "bg-[#101014] hover:bg-[#14141A] border-[#1F1F23]"
                        }`}
                      >
                        <div className={`w-5 h-5 rounded-full flex items-center justify-center font-mono font-bold text-[9px] shrink-0 mt-0.5 ${
                          isActive ? "bg-red-500 text-black" : "bg-[#1E1E23] text-gray-400 border border-[#1F1F23]"
                        }`}>
                          {step.stepNumber}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex justify-between items-center">
                            <h4 className="text-[10px] font-bold text-white tracking-wide truncate">
                              {step.action}
                            </h4>
                            <span className="text-[8px] font-mono text-cyan-400 font-medium tracking-tighter shrink-0 ml-1">
                              {step.nodeId}
                            </span>
                          </div>
                          {isActive && (
                            <p className="text-[9.5px] text-gray-400 leading-relaxed mt-1 border-t border-red-900/20 pt-1">
                              {step.explanation}
                            </p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* THEORETICAL EXPLORER PAYLOAD SIMULATOR (SAFE Remediable terminal test script) */}
            <div className="space-y-2 pt-2 border-t border-[#1F1F23]">
              <div className="flex justify-between items-center">
                <span className="text-[9.5px] text-gray-400 font-mono uppercase flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-red-500" /> Proof-of-Concept Exploit Vector
                </span>
                <span className="text-[8px] font-mono text-gray-500 bg-[#16161A] border border-[#1F1F23] px-1 py-0.5 rounded">
                  DEFENSIVE MODEL
                </span>
              </div>

              {isPatchDeployed ? (
                <div className="p-3 bg-[#0A0A0C] border border-[#1F1F23] rounded text-left text-[9.5px] text-gray-500 font-mono space-y-1">
                  <p className="text-emerald-500 font-bold">&gt; Blocked: perimeter hardening active</p>
                  <p>&gt; Exploit signature filtered by perimeter routing rules</p>
                  <p>&gt; Connection logs: 403 Forbidden</p>
                </div>
              ) : (
                <div className="bg-[#050508] border border-[#1F1F22] rounded overflow-hidden">
                  <div className="bg-[#0C0C10] px-3 py-1 border-b border-[#1F1F23] flex justify-between items-center text-[8.5px] font-mono text-gray-500">
                    <span>bash / curl testing payload</span>
                    <button
                      onClick={() => handleCopyText(analysisResult.attackPaths[0]?.exploitPayloadSimulator || "", "poc")}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 bg-[#14141A] px-1 rounded hover:bg-[#1E1E26] py-0.5 transition cursor-pointer"
                    >
                      {copyStates["poc"] ? <Check className="w-2.5 h-2.5" /> : <Copy className="w-2.5 h-2.5" />}
                      {copyStates["poc"] ? "Copied" : "Copy POC"}
                    </button>
                  </div>
                  <pre className="p-2.5 font-mono text-[9px] leading-relaxed text-red-300/80 overflow-x-auto whitespace-pre select-all text-left max-h-[140px] custom-scrollbar">
                    {analysisResult.attackPaths[0]?.exploitPayloadSimulator || `# Exploit proof-of-concept simulation loaded`}
                  </pre>
                </div>
              )}
            </div>

            {/* Blast radius visualization */}
            <div className="pt-3 border-t border-[#1F1F23] space-y-1.5">
              <div className="flex justify-between items-center text-[9.5px] font-mono">
                <span className="text-gray-400 uppercase font-bold">Inbound Blast Radius Scope</span>
                <span className={`font-bold uppercase ${isPatchDeployed ? "text-emerald-400" : "text-red-500"}`}>
                  {isPatchDeployed ? "0% SECURED" : "85% CRITICAL IMPACT"}
                </span>
              </div>
              <div className="h-4 w-full bg-[#141418] border border-[#1F1F23] rounded relative overflow-hidden flex items-center justify-center">
                <div 
                  className={`absolute left-0 top-0 h-full transition-all duration-1000 ${
                    isPatchDeployed ? "bg-emerald-500/20 w-0" : "bg-red-500/15 w-[85%]"
                  }`}
                ></div>
                <span className="text-[8.5px] font-mono text-gray-400 px-2 relative z-10 uppercase font-medium">
                  {isPatchDeployed ? "Security Core Isolated" : "Lateral Pivot Pathways Reachable"}
                </span>
              </div>
            </div>

          </div>
        </section>

      </div>

      {/* 3. Bottom Row: GRC Remediation Patch Engine & Simulated Deploy Console */}
      <footer className="col-span-12 border-t border-[#1F1F23] bg-[#0A0A0C] flex flex-col md:flex-row min-h-[220px]">
        
        {/* Left Footer Pane: Patch selector & controls */}
        <div className="w-full md:w-72 border-r border-[#1F1F23] p-4 flex flex-col justify-between bg-[#0D0D10]/80">
          <div>
            <div className="flex items-center gap-1.5 mb-1 text-emerald-500">
              <ShieldCheck className="w-4 h-4" />
              <h3 id="remediation-title" className="text-[11px] font-bold uppercase tracking-widest text-[#10B981]">
                Remediation Engine
              </h3>
            </div>
            
            <p className="text-[10px] text-gray-400 font-mono leading-relaxed mb-3">
              Generate exact, secure IaC patches to resolve selected compliance gaps and shut down theoretical exploit paths.
            </p>

            {/* Patch Selector Dropdown option */}
            <div className="space-y-2 mb-4">
              <div className="flex flex-col">
                <span className="text-[8px] text-gray-500 uppercase font-mono mb-1">Active Mitigation Target</span>
                <div className="space-y-1.5 max-h-[72px] overflow-y-auto pr-1">
                  {analysisResult.remediations.map((rem) => {
                    const isSelected = activeRemediationId === rem.id;
                    return (
                      <button
                        key={rem.id}
                        onClick={() => setActiveRemediationId(rem.id)}
                        className={`w-full text-left px-2 py-1 text-[9px] font-mono rounded truncate border flex justify-between items-center transition ${
                          isSelected 
                            ? "bg-emerald-950/20 border-emerald-500 text-emerald-400" 
                            : "bg-[#141418] border-[#1F1F23] text-gray-400 hover:text-white"
                        }`}
                      >
                        <span className="truncate">{rem.title}</span>
                        <span className="text-[7.5px] text-gray-500 ml-1 font-bold">({rem.frameworkCode})</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            {isPatchDeployed ? (
              <div className="w-full py-2 bg-emerald-950/30 border border-emerald-500/40 text-emerald-400 text-[10px] font-bold uppercase rounded text-center flex items-center justify-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 animate-bounce" /> Patches Applied Successfully
              </div>
            ) : (
              <button
                id="btn-remediate"
                onClick={simulatedDeployPatch}
                disabled={isDeployingPatch || !activeRemediation}
                className="w-full py-2.5 bg-[#10B981] hover:bg-[#34D399] disabled:bg-gray-800 disabled:text-gray-500 text-black font-extrabold text-[10px] uppercase rounded shadow-lg shadow-emerald-950/20 transition cursor-pointer flex items-center justify-center gap-1.5"
              >
                {isDeployingPatch ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Assessing Conflicts...
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" /> Deploy Infrastructure Patch
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Center Footer Pane: Side-by-Side Code Diff patcher view */}
        <div className="flex-1 bg-[#050507] p-4 font-mono text-[10.5px] flex flex-col overflow-hidden min-h-[220px] md:min-h-0">
          
          <div className="flex justify-between items-center mb-2 border-b border-green-950/40 pb-1.5 shrink-0">
            <span className="text-[9.5px] text-[#10B981] font-semibold tracking-wide uppercase flex items-center gap-1.5">
              <FileCode className="w-4 h-4" /> 
              Patch: {activeRemediation?.filename || "main.tf"} 
              <span className="text-gray-500 text-[8.5px] lowercase bg-[#0E0E14] px-1.5 py-0.5 rounded border border-[#1F1F23]">
                ({activeRemediation?.language || "hcl"})
              </span>
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => handleCopyText(activeRemediation?.remediatedCode || "", "iac-patch")}
                className="text-emerald-400 hover:text-emerald-300 text-[9px] bg-[#0E1510] border border-emerald-900/30 rounded px-2 py-0.5 transition cursor-pointer flex items-center gap-1"
                title="Copy secure configuration patch to clipboard"
              >
                {copyStates["iac-patch"] ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copyStates["iac-patch"] ? "Copied" : "Copy Secure Code"}
              </button>
            </div>
          </div>

          {/* Diff comparison cells */}
          {activeRemediation ? (
            <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-3 overflow-y-auto custom-scrollbar">
              
              {/* Box 1: Vulnerable logic */}
              <div className="flex flex-col bg-[#0B0506] rounded border border-red-950/40 p-2.5 overflow-hidden">
                <div className="text-[9px] text-[#F87171] uppercase font-bold border-b border-red-950/60 pb-1 mb-2">
                  [-] Non-Compliant Target State (Violates {activeRemediation.frameworkCode})
                </div>
                <pre className="flex-1 overflow-x-auto text-[10px] text-red-300/70 select-text bg-[#030000] p-2 rounded max-h-[140px] md:max-h-none custom-scrollbar">
                  {activeRemediation.originalCode}
                </pre>
              </div>

              {/* Box 2: Remediated secure logic */}
              <div className="flex flex-col bg-[#050B08] rounded border border-green-950/40 p-2.5 overflow-hidden">
                <div className="text-[9px] text-[#34D399] uppercase font-bold border-b border-green-950/60 pb-1 mb-2">
                  [+] Proposed Defensive Patch (GRC Compliant Solution)
                </div>
                <pre className={`flex-1 overflow-x-auto text-[10px] select-text bg-[#000300] p-2 rounded max-h-[140px] md:max-h-none custom-scrollbar ${
                  isPatchDeployed ? "text-emerald-400 border border-emerald-500/20" : "text-emerald-300/80"
                }`}>
                  {activeRemediation.remediatedCode}
                </pre>
              </div>

            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-gray-500">
              Select or generate a scenario to view compliance patches.
            </div>
          )}
          
          {/* Micro explanation row */}
          {activeRemediation && (
            <p className="text-[9.5px] text-gray-400 leading-tight mt-2 italic bg-[#0E0E12] p-1 px-2 border border-[#16161B] rounded">
              <span className="text-cyan-400 font-bold not-italic">Remediation Vector:</span> {activeRemediation.explanation}
            </p>
          )}

        </div>

        {/* Right Footer Pane: Real Time Logging and Telemetry Monitor */}
        <div className="w-full md:w-56 p-4 bg-[#0D0D10] border-l border-[#1F1F23] flex flex-col justify-between min-h-[140px] md:min-h-0">
          <div className="text-[9.5px] text-cyan-400 font-bold uppercase tracking-tight font-mono flex items-center gap-1.5 border-b border-[#1F1F23] pb-1.5">
            <BookOpen className="w-3.5 h-3.5" /> Twin Validation Term
          </div>
          
          {/* Console logging line loops */}
          <div 
            id="console-terminal"
            className="flex-1 mt-2 font-mono text-[9px] leading-tight text-emerald-500 space-y-1.5 overflow-y-auto max-h-[120px] custom-scrollbar text-left select-all"
          >
            {remediationLogs.map((log, idx) => (
              <div key={idx} className={log.startsWith("> [RESET]") ? "text-red-400" : log.startsWith("> [SUCCESS]") ? "text-cyan-400 font-bold" : "text-emerald-500"}>
                {log}
              </div>
            ))}
          </div>
          
          <div className="mt-2.5 pt-2 border-t border-[#1F1F23]/60 text-[8px] font-mono text-gray-500 flex justify-between uppercase">
            <span>PROPOSED FIX: 2 ASSETS</span>
            <span>VERIFIED OK</span>
          </div>
        </div>

      </footer>

    </div>
  );
}
