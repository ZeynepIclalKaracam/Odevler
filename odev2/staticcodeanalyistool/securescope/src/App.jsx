import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import path from "path-browserify";

// ═══════════════════════════════════════════════════════════════
//  OOP DOMAIN — SEVERITY
// ═══════════════════════════════════════════════════════════════
class Severity {
  static CRITICAL = new Severity("CRITICAL", 4, "#FF5F5F", "#2A0E0E");
  static HIGH     = new Severity("HIGH",     3, "#FFB347", "#2A1A06");
  static MEDIUM   = new Severity("MEDIUM",   2, "#5BB8FF", "#0A1825");
  static LOW      = new Severity("LOW",      1, "#5EE89A", "#0A2017");
  static INFO     = new Severity("INFO",     0, "#8899AA", "#141820");

  constructor(label, weight, color, bg) {
    this.label  = label;
    this.weight = weight;
    this.color  = color;
    this.bg     = bg;
  }

  static fromLabel(label) {
    return { CRITICAL: Severity.CRITICAL, HIGH: Severity.HIGH, MEDIUM: Severity.MEDIUM, LOW: Severity.LOW, INFO: Severity.INFO }
      [label?.toUpperCase()] || Severity.INFO;
  }
}

// ═══════════════════════════════════════════════════════════════
//  OOP DOMAIN — VULNERABILITY
// ═══════════════════════════════════════════════════════════════
class Vulnerability {
  constructor({ id, title, severity, category, description, lineNumber, codeSnippet, recommendation, cwe }) {
    this.id             = id;
    this.title          = title;
    this.severity       = severity instanceof Severity ? severity : Severity.fromLabel(severity);
    this.category       = category;
    this.description    = description;
    this.lineNumber     = lineNumber   || null;
    this.codeSnippet    = codeSnippet  || null;
    this.recommendation = recommendation;
    this.cwe            = cwe          || null;
  }
}

// ═══════════════════════════════════════════════════════════════
//  OOP DOMAIN — SECURITY REPORT
// ═══════════════════════════════════════════════════════════════
class SecurityReport {
  constructor({ language, filePath, analysisTime }) {
    this.id              = `report-${Date.now()}`;
    this.language        = language;
    this.filePath        = filePath;
    this.analysisTime    = analysisTime;
    this.vulnerabilities = [];
    this.summary         = "";
    this.createdAt       = new Date();
  }

  addVulnerabilities(vulns) {
    vulns.forEach(v => this.vulnerabilities.push(v));
  }

  get criticalCount() { return this.#count("CRITICAL"); }
  get highCount()     { return this.#count("HIGH"); }
  get mediumCount()   { return this.#count("MEDIUM"); }
  get lowCount()      { return this.#count("LOW"); }
  get totalCount()    { return this.vulnerabilities.length; }
  #count(label)       { return this.vulnerabilities.filter(v => v.severity.label === label).length; }

  get riskScore() {
    const w = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1, INFO: 0 };
    return Math.min(100, this.vulnerabilities.reduce((a, v) => a + (w[v.severity.label] || 0), 0));
  }

  get riskLabel() {
    const s = this.riskScore;
    if (s >= 70) return { text: "CRITICAL RISK", color: Severity.CRITICAL.color };
    if (s >= 40) return { text: "HIGH RISK",     color: Severity.HIGH.color };
    if (s >= 15) return { text: "MEDIUM RISK",   color: Severity.MEDIUM.color };
    if (s >  0)  return { text: "LOW RISK",      color: Severity.LOW.color };
    return           { text: "CLEAN",            color: Severity.LOW.color };
  }

  getSorted() {
    return [...this.vulnerabilities].sort((a, b) => b.severity.weight - a.severity.weight);
  }
}

// ═══════════════════════════════════════════════════════════════
//  OOP DOMAIN — ANALYSIS SERVICE
// ═══════════════════════════════════════════════════════════════
class AnalysisPromptBuilder {
  constructor(language) { this.language = language; }

  buildSystem() {
    return `You are an expert security code analyst specializing in ${this.language}. Return ONLY valid JSON:
{
  "summary": "2-3 sentence executive summary of security posture",
  "vulnerabilities": [
    {
      "title": "Short name",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "e.g. SQL Injection / XSS / Hardcoded Secret / ...",
      "description": "Detailed explanation of the risk",
      "lineNumber": 42,
      "codeSnippet": "exact vulnerable snippet max 100 chars",
      "recommendation": "Specific actionable fix",
      "cwe": "CWE-XXX"
    }
  ]
}
Check for: SQL/NoSQL/Command injection, XSS, CSRF, hardcoded credentials/secrets/API keys,
weak/broken cryptography, path traversal, SSRF, IDOR, prototype pollution, insecure deserialization,
missing authentication/authorization, race conditions, buffer overflows, eval/exec misuse,
insecure imports, type confusion, open redirect, unvalidated input. Return ONLY JSON, no markdown fences.`;
  }

  buildUser(code) {
    return `Perform a comprehensive security analysis on this ${this.language} code:\n\n${code}`;
  }
}

class APIAnalysisService {
  constructor(apiKey) { this.apiKey = apiKey; }

  async analyze(code, language) {
    const builder = new AnalysisPromptBuilder(language);

    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type":         "application/json",
        "x-api-key":            this.apiKey,
        "anthropic-version":    "2023-06-01",
        "anthropic-dangerous-direct-browser-access": "true",
      },
      body: JSON.stringify({
        model:      "claude-sonnet-4-20250514",
        max_tokens: 4096,
        system:     builder.buildSystem(),
        messages:   [{ role: "user", content: builder.buildUser(code) }],
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error?.message || `API error ${res.status}`);
    }

    const data = await res.json();
    const raw = data.content?.map(c => c.text || "").join("") || "";
    try {
      return JSON.parse(raw.replace(/```json|```/g, "").trim());
    } catch {
      throw new Error("Could not parse analysis response");
    }
  }
}

class StaticCodeAnalyzer {
  constructor(apiKey) { this.service = new APIAnalysisService(apiKey); }

  async run(code, language, filePath) {
    const t0 = Date.now();
    const result = await this.service.analyze(code, language);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(2);

    const report = new SecurityReport({ language, filePath, analysisTime: elapsed });
    report.summary = result.summary || "";
    report.addVulnerabilities(
      (result.vulnerabilities || []).map((v, i) =>
        new Vulnerability({ id: `v${i}`, ...v })
      )
    );
    return report;
  }
}

// ═══════════════════════════════════════════════════════════════
//  OOP DOMAIN — VIRTUAL FILE SYSTEM
// ═══════════════════════════════════════════════════════════════
class FileTab {
  constructor({ id, name, filePath, language, content, isDirty = false }) {
    this.id       = id;
    this.name     = name;
    this.filePath = filePath;  // null = unsaved
    this.language = language;
    this.content  = content;
    this.isDirty  = isDirty;
    this.report   = null;
  }

  get ext() {
    const parts = this.name.split(".");
    return parts.length > 1 ? parts.pop().toLowerCase() : "";
  }
}

class TabManager {
  constructor() {
    this.tabs     = [];
    this.activeId = null;
  }

  get active() { return this.tabs.find(t => t.id === this.activeId) || null; }

  addTab(tab) {
    // Don't duplicate open files
    const existing = this.tabs.find(t => t.filePath && t.filePath === tab.filePath);
    if (existing) { this.activeId = existing.id; return this.clone(); }
    this.tabs.push(tab);
    this.activeId = tab.id;
    return this.clone();
  }

  removeTab(id) {
    this.tabs = this.tabs.filter(t => t.id !== id);
    if (this.activeId === id) this.activeId = this.tabs[this.tabs.length - 1]?.id || null;
    return this.clone();
  }

  setActive(id)              { this.activeId = id; return this.clone(); }
  updateContent(id, content) { const t = this.tabs.find(t => t.id === id); if (t) { t.content = content; t.isDirty = true; } return this.clone(); }
  setReport(id, report)      { const t = this.tabs.find(t => t.id === id); if (t) t.report = report; return this.clone(); }

  clone() {
    const m = new TabManager();
    m.tabs     = this.tabs;
    m.activeId = this.activeId;
    return m;
  }
}

class ConsoleLogger {
  constructor(msgs = []) { this.msgs = msgs; }

  log(type, text) {
    return new ConsoleLogger([
      ...this.msgs,
      { id: `${Date.now()}${Math.random()}`, type, text, time: new Date().toLocaleTimeString("en", { hour12: false }) },
    ]);
  }

  clear() { return new ConsoleLogger([]); }
}

// ═══════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════
const EXT_LANG = {
  js:"JavaScript", jsx:"JavaScript", ts:"TypeScript", tsx:"TypeScript",
  py:"Python", go:"Go", java:"Java", php:"PHP", rb:"Ruby",
  cs:"C#", rs:"Rust", sql:"SQL", sh:"Bash", bash:"Bash",
  kt:"Kotlin", swift:"Swift", c:"C", cpp:"C++", cc:"C++",
  h:"C", hpp:"C++", vue:"JavaScript", svelte:"JavaScript",
  html:"HTML", css:"CSS", scss:"CSS", yaml:"YAML", yml:"YAML",
  json:"JSON", toml:"TOML",
};

const LANG_COLOR = {
  JavaScript:"#FFB347", TypeScript:"#5BB8FF", Python:"#5EE89A",
  Java:"#FF5F5F", Go:"#00ADD8", PHP:"#9B8FDB", Ruby:"#FF5F5F",
  "C#":"#9B8FDB", Rust:"#FFB347", SQL:"#5EE89A", Bash:"#5EE89A",
  Kotlin:"#9B8FDB", Swift:"#FF5F5F", C:"#4FC3F7", "C++":"#4FC3F7",
};

const FILE_ICON = {
  js:"ti-brand-javascript", jsx:"ti-brand-react", ts:"ti-brand-typescript",
  tsx:"ti-brand-react", py:"ti-brand-python", go:"ti-brand-golang",
  java:"ti-coffee", php:"ti-brand-php", rb:"ti-diamond",
  cs:"ti-brand-c-sharp", rs:"ti-brand-rust", sql:"ti-database",
  sh:"ti-terminal", bash:"ti-terminal", kt:"ti-brand-kotlin",
  swift:"ti-brand-swift", c:"ti-file-code", cpp:"ti-file-code",
  h:"ti-file-code", json:"ti-braces", yaml:"ti-file-text",
  yml:"ti-file-text", html:"ti-brand-html5", css:"ti-brand-css3",
  vue:"ti-brand-vue", svelte:"ti-bolt",
};

function detectLang(filename) {
  const ext = filename.split(".").pop()?.toLowerCase();
  return EXT_LANG[ext] || "Text";
}

function fileIcon(ext) { return FILE_ICON[ext] || "ti-file"; }

// ═══════════════════════════════════════════════════════════════
//  COLORS (dark theme)
// ═══════════════════════════════════════════════════════════════
const C = {
  bg0: "#0B0D12", bg1: "#0E1117", bg2: "#141820", bg3: "#1A2030", bg4: "#202840",
  border: "#1E2A3A", borderHi: "#2A3A50",
  text: "#CDD6F4", textMuted: "#6C7A9C", textDim: "#3D4F65",
  green: "#5EE89A", red: "#FF5F5F", amber: "#FFB347", blue: "#5BB8FF",
  accent: "#4FC3F7", accentDim: "#1A3A50",
};

const LOG_COLOR = { info: C.textMuted, success: C.green, error: C.red, warn: C.amber, system: C.textDim };

// ═══════════════════════════════════════════════════════════════
//  REUSABLE UI COMPONENTS
// ═══════════════════════════════════════════════════════════════

function Btn({ icon, label, onClick, primary, danger, disabled, small, title }) {
  const [h, setH] = useState(false);
  return (
    <button
      title={title}
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setH(true)}
      onMouseLeave={() => setH(false)}
      style={{
        display: "flex", alignItems: "center", gap: 5,
        padding: small ? "3px 8px" : "5px 12px",
        background: primary ? (h ? "#1A6B4A" : "#0F3D2A") : danger ? (h ? "#3A1515" : "transparent") : (h ? C.bg3 : "transparent"),
        border: `1px solid ${primary ? (h ? C.green : "#2A6A45") : danger ? (h ? C.red : "#3A1515") : (h ? C.borderHi : C.border)}`,
        borderRadius: 4, color: primary ? C.green : danger ? C.red : (h ? C.text : C.textMuted),
        fontSize: small ? 11 : 12, cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.4 : 1, transition: "all 0.1s", fontFamily: "inherit",
        whiteSpace: "nowrap", flexShrink: 0,
      }}
    >
      {icon && <i className={`ti ${icon}`} style={{ fontSize: small ? 12 : 13 }} aria-hidden="true" />}
      {label}
    </button>
  );
}

function LineEditor({ content, onChange }) {
  const textareaRef = useRef(null);
  const lineNumRef  = useRef(null);
  const lineCount   = useMemo(() => Math.max(1, content.split("\n").length), [content]);

  const syncScroll = useCallback(() => {
    if (lineNumRef.current && textareaRef.current)
      lineNumRef.current.scrollTop = textareaRef.current.scrollTop;
  }, []);

  const handleKeyDown = useCallback((e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const s = e.target.selectionStart, end = e.target.selectionEnd;
      const v = e.target.value;
      const nv = v.substring(0, s) + "  " + v.substring(end);
      onChange(nv);
      requestAnimationFrame(() => {
        if (textareaRef.current) {
          textareaRef.current.selectionStart = textareaRef.current.selectionEnd = s + 2;
        }
      });
    }
  }, [onChange]);

  return (
    <div style={{ display: "flex", flex: 1, overflow: "hidden", background: C.bg1 }}>
      {/* Line numbers */}
      <div ref={lineNumRef} style={{ width: 48, flexShrink: 0, overflow: "hidden", padding: "14px 0", background: C.bg2, borderRight: `1px solid ${C.border}`, userSelect: "none" }}>
        {Array.from({ length: lineCount }, (_, i) => (
          <div key={i} style={{ height: 21, lineHeight: "21px", textAlign: "right", paddingRight: 10, fontSize: 12, fontFamily: "'JetBrains Mono','Fira Code','Cascadia Code',monospace", color: C.textDim }}>
            {i + 1}
          </div>
        ))}
      </div>
      {/* Editor */}
      <textarea
        ref={textareaRef}
        value={content}
        onChange={e => onChange(e.target.value)}
        onScroll={syncScroll}
        onKeyDown={handleKeyDown}
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="off"
        style={{
          flex: 1, border: "none", outline: "none", resize: "none",
          background: "transparent", color: C.text,
          fontFamily: "'JetBrains Mono','Fira Code','Cascadia Code','Consolas',monospace",
          fontSize: 13.5, lineHeight: "21px", padding: "14px 16px 14px 12px",
          caretColor: C.accent, overflowY: "auto", whiteSpace: "pre", overflowX: "auto",
          tabSize: 2,
        }}
      />
    </div>
  );
}

function VulnCard({ vuln }) {
  const [open, setOpen] = useState(false);
  const s = vuln.severity;
  return (
    <div style={{ borderLeft: `2px solid ${s.color}`, background: open ? C.bg4 : C.bg3, marginBottom: 3, borderRadius: "0 4px 4px 0", transition: "background 0.1s" }}>
      <div onClick={() => setOpen(o => !o)} style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 10px", cursor: "pointer" }}>
        <span style={{ fontSize: 9, fontWeight: 700, padding: "2px 5px", borderRadius: 2, background: s.bg, color: s.color, letterSpacing: "0.06em", fontFamily: "monospace", flexShrink: 0 }}>{s.label}</span>
        <span style={{ fontSize: 11.5, color: C.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{vuln.title}</span>
        {vuln.lineNumber && <span style={{ fontSize: 10, color: C.textDim, fontFamily: "monospace", flexShrink: 0 }}>:{vuln.lineNumber}</span>}
        <i className={`ti ti-chevron-${open ? "up" : "down"}`} style={{ fontSize: 11, color: C.textDim, flexShrink: 0 }} aria-hidden="true" />
      </div>
      {open && (
        <div style={{ padding: "0 10px 10px", display: "flex", flexDirection: "column", gap: 8 }}>
          <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
            <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.bg2, color: C.textMuted, border: `1px solid ${C.border}` }}>{vuln.category}</span>
            {vuln.cwe && <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 3, background: C.bg2, color: C.textDim, fontFamily: "monospace" }}>{vuln.cwe}</span>}
          </div>
          <p style={{ margin: 0, fontSize: 11.5, color: C.textMuted, lineHeight: 1.6 }}>{vuln.description}</p>
          {vuln.codeSnippet && (
            <pre style={{ margin: 0, padding: "8px 10px", borderRadius: 4, background: C.bg0, border: `1px solid ${s.color}30`, fontSize: 11, fontFamily: "monospace", color: s.color, overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {vuln.codeSnippet}
            </pre>
          )}
          <div>
            <div style={{ fontSize: 10, color: C.green, marginBottom: 3, letterSpacing: "0.04em" }}>▸ FIX</div>
            <p style={{ margin: 0, fontSize: 11.5, color: C.textMuted, lineHeight: 1.6 }}>{vuln.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

function RiskBar({ score, label }) {
  const color = score >= 70 ? C.red : score >= 40 ? C.amber : score >= 15 ? C.blue : C.green;
  return (
    <div style={{ padding: "10px 12px", borderBottom: `1px solid ${C.border}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 5 }}>
        <span style={{ fontSize: 9, color: C.textMuted, letterSpacing: "0.08em" }}>RISK SCORE</span>
        <span style={{ fontSize: 14, fontWeight: 700, color, fontFamily: "monospace" }}>{score}/100</span>
      </div>
      <div style={{ height: 4, background: C.bg0, borderRadius: 2, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${score}%`, background: color, borderRadius: 2, transition: "width 0.6s ease" }} />
      </div>
      <div style={{ marginTop: 4, fontSize: 10, color, letterSpacing: "0.08em", fontWeight: 700 }}>{label.text}</div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  API KEY MODAL
// ═══════════════════════════════════════════════════════════════
function ApiKeyModal({ onSave, existing }) {
  const [key, setKey] = useState(existing || "");
  const [show, setShow] = useState(false);

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 999 }}>
      <div style={{ background: C.bg2, border: `1px solid ${C.border}`, borderRadius: 8, padding: 28, width: 420 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
          <i className="ti ti-key" style={{ fontSize: 20, color: C.amber }} aria-hidden="true" />
          <div>
            <div style={{ fontSize: 14, fontWeight: 600, color: C.text }}>Anthropic API Key</div>
            <div style={{ fontSize: 11, color: C.textMuted, marginTop: 2 }}>Required for AI-powered security analysis</div>
          </div>
        </div>

        <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 10, lineHeight: 1.6 }}>
          Get your API key from{" "}
          <span
            onClick={() => window.open?.("https://console.anthropic.com/api-keys")}
            style={{ color: C.accent, cursor: "pointer", textDecoration: "underline" }}
          >console.anthropic.com/api-keys</span>
        </div>

        <div style={{ position: "relative", marginBottom: 16 }}>
          <input
            type={show ? "text" : "password"}
            value={key}
            onChange={e => setKey(e.target.value)}
            onKeyDown={e => e.key === "Enter" && key.trim() && onSave(key.trim())}
            placeholder="sk-ant-api03-..."
            style={{
              width: "100%", padding: "9px 36px 9px 10px",
              background: C.bg0, border: `1px solid ${C.borderHi}`,
              borderRadius: 4, color: C.text, fontSize: 12,
              fontFamily: "monospace", outline: "none",
            }}
          />
          <button
            onClick={() => setShow(v => !v)}
            style={{ position: "absolute", right: 8, top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: C.textMuted, cursor: "pointer", fontSize: 14 }}
          >
            <i className={`ti ${show ? "ti-eye-off" : "ti-eye"}`} aria-hidden="true" />
          </button>
        </div>

        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          {existing && <Btn label="Cancel" onClick={() => onSave(existing)} />}
          <Btn label="Save & Continue" primary onClick={() => key.trim() && onSave(key.trim())} disabled={!key.trim()} />
        </div>

        <div style={{ marginTop: 14, fontSize: 10, color: C.textDim, lineHeight: 1.5 }}>
          🔒 Your API key is stored locally in the app config — never sent to any server other than Anthropic.
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  FOLDER TREE COMPONENT
// ═══════════════════════════════════════════════════════════════
function FolderTree({ node, onFileClick, depth = 0 }) {
  const [open, setOpen] = useState(depth < 1);

  if (node.type === "file") {
    const ext = node.name.split(".").pop()?.toLowerCase();
    return (
      <div
        onClick={() => onFileClick(node)}
        style={{
          display: "flex", alignItems: "center", gap: 5,
          padding: `4px 8px 4px ${12 + depth * 14}px`,
          cursor: "pointer", color: C.textMuted, fontSize: 12,
        }}
        onMouseEnter={e => e.currentTarget.style.background = C.bg3}
        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
      >
        <i className={`ti ${fileIcon(ext)}`} style={{ fontSize: 12, color: LANG_COLOR[detectLang(node.name)] || C.textDim, flexShrink: 0 }} aria-hidden="true" />
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{node.name}</span>
      </div>
    );
  }

  return (
    <div>
      <div
        onClick={() => setOpen(v => !v)}
        style={{ display: "flex", alignItems: "center", gap: 5, padding: `4px 8px 4px ${8 + depth * 14}px`, cursor: "pointer", color: C.textMuted, fontSize: 12 }}
        onMouseEnter={e => e.currentTarget.style.background = C.bg3}
        onMouseLeave={e => e.currentTarget.style.background = "transparent"}
      >
        <i className={`ti ti-chevron-${open ? "down" : "right"}`} style={{ fontSize: 11, color: C.textDim }} aria-hidden="true" />
        <i className={`ti ti-folder${open ? "-open" : ""}`} style={{ fontSize: 13, color: C.amber }} aria-hidden="true" />
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{node.name}</span>
      </div>
      {open && node.children?.map((child, i) => (
        <FolderTree key={i} node={child} onFileClick={onFileClick} depth={depth + 1} />
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  MAIN APP
// ═══════════════════════════════════════════════════════════════
export default function App() {
  const [apiKey,       setApiKey]       = useState("");
  const [showKeyModal, setShowKeyModal] = useState(false);
  const [tabs,         setTabs]         = useState(() => new TabManager());
  const [console_,     setConsole_]     = useState(() => new ConsoleLogger());
  const [loading,      setLoading]      = useState(false);
  const [bottomPanel,  setBottomPanel]  = useState("console");
  const [filterSev,    setFilterSev]    = useState("ALL");
  const [folderTree,   setFolderTree]   = useState(null);
  const [showNewFile,  setShowNewFile]  = useState(false);
  const [newFileName,  setNewFileName]  = useState("");
  const consoleEndRef = useRef(null);

  // Load saved API key on startup
  useEffect(() => {
    const api = window.electronAPI;
    if (!api) return;
    api.getApiKey().then(k => {
      if (k) setApiKey(k);
      else   setShowKeyModal(true);
    });
  }, []);

  // Menu shortcuts
  useEffect(() => {
    const api = window.electronAPI;
    if (!api) return;
    api.onMenuOpenFile(handleOpenFiles);
    api.onMenuOpenFolder(handleOpenFolder);
    api.onMenuNewFile(() => setShowNewFile(true));
    api.onMenuRunAnalysis(handleAnalyze);
    api.onMenuClear(handleClear);
    return () => {
      ["menu-open-file","menu-open-folder","menu-new-file","menu-run-analysis","menu-clear"]
        .forEach(ch => api.removeAllListeners(ch));
    };
  }, []);

  useEffect(() => {
    if (consoleEndRef.current) consoleEndRef.current.scrollIntoView({ behavior: "smooth" });
  }, [console_.msgs]);

  const addLog = useCallback((type, text) => setConsole_(c => c.log(type, text)), []);

  // ── File open from disk ──
  const handleOpenFiles = useCallback(async () => {
    const api = window.electronAPI;
    if (!api) return;
    const paths = await api.openFileDialog();
    if (!paths) return;
    for (const fp of paths) {
      const res = await api.readFile(fp);
      if (!res.ok) { addLog("error", `Cannot read: ${fp}`); continue; }
      const name = fp.split(/[\\/]/).pop();
      const lang = detectLang(name);
      setTabs(t => t.addTab(new FileTab({ id: `tab-${Date.now()}-${Math.random()}`, name, filePath: fp, language: lang, content: res.content })));
      addLog("info", `Opened: ${name} (${lang})`);
    }
  }, [addLog]);

  const handleOpenFolder = useCallback(async () => {
    const api = window.electronAPI;
    if (!api) return;
    const fp = await api.openFolderDialog();
    if (!fp) return;
    const res = await api.readFolder(fp);
    if (!res.ok) { addLog("error", `Cannot read folder: ${fp}`); return; }
    setFolderTree({ root: res.root, children: res.tree, type: "dir", name: fp.split(/[\\/]/).pop() });
    addLog("info", `Opened folder: ${res.root}`);
  }, [addLog]);

  const handleFolderFileClick = useCallback(async (node) => {
    const api = window.electronAPI;
    if (!api) return;
    const res = await api.readFile(node.path);
    if (!res.ok) { addLog("error", `Cannot read: ${node.path}`); return; }
    const lang = detectLang(node.name);
    setTabs(t => t.addTab(new FileTab({ id: `tab-${Date.now()}`, name: node.name, filePath: node.path, language: lang, content: res.content })));
  }, [addLog]);

  // ── New blank file ──
  const handleNewFile = useCallback(() => {
    if (!newFileName.trim()) return;
    const lang = detectLang(newFileName);
    setTabs(t => t.addTab(new FileTab({ id: `tab-${Date.now()}`, name: newFileName.trim(), filePath: null, language: lang, content: "" })));
    setNewFileName("");
    setShowNewFile(false);
  }, [newFileName]);

  // ── Run Analysis ──
  const handleAnalyze = useCallback(async () => {
    const activeTab = tabs.active;
    if (!activeTab || loading) return;
    if (!apiKey) { setShowKeyModal(true); return; }

    setLoading(true);
    setFilterSev("ALL");
    setBottomPanel("console");

    const analyzer = new StaticCodeAnalyzer(apiKey);
    addLog("system", `─── Analyzing: ${activeTab.name} ───`);
    addLog("info",   `Language: ${activeTab.language}`);
    addLog("info",   `Lines: ${activeTab.content.split("\n").length} · Chars: ${activeTab.content.length}`);
    addLog("info",   `Sending to SecureScope AI engine…`);

    try {
      const report = await analyzer.run(activeTab.content, activeTab.language, activeTab.filePath);
      setTabs(t => t.setReport(activeTab.id, report));
      addLog("success", `Done in ${report.analysisTime}s`);
      addLog(report.criticalCount > 0 ? "error" : "info", `${report.totalCount} issue(s) — Risk: ${report.riskScore}/100`);
      if (report.criticalCount > 0) addLog("error", `⚠ ${report.criticalCount} CRITICAL vulnerability/ies!`);
      if (report.highCount     > 0) addLog("warn",  `${report.highCount} HIGH severity finding(s)`);
      addLog("system", `─── Finished ───`);
      setBottomPanel("findings");
    } catch (e) {
      addLog("error", `Analysis failed: ${e.message}`);
    } finally {
      setLoading(false);
    }
  }, [tabs, loading, apiKey, addLog]);

  const handleClear = useCallback(() => {
    setConsole_(c => c.clear());
    if (tabs.active) setTabs(t => t.setReport(t.activeId, null));
  }, [tabs]);

  const handleSaveKey = useCallback(async (k) => {
    setApiKey(k);
    setShowKeyModal(false);
    await window.electronAPI?.setApiKey(k);
  }, []);

  const activeTab = tabs.active;
  const report    = activeTab?.report || null;
  const vulns     = useMemo(() => {
    if (!report) return [];
    const all = report.getSorted();
    return filterSev === "ALL" ? all : all.filter(v => v.severity.label === filterSev);
  }, [report, filterSev]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: C.bg0, overflow: "hidden" }}>
      <style>{`
        * { box-sizing: border-box; }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
        textarea { scrollbar-width: thin; scrollbar-color: ${C.border} transparent; }
        button:focus-visible { outline: 1px solid ${C.accent}; }
      `}</style>

      {showKeyModal && <ApiKeyModal onSave={handleSaveKey} existing={apiKey} />}

      {/* ── TITLEBAR ─────────────────────────────── */}
      <div style={{ height: 38, background: C.bg0, borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8, padding: "0 12px", flexShrink: 0, WebkitAppRegion: "drag" }}>
        <i className="ti ti-shield-lock" style={{ fontSize: 16, color: C.red }} aria-hidden="true" />
        <span style={{ fontSize: 12, fontWeight: 700, color: C.text, letterSpacing: "0.05em" }}>SecureScope</span>
        <span style={{ fontSize: 10, color: C.textDim, padding: "1px 6px", border: `1px solid ${C.border}`, borderRadius: 3 }}>IDE v2.0</span>
        <div style={{ flex: 1, WebkitAppRegion: "drag" }} />
        <div style={{ WebkitAppRegion: "no-drag", display: "flex", gap: 6 }}>
          <Btn icon="ti-folder-open" label="Open File" onClick={handleOpenFiles} />
          <Btn icon="ti-folder" label="Open Folder" onClick={handleOpenFolder} />
          <Btn icon="ti-player-play" label={loading ? "Analyzing…" : "Run Analysis (F5)"} onClick={handleAnalyze} primary disabled={loading || !activeTab} />
          <Btn icon="ti-key" onClick={() => setShowKeyModal(true)} small title="API Key Settings" />
        </div>
      </div>

      {/* ── BODY ─────────────────────────────────── */}
      <div style={{ display: "flex", flex: 1, overflow: "hidden" }}>

        {/* ── SIDEBAR ────────────────────────── */}
        <div style={{ width: 200, flexShrink: 0, background: C.bg2, borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          {/* Sidebar header */}
          <div style={{ padding: "7px 10px 5px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <span style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.1em", fontWeight: 700 }}>EXPLORER</span>
            <div style={{ display: "flex", gap: 4 }}>
              <button onClick={() => setShowNewFile(v => !v)} title="New file" style={{ background: "none", border: "none", color: C.textMuted, cursor: "pointer", fontSize: 14, padding: "0 2px", lineHeight: 1 }}>
                <i className="ti ti-file-plus" aria-hidden="true" />
              </button>
              <button onClick={handleOpenFolder} title="Open folder" style={{ background: "none", border: "none", color: C.textMuted, cursor: "pointer", fontSize: 14, padding: "0 2px", lineHeight: 1 }}>
                <i className="ti ti-folder-plus" aria-hidden="true" />
              </button>
            </div>
          </div>

          {showNewFile && (
            <div style={{ padding: "5px 8px", borderBottom: `1px solid ${C.border}` }}>
              <input
                autoFocus
                value={newFileName}
                onChange={e => setNewFileName(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") handleNewFile(); if (e.key === "Escape") setShowNewFile(false); }}
                placeholder="filename.js"
                style={{ width: "100%", padding: "4px 7px", fontSize: 11, background: C.bg0, border: `1px solid ${C.accent}`, borderRadius: 3, color: C.text, outline: "none", fontFamily: "monospace" }}
              />
            </div>
          )}

          <div style={{ flex: 1, overflowY: "auto" }}>
            {/* Open tabs */}
            {tabs.tabs.length > 0 && (
              <div style={{ padding: "5px 0" }}>
                <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.08em", padding: "2px 10px 4px", fontWeight: 700 }}>OPEN TABS</div>
                {tabs.tabs.map(tab => {
                  const active = tab.id === tabs.activeId;
                  return (
                    <div
                      key={tab.id}
                      onClick={() => setTabs(t => t.setActive(tab.id))}
                      style={{ display: "flex", alignItems: "center", gap: 5, padding: "4px 10px", cursor: "pointer", background: active ? C.bg3 : "transparent", borderLeft: active ? `2px solid ${C.accent}` : "2px solid transparent" }}
                    >
                      <i className={`ti ${fileIcon(tab.ext)}`} style={{ fontSize: 12, color: LANG_COLOR[tab.language] || C.textDim, flexShrink: 0 }} aria-hidden="true" />
                      <span style={{ fontSize: 11.5, color: active ? C.text : C.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1, fontFamily: "sans-serif" }}>
                        {tab.isDirty ? "● " : ""}{tab.name}
                      </span>
                      <button
                        onClick={e => { e.stopPropagation(); setTabs(t => t.removeTab(tab.id)); }}
                        style={{ background: "none", border: "none", color: C.textDim, cursor: "pointer", fontSize: 12, padding: 1, lineHeight: 1 }}
                      >
                        <i className="ti ti-x" aria-hidden="true" />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Folder tree */}
            {folderTree && (
              <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 5 }}>
                <div style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.08em", padding: "2px 10px 4px", fontWeight: 700 }}>
                  {folderTree.name.toUpperCase()}
                </div>
                {folderTree.children?.map((node, i) => (
                  <FolderTree key={i} node={node} onFileClick={handleFolderFileClick} depth={0} />
                ))}
              </div>
            )}

            {tabs.tabs.length === 0 && !folderTree && (
              <div style={{ padding: "20px 12px", textAlign: "center", color: C.textDim, fontSize: 11, lineHeight: 1.7 }}>
                <i className="ti ti-folder-open" style={{ fontSize: 24, display: "block", marginBottom: 8, opacity: 0.5 }} aria-hidden="true" />
                Open files or a folder to get started
              </div>
            )}
          </div>
        </div>

        {/* ── EDITOR + BOTTOM PANEL ──────────── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", minWidth: 0 }}>

          {/* Tab bar */}
          <div style={{ height: 34, display: "flex", alignItems: "stretch", background: C.bg0, borderBottom: `1px solid ${C.border}`, overflowX: "auto", flexShrink: 0 }}>
            {tabs.tabs.map(tab => {
              const active = tab.id === tabs.activeId;
              return (
                <div
                  key={tab.id}
                  onClick={() => setTabs(t => t.setActive(tab.id))}
                  style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 14px", cursor: "pointer", background: active ? C.bg1 : "transparent", borderRight: `1px solid ${C.border}`, borderBottom: active ? `2px solid ${C.accent}` : "2px solid transparent", flexShrink: 0 }}
                >
                  <i className={`ti ${fileIcon(tab.ext)}`} style={{ fontSize: 12, color: active ? LANG_COLOR[tab.language] || C.text : C.textDim }} aria-hidden="true" />
                  <span style={{ fontSize: 12, color: active ? C.text : C.textDim, fontFamily: "sans-serif" }}>
                    {tab.isDirty && <span style={{ color: C.amber, marginRight: 3 }}>●</span>}{tab.name}
                  </span>
                  {tab.report && (
                    <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 2, background: tab.report.criticalCount > 0 ? "#2A0E0E" : "#2A1A06", color: tab.report.criticalCount > 0 ? C.red : C.amber }}>{tab.report.totalCount}</span>
                  )}
                </div>
              );
            })}
            {tabs.tabs.length === 0 && (
              <div style={{ display: "flex", alignItems: "center", padding: "0 16px", color: C.textDim, fontSize: 12 }}>
                No files open — use File menu or toolbar to open
              </div>
            )}
          </div>

          {/* Code editor */}
          {activeTab ? (
            <LineEditor content={activeTab.content} onChange={c => setTabs(t => t.updateContent(activeTab.id, c))} />
          ) : (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 16, color: C.textDim }}>
              <i className="ti ti-shield-lock" style={{ fontSize: 48, color: C.border }} aria-hidden="true" />
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 14, color: C.textMuted, marginBottom: 6 }}>SecureScope IDE</div>
                <div style={{ fontSize: 12, lineHeight: 1.8 }}>
                  Open a file to start analyzing<br />
                  <span style={{ color: C.textDim }}>File → Open File(s)  or  Ctrl+O</span>
                </div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <Btn icon="ti-folder-open" label="Open File" onClick={handleOpenFiles} />
                <Btn icon="ti-folder" label="Open Folder" onClick={handleOpenFolder} />
              </div>
            </div>
          )}

          {/* Bottom panel tabs */}
          <div style={{ height: 28, display: "flex", alignItems: "stretch", background: C.bg0, borderTop: `1px solid ${C.border}`, flexShrink: 0 }}>
            {["console", "findings"].map(p => (
              <button
                key={p}
                onClick={() => setBottomPanel(p)}
                style={{ display: "flex", alignItems: "center", gap: 5, height: "100%", padding: "0 14px", background: bottomPanel === p ? C.bg2 : "transparent", border: "none", borderRight: `1px solid ${C.border}`, borderBottom: bottomPanel === p ? `2px solid ${C.accent}` : "2px solid transparent", color: bottomPanel === p ? C.text : C.textDim, fontSize: 11, cursor: "pointer", fontFamily: "inherit" }}
              >
                <i className={`ti ${p === "console" ? "ti-terminal" : "ti-shield-bolt"}`} style={{ fontSize: 12 }} aria-hidden="true" />
                {p.charAt(0).toUpperCase() + p.slice(1)}
                {p === "findings" && report?.totalCount > 0 && (
                  <span style={{ fontSize: 9, padding: "1px 4px", borderRadius: 2, background: report.criticalCount > 0 ? "#2A0E0E" : "#2A1A06", color: report.criticalCount > 0 ? C.red : C.amber }}>{report.totalCount}</span>
                )}
              </button>
            ))}
            <div style={{ flex: 1 }} />
            {loading && (
              <div style={{ display: "flex", alignItems: "center", gap: 5, paddingRight: 12, color: C.accent, fontSize: 11 }}>
                <i className="ti ti-loader-2" style={{ fontSize: 12, animation: "spin 1s linear infinite" }} aria-hidden="true" />
                Scanning…
              </div>
            )}
            {activeTab && !loading && (
              <div style={{ display: "flex", alignItems: "center", paddingRight: 12, fontSize: 10, color: C.textDim, gap: 8 }}>
                <span style={{ color: LANG_COLOR[activeTab.language] || C.textDim }}>{activeTab.language}</span>
                <span>{activeTab.content.split("\n").length} lines</span>
              </div>
            )}
          </div>

          {/* Bottom panel content */}
          <div style={{ height: 160, background: C.bg0, borderTop: `1px solid ${C.border}`, overflow: "hidden", flexShrink: 0 }}>
            {bottomPanel === "console" && (
              <div style={{ height: "100%", overflowY: "auto", padding: "8px 14px" }}>
                {console_.msgs.length === 0 && (
                  <div style={{ color: C.textDim, fontSize: 11, paddingTop: 4 }}>Run analysis to see output…</div>
                )}
                {console_.msgs.map(m => (
                  <div key={m.id} style={{ display: "flex", gap: 12, marginBottom: 2, fontFamily: "monospace", fontSize: 11.5 }}>
                    <span style={{ color: C.textDim, flexShrink: 0 }}>{m.time}</span>
                    <span style={{ color: LOG_COLOR[m.type] || C.textMuted }}>{m.text}</span>
                  </div>
                ))}
                <div ref={consoleEndRef} />
              </div>
            )}

            {bottomPanel === "findings" && (
              <div style={{ height: "100%", overflowY: "auto", padding: "8px 12px" }}>
                {!report ? (
                  <div style={{ color: C.textDim, fontSize: 11, paddingTop: 4, display: "flex", alignItems: "center", gap: 6 }}>
                    <i className="ti ti-scan" style={{ fontSize: 14 }} aria-hidden="true" />
                    Run analysis to see security findings
                  </div>
                ) : (
                  <div>
                    <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap", alignItems: "center" }}>
                      {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(f => {
                        const counts = { ALL: report.totalCount, CRITICAL: report.criticalCount, HIGH: report.highCount, MEDIUM: report.mediumCount, LOW: report.lowCount };
                        const sev = Severity.fromLabel(f);
                        return (
                          <button
                            key={f}
                            onClick={() => setFilterSev(f)}
                            style={{ fontSize: 10, padding: "3px 9px", borderRadius: 3, background: filterSev === f ? (sev.bg || C.bg3) : "transparent", border: `1px solid ${filterSev === f ? (sev.color || C.borderHi) : C.border}`, color: filterSev === f ? (sev.color || C.text) : C.textDim, cursor: "pointer", fontFamily: "monospace", fontWeight: 600 }}
                          >
                            {f} <span style={{ opacity: 0.7 }}>{counts[f]}</span>
                          </button>
                        );
                      })}
                      <span style={{ fontSize: 10, color: C.textDim, marginLeft: "auto" }}>Risk: {report.riskScore}/100 · {report.analysisTime}s</span>
                    </div>
                    {vulns.length === 0 && report.totalCount === 0 ? (
                      <div style={{ color: C.green, fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}>
                        <i className="ti ti-shield-check" style={{ fontSize: 14 }} aria-hidden="true" />
                        No security vulnerabilities detected
                      </div>
                    ) : (
                      vulns.map(v => <VulnCard key={v.id} vuln={v} />)
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* ── RIGHT FINDINGS PANEL ───────────── */}
        <div style={{ width: 240, flexShrink: 0, background: C.bg2, borderLeft: `1px solid ${C.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "7px 12px", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 6 }}>
            <i className="ti ti-shield-bolt" style={{ fontSize: 13, color: C.red }} aria-hidden="true" />
            <span style={{ fontSize: 9, color: C.textMuted, letterSpacing: "0.1em", fontWeight: 700 }}>SECURITY FINDINGS</span>
          </div>

          {loading ? (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 10 }}>
              <i className="ti ti-loader-2" style={{ fontSize: 28, color: C.accent, animation: "spin 1s linear infinite" }} aria-hidden="true" />
              <span style={{ fontSize: 11, color: C.textMuted }}>Scanning…</span>
              <div style={{ display: "flex", gap: 4 }}>
                {[0, 1, 2].map(i => (
                  <div key={i} style={{ width: 5, height: 5, borderRadius: "50%", background: C.accent, animation: `blink 1.2s ${i * 0.4}s infinite` }} />
                ))}
              </div>
            </div>
          ) : !report ? (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8, padding: 16, textAlign: "center" }}>
              <i className="ti ti-scan" style={{ fontSize: 32, color: C.border }} aria-hidden="true" />
              <span style={{ fontSize: 11, color: C.textDim, lineHeight: 1.6 }}>Open a file and run analysis to see vulnerabilities here</span>
            </div>
          ) : (
            <div style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column" }}>
              <RiskBar score={report.riskScore} label={report.riskLabel} />

              {/* Stats grid */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 1, borderBottom: `1px solid ${C.border}`, background: C.border }}>
                {[
                  { label: "CRITICAL", val: report.criticalCount, color: Severity.CRITICAL.color, bg: Severity.CRITICAL.bg },
                  { label: "HIGH",     val: report.highCount,     color: Severity.HIGH.color,     bg: Severity.HIGH.bg },
                  { label: "MEDIUM",   val: report.mediumCount,   color: Severity.MEDIUM.color,   bg: Severity.MEDIUM.bg },
                  { label: "LOW",      val: report.lowCount,      color: Severity.LOW.color,      bg: Severity.LOW.bg },
                ].map(s => (
                  <div key={s.label} style={{ padding: "8px 10px", background: C.bg2, textAlign: "center" }}>
                    <div style={{ fontSize: 18, fontWeight: 700, color: s.color, fontFamily: "monospace" }}>{s.val}</div>
                    <div style={{ fontSize: 9, color: s.color, opacity: 0.7, letterSpacing: "0.06em" }}>{s.label}</div>
                  </div>
                ))}
              </div>

              {/* Summary */}
              {report.summary && (
                <div style={{ padding: "8px 10px", borderBottom: `1px solid ${C.border}` }}>
                  <p style={{ margin: 0, fontSize: 11, color: C.textMuted, lineHeight: 1.6 }}>{report.summary}</p>
                </div>
              )}

              {/* Vulnerability list */}
              <div style={{ flex: 1, overflowY: "auto", padding: "6px 8px" }}>
                {report.totalCount === 0 ? (
                  <div style={{ textAlign: "center", padding: "20px 0", color: C.green, fontSize: 11 }}>
                    <i className="ti ti-shield-check" style={{ fontSize: 24, display: "block", marginBottom: 6 }} aria-hidden="true" />
                    No vulnerabilities found
                  </div>
                ) : (
                  vulns.map(v => <VulnCard key={v.id} vuln={v} />)
                )}
              </div>
            </div>
          )}

          {/* Status indicator */}
          <div style={{ padding: "6px 10px", borderTop: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: loading ? C.amber : report ? C.green : C.textDim, animation: loading ? "blink 1s infinite" : "none" }} />
            <span style={{ fontSize: 9, color: C.textDim, letterSpacing: "0.05em" }}>
              {loading ? "SCANNING" : report ? `${report.totalCount} ISSUES FOUND` : "READY"}
            </span>
            {apiKey && <span style={{ marginLeft: "auto", fontSize: 9, color: C.textDim }}>API ✓</span>}
          </div>
        </div>

      </div>

      {/* ── GLOBAL STATUS BAR ───────────────── */}
      <div style={{ height: 22, background: C.bg0, borderTop: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 12, padding: "0 14px", flexShrink: 0 }}>
        <span style={{ fontSize: 10, color: C.textDim }}>SecureScope IDE v2.0</span>
        <span style={{ fontSize: 10, color: C.textDim }}>·</span>
        <span style={{ fontSize: 10, color: LANG_COLOR[activeTab?.language] || C.textDim }}>{activeTab?.language || "No file open"}</span>
        {activeTab?.filePath && <span style={{ fontSize: 10, color: C.textDim, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{activeTab.filePath}</span>}
        <div style={{ flex: 1 }} />
        {report && (
          <span style={{ fontSize: 10, color: report.criticalCount > 0 ? C.red : C.green }}>
            {report.criticalCount > 0 ? `⚠ ${report.criticalCount} critical` : "✓ No critical issues"}
          </span>
        )}
        <span style={{ fontSize: 10, color: C.textDim }}>Powered by Claude AI</span>
      </div>
    </div>
  );
}
