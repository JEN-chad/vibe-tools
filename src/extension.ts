/**
 * CodeSentry VS Code Extension v1.0.0
 *
 * TWO MODES — automatic, no config needed:
 *   Mode A  Built-in TypeScript scanner (zero prerequisites, works on any machine)
 *   Mode B  Python AST scanner (auto-activates when codesentry is detected)
 *
 * FEATURES ADDED IN THIS VERSION:
 *   autofix      — lightbulb → "Copy fix prompt" → paste into ChatGPT / Claude
 *   one-prompt   — combine ALL file issues into one prompt (same as CLI --autofix --one-prompt)
 *   explain      — side panel with full guidance, before/after code, for every issue
 *   workspace    — copy combined prompt for ALL issues across ALL files
 *   scan on save, scan on type, status bar, suppress, test-path downgrade
 */

import * as vscode from 'vscode';
import * as path   from 'path';
import * as cp     from 'child_process';

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

interface Issue {
  id:       string;
  severity: 'HIGH' | 'MED' | 'LOW';
  file:     string;
  line:     number;
  name:     string;
  why:      string;
  context?: string;
}

interface PythonOutput {
  codesentry_version: string;
  scanned_files:     number;
  summary:           { HIGH: number; MED: number; LOW: number };
  passed:            boolean;
  issues:            Issue[];
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX GUIDANCE  (offline — no API needed, same content as CLI _FIX_GUIDANCE)
// ─────────────────────────────────────────────────────────────────────────────

interface Guide { short: string; before: string; after: string; }

const FIX_GUIDANCE: Record<string, Guide> = {
  P1: {
    short:  'Replace with an environment variable.',
    before: 'api_key = "sk-abc123"',
    after:  'api_key = os.getenv("API_KEY")',
  },
  P1b: {
    short:  'High-entropy string — move to a secrets manager or env variable.',
    before: 'token = "eyJhbGci..."',
    after:  'token = os.getenv("TOKEN")',
  },
  P1_YAML: {
    short:  'Move secret out of YAML into an environment variable.',
    before: 'api_key: sk-live-abc123',
    after:  'api_key: "${API_KEY}"',
  },
  P_SQL: {
    short:  'Use parameterised queries instead of string interpolation.',
    before: 'f"SELECT * FROM users WHERE id={uid}"',
    after:  'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))',
  },
  P_SQL_CONCAT: {
    short:  'Never build SQL by concatenating strings.',
    before: '"SELECT * FROM " + table + " WHERE id=" + uid',
    after:  'cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))',
  },
  P_CONNSTR: {
    short:  'Move the password to an environment variable.',
    before: '"Server=myserver;Password=abc123"',
    after:  'f"Server=myserver;Password={os.getenv(\'DB_PASSWORD\')}"',
  },
  P_SHELL: {
    short:  'Replace os.system/popen with subprocess — never use shell=True.',
    before: 'os.system(f"rm {path}")',
    after:  'subprocess.run(["rm", path], check=True)',
  },
  P_DESER: {
    short:  'Use yaml.safe_load() — avoid pickle.loads() on untrusted input.',
    before: 'yaml.load(data)',
    after:  'yaml.load(data, Loader=yaml.SafeLoader)',
  },
  P_EVAL: {
    short:  'Never eval() user input — use ast.literal_eval() for safe parsing.',
    before: 'eval(request.data)',
    after:  'ast.literal_eval(request.data)',
  },
  P_ADMIN: {
    short:  'Never hardcode credentials. Use environment variables.',
    before: 'username = "admin"',
    after:  'username = os.getenv("ADMIN_USER")',
  },
  P2: {
    short:  'Replace bare except with a specific exception and log it.',
    before: 'except: pass',
    after:  'except ValueError as e: logger.error(e)',
  },
  P3: {
    short:  'Handle the error inside catch — never swallow it silently.',
    before: '.catch(() => {})',
    after:  '.catch((err) => console.error("Caught:", err))',
  },
  P4: {
    short:  'Remove the sensitive field from the log statement.',
    before: 'print(f"Token: {token}")',
    after:  'print("Token received")',
  },
  P7: {
    short:  'Catch specific exception and log it — don\'t discard it.',
    before: 'except Exception: pass',
    after:  'except Exception as e: logger.warning("Unexpected: %s", e)',
  },
  P5: {
    short:  'Resolve or remove the TODO/FIXME before shipping.',
    before: '# TODO: implement this',
    after:  '# (resolved — tracked in issue tracker)',
  },
  P6: {
    short:  'Replace hardcoded URL with an environment variable.',
    before: 'BASE_URL = "http://localhost:3000"',
    after:  'BASE_URL = os.getenv("BASE_URL", "http://localhost:3000")',
  },
  P8: {
    short:  'Set DEBUG from environment, not hardcoded in code.',
    before: 'DEBUG = True',
    after:  'DEBUG = os.getenv("DEBUG", "false").lower() == "true"',
  },
  P_DUP: {
    short:  'Keep one canonical version and import it everywhere.',
    before: '# same function defined in multiple files',
    after:  '# import from one shared module',
  },
  P_NOVALIDATE: {
    short:  'Add input validation before using request data.',
    before: '@app.post("/login")\ndef login(): ...',
    after:  '@app.post("/login")\ndef login():\n    data = LoginSchema(**request.json)',
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// AUTOFIX PROMPT BUILDERS  (identical logic to CLI --autofix / --one-prompt)
// ─────────────────────────────────────────────────────────────────────────────

function buildFixPrompt(issue: Issue): string {
  const g       = FIX_GUIDANCE[issue.id];
  const context = issue.context ?? `(line ${issue.line} in ${path.basename(issue.file)})`;
  const parts   = [
    'Fix this specific issue. Return ONLY the corrected snippet.',
    '',
    `Issue : ${issue.name}`,
    `Why   : ${issue.why}`,
    `File  : ${issue.file}  Line: ${issue.line}`,
    '',
    'Rules:',
    '- Fix ONLY this issue',
    '- Do NOT change unrelated code',
    '- Do NOT refactor or rename',
    '- If unsure, leave unchanged',
    '',
    'Code:',
    context,
  ];
  if (g) {
    parts.push('', `Suggested fix: ${g.short}`, `Before: ${g.before}`, `After:  ${g.after}`);
  }
  return parts.join('\n');
}

function buildOnePrompt(issues: Issue[]): string {
  const parts = [
    'Fix the issues below. Return updated code grouped by file.',
    'No explanations. Fix ONLY listed issues. No refactoring.',
    '',
    'Issues:',
  ];
  issues.forEach((iss, i) => {
    parts.push(
      '',
      `[${i + 1}] ${iss.file}:${iss.line} — ${iss.name}`,
      `Why: ${iss.why}`,
      `Code:\n${iss.context ?? `(line ${iss.line})`}`,
    );
  });
  parts.push('', 'Output: updated code grouped by file only.');
  return parts.join('\n');
}

// ─────────────────────────────────────────────────────────────────────────────
// BUILT-IN SCANNER — 18 patterns in TypeScript, zero prerequisites
// ─────────────────────────────────────────────────────────────────────────────

interface Pattern {
  id:            string;
  severity:      'HIGH' | 'MED' | 'LOW';
  name:          string;
  why:           string;
  regex?:        RegExp;
  custom?:       'entropy';
  extensions:    string[];
  skipTemplates?: boolean;
  strictOnly?:   boolean;
}

const PATTERNS: Pattern[] = [
  { id:'P1',          severity:'HIGH', name:'Hardcoded secret',
    why:'Ships to GitHub and gets scraped by bots within hours.',
    regex:/(api_key|apikey|password|passwd|secret|token|auth_token|access_token|private_key)\s*[:=]\s*['"][^'"]{6,}['"]/i,
    extensions:['.py','.js','.ts','.jsx','.tsx','.env','.sh','.bash','.yaml','.yml'], skipTemplates:true },
  { id:'P1b',         severity:'HIGH', name:'High-entropy secret',
    why:'High-entropy string — likely a raw key or JWT missed by keyword scan.',
    custom:'entropy',
    extensions:['.py','.js','.ts','.jsx','.tsx','.env'], skipTemplates:true },
  { id:'P1_YAML',     severity:'HIGH', name:'Hardcoded secret (YAML/unquoted)',
    why:'Unquoted secret in YAML or env file — scraped by bots within hours.',
    regex:/^(api_key|apikey|password|passwd|secret|token|auth_token|access_token|private_key|stripe_key|sendgrid_key|twilio)\s*:\s*(?!['"{])[^\s#]{6,}/im,
    extensions:['.yaml','.yml','.env'], skipTemplates:true },
  { id:'P_SQL',       severity:'HIGH', name:'SQL string injection',
    why:'Dynamic SQL via string interpolation — SQL injection risk.',
    regex:/(`[^`]*(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE)[^`]*\$\{|f['"][^'"']*(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE)[^'"']*\{)/i,
    extensions:['.py','.js','.ts','.jsx','.tsx'] },
  { id:'P_SQL_CONCAT',severity:'HIGH', name:'SQL string concatenation',
    why:'SQL built by string concatenation — classic injection vector.',
    regex:/['"].*(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE).*['"]\s*\+/i,
    extensions:['.py','.js','.ts','.jsx','.tsx'] },
  { id:'P_CONNSTR',   severity:'HIGH', name:'Hardcoded connection string',
    why:'Database connection string contains an embedded password.',
    regex:/(Password|pwd|Pwd)\s*=\s*[^;>\s'"]{4,}/,
    extensions:['.py','.js','.ts','.jsx','.tsx','.json','.yaml','.yml','.env'], skipTemplates:true },
  { id:'P_SHELL',     severity:'HIGH', name:'Shell injection risk',
    why:'Direct shell execution — allows arbitrary command injection.',
    regex:/(subprocess\.\w+\s*\(.*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(|os\.execvp\s*\(|os\.execve\s*\(|commands\.getoutput\s*\()/,
    extensions:['.py'] },
  { id:'P_DESER',     severity:'HIGH', name:'Unsafe deserialization',
    why:'pickle.loads or yaml.load without Loader can execute arbitrary code.',
    regex:/(pickle\.loads?\s*\(|yaml\.load\s*\([^,)]*\)(?!\s*,\s*Loader))/,
    extensions:['.py'] },
  { id:'P_EVAL',      severity:'HIGH', name:'eval/exec on input',
    why:'eval/exec on user-controlled input = remote code execution.',
    regex:/\b(eval|exec)\s*\(\s*(request|input|data|body|params|user|query)/i,
    extensions:['.py','.js','.ts','.jsx','.tsx'] },
  { id:'P_ADMIN',     severity:'HIGH', name:'Hardcoded admin credentials',
    why:'Default admin credentials hardcoded — trivial to exploit.',
    regex:/(username|user|login)\s*=\s*['"]*(admin|root|administrator)['"]/i,
    extensions:['.py','.js','.ts','.jsx','.tsx','.yaml','.yml'], skipTemplates:true },
  { id:'P2',          severity:'HIGH', name:'Silent error catch',
    why:'Exception swallowed silently — app fails with no trace, no log.',
    regex:/except\s*:\s*pass/, extensions:['.py'] },
  { id:'P3',          severity:'HIGH', name:'Empty catch block',
    why:'JS error swallowed — production failures become completely invisible.',
    regex:/catch\s*\([^)]*\)\s*\{\s*\}|\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/,
    extensions:['.js','.ts','.jsx','.tsx'] },
  { id:'P4',          severity:'HIGH', name:'Sensitive data in log',
    why:'Credentials written to logs end up in monitoring tools.',
    regex:/(console\.log|console\.error|print|logger\.\w+)\s*\(.*?(token|key|password|secret|auth)/i,
    extensions:['.py','.js','.ts','.jsx','.tsx'] },
  { id:'P7',          severity:'MED',  name:'Broad exception swallowed',
    why:'Broad exception caught and discarded — bugs vanish silently.',
    regex:/except\s+(Exception|BaseException)\s*:\s*\n\s*pass/, extensions:['.py'] },
  { id:'P5',          severity:'MED',  name:'TODO in production path',
    why:'AI placeholder left in code that actually runs in production.',
    regex:/(#\s*TODO|\/\/\s*TODO|#\s*FIXME|\/\/\s*FIXME|<!--\s*TODO)/i,
    extensions:['.py','.js','.ts','.jsx','.tsx','.sh','.bash'] },
  { id:'P6',          severity:'MED',  name:'Hardcoded localhost',
    why:'Works on your machine, breaks silently on every real deployment.',
    regex:/(localhost|127\.0\.0\.1|0\.0\.0\.0)/,
    extensions:['.py','.js','.ts','.jsx','.tsx','.json'] },
  { id:'P8',          severity:'LOW',  name:'Debug flag on',
    why:'Debug mode exposes stack traces and internal state in production.',
    regex:/(DEBUG|APP_DEBUG|NODE_ENV)\s*=\s*(True|true|1|development|dev)[^_]/,
    extensions:['.py','.js','.ts','.jsx','.tsx','.env','.yaml','.yml'], skipTemplates:true },
  { id:'P_NOVALIDATE',severity:'MED',  name:'Route without validation hint',
    why:'API route defined — confirm request body/params are validated.',
    regex:/@(app|router|blueprint)\.(get|post|put|patch|delete)\s*\(/i,
    extensions:['.py'], strictOnly:true },
];

// ── Helpers ───────────────────────────────────────────────────────────────────
const TMPL_SFXS = ['.example','.sample','.template','.dist'];
const TEST_DIRS = new Set(['test','tests','spec','specs','fixtures','__mocks__','mocks','fixture']);

const isTemplate = (fp:string) => TMPL_SFXS.some(s => path.basename(fp).toLowerCase().endsWith(s));
const isTestPath = (fp:string) => fp.replace(/\\/g,'/').toLowerCase().split('/').some(p => TEST_DIRS.has(p));
const adjSev = (s:'HIGH'|'MED'|'LOW', fp:string): 'HIGH'|'MED'|'LOW' => {
  if (!isTestPath(fp)) return s;
  const o:Array<'HIGH'|'MED'|'LOW'> = ['HIGH','MED','LOW'];
  return o[Math.min(o.indexOf(s)+1, 2)];
};
const entropy = (s:string): number => {
  if (!s) return 0;
  const f:Record<string,number>={};
  for (const c of s) f[c]=(f[c]||0)+1;
  const n=s.length;
  return -Object.values(f).reduce((a,v)=>{const p=v/n; return a+p*Math.log2(p);},0);
};
const hasHighEntropy = (line:string) =>
  (line.match(/['"]([A-Za-z0-9+/=_\-.]{20,})['"]/g)||[]).some(t => entropy(t.slice(1,-1))>4.5);

const isSuppressed = (line:string, id:string): boolean => {
  if (!line.includes('codesentry-ignore')) return false;
  if (/codesentry-ignore(?!:)/.test(line)) return true;
  const m = line.match(/codesentry-ignore:\s*([A-Za-z0-9_,\s]+)/i);
  return !!m && m[1].split(',').map(s=>s.trim().toUpperCase()).includes(id.toUpperCase());
};

const LANG_MAP: Record<string,string> = {
  python:'.py', javascript:'.js', typescript:'.ts',
  javascriptreact:'.jsx', typescriptreact:'.tsx',
  yaml:'.yaml', json:'.json', shellscript:'.sh',
};

function builtinScan(text:string, filePath:string, langId:string, strict:boolean): Issue[] {
  const ext      = LANG_MAP[langId] || ('.'+filePath.split('.').pop()?.toLowerCase());
  const tmpl     = isTemplate(filePath);
  const lines    = text.split('\n');
  const issues:Issue[] = [];
  const seen     = new Set<string>();

  for (const pat of PATTERNS) {
    if (!pat.extensions.includes(ext)) continue;
    if (pat.skipTemplates && tmpl) continue;
    if (pat.strictOnly && !strict) continue;

    if (pat.custom==='entropy') {
      lines.forEach((line,i) => {
        if (isSuppressed(line,pat.id)||!hasHighEntropy(line)) return;
        const key=`${pat.id}:${i+1}`;
        if (seen.has(key)) return;
        seen.add(key);
        const ctx = lines.slice(Math.max(0,i-2),Math.min(lines.length,i+3)).join('\n');
        issues.push({id:pat.id,severity:adjSev(pat.severity,filePath),
          name:pat.name,why:pat.why,file:filePath,line:i+1,context:ctx});
      });
      continue;
    }
    if (!pat.regex) continue;

    const rx = new RegExp(pat.regex.source,'gim');
    let m:RegExpExecArray|null;
    while ((m=rx.exec(text))!==null) {
      const ln  = text.slice(0,m.index).split('\n').length;
      const ltx = lines[ln-1]||'';
      if (isSuppressed(ltx,pat.id)) continue;
      const tr = ltx.trimStart();
      if (tr.startsWith('#')||tr.startsWith('//')||tr.startsWith('*')) continue;
      const key=`${pat.id}:${ln}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const ctx = lines.slice(Math.max(0,ln-3),Math.min(lines.length,ln+2)).join('\n');
      issues.push({id:pat.id,severity:adjSev(pat.severity,filePath),
        name:pat.name,why:pat.why,file:filePath,line:ln,context:ctx});
    }
  }
  return issues;
}

// ─────────────────────────────────────────────────────────────────────────────
// PYTHON DETECTION
// ─────────────────────────────────────────────────────────────────────────────

let pythonAvailable: boolean|null = null;

async function checkPython(): Promise<boolean> {
  if (pythonAvailable!==null) return pythonAvailable;
  return new Promise(resolve => {
    cp.execFile('codesentry',['--version'],{timeout:5000},(_e,stdout) => {
      pythonAvailable = !_e && stdout.includes('1.0');
      resolve(pythonAvailable);
    });
  });
}

function pythonScan(fp:string,wsDir:string,strict:boolean,cb:(i:Issue[],ok:boolean)=>void): void {
  const cfg      = vscode.workspace.getConfiguration('codesentry');
  const exe      = cfg.get<string>('codesentryPath','codesentry');
  const args     = ['check',wsDir,'--output','json','--commits','1'];
  if (strict) args.push('--strict');
  cp.execFile(exe,args,{cwd:wsDir,timeout:20000},(_e,stdout)=>{
    try {
      const out:PythonOutput = JSON.parse(stdout);
      const rel = path.relative(wsDir,fp).replace(/\\/g,'/');
      cb(out.issues.filter(i=>i.file===rel||fp.endsWith(i.file)),true);
    } catch { cb([],false); }
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// EXPLAIN WEBVIEW
// ─────────────────────────────────────────────────────────────────────────────

function showExplainPanel(_ctx: vscode.ExtensionContext, issues: Issue[]): void {
  const panel = vscode.window.createWebviewPanel(
    'codesentryExplain','CodeSentry — Fix Guidance',
    vscode.ViewColumn.Beside, {enableScripts:false}
  );

  const escH = (s:string) => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const rows = issues.map((iss,i) => {
    const g   = FIX_GUIDANCE[iss.id];
    let col = '#3B82F6';
    if (iss.severity === 'HIGH') col = '#EF4444';
    else if (iss.severity === 'MED') col = '#F59E0B';
    
    return `
    <div class="issue">
      <div class="hdr">
        <span class="num">${i+1}</span>
        <span class="badge" style="background:${col}">${iss.id}</span>
        <span class="name">${escH(iss.name)}</span>
        <span class="loc">${escH(path.basename(iss.file))}:${iss.line}</span>
      </div>
      <p class="why">${escH(iss.why)}</p>
      ${iss.context ? `<pre class="ctx">${escH(iss.context)}</pre>` : ''}
      ${g ? `
        <p class="fix-lbl">How to fix</p>
        <p>${escH(g.short)}</p>
        <table class="diff">
          <tr><td class="bl">Before</td><td class="bc">${escH(g.before)}</td></tr>
          <tr><td class="al">After</td><td class="ac">${escH(g.after)}</td></tr>
        </table>` : ''}
    </div>`;
  }).join('');

  panel.webview.html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; font-src https://fonts.gstatic.com; style-src 'unsafe-inline' https://fonts.googleapis.com; script-src 'unsafe-inline';">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
<style>
body{font-family:'Inter', sans-serif;font-size:13px;padding:24px;background:#0A0D14;color:#E2E8F0;line-height:1.5;}
h2{font-size:16px;font-weight:600;margin:0 0 20px;color:#F8FAFC;letter-spacing:0.3px;}
.issue{border:1px solid #1E2433;border-radius:8px;background:#111520;margin-bottom:16px;padding:16px;box-shadow:0 4px 12px rgba(0,0,0,0.1);}
.hdr{display:flex;align-items:center;gap:10px;margin-bottom:12px;}
.num{background:#1E2433;color:#94A3B8;border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;flex-shrink:0;}
.badge{color:#fff;border-radius:4px;padding:3px 8px;font-size:10px;text-transform:uppercase;font-weight:700;letter-spacing:0.5px;flex-shrink:0;}
.name{font-weight:600;font-size:14px;color:#F8FAFC;}
.loc{margin-left:auto;font-size:12px;color:#64748B;font-family:'JetBrains Mono', monospace;}
.why{color:#CBD5E1;margin:0 0 12px;}
pre.ctx{background:#0A0D14;border:1px solid #1E2433;border-radius:6px;padding:12px;font-size:12px;overflow:auto;margin:0 0 12px;white-space:pre-wrap;font-family:'JetBrains Mono', monospace;color:#E2E8F0;}
.fix-lbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:#94A3B8;margin:12px 0 6px;}
table.diff{width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;}
td{padding:8px 10px;border-bottom:1px solid #1E2433;}
tr:last-child td{border-bottom:none;}
.bl{color:#EF4444;font-weight:600;width:60px;}
.al{color:#10B981;font-weight:600;width:60px;}
.bc{background:rgba(239,68,68,0.1);color:#FCA5A5;font-family:'JetBrains Mono', monospace;border-radius:4px;}
.ac{background:rgba(16,185,129,0.1);color:#6EE7B7;font-family:'JetBrains Mono', monospace;border-radius:4px;}
</style></head><body>
<h2>CodeSentry — \${issues.length} issue(s)</h2>
\${rows||'<p style="color:#64748B">No issues to explain.</p>'}
</body></html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD WEBVIEW  — live security overview connecting CLI + extension
// ─────────────────────────────────────────────────────────────────────────────

let dashboardPanel: vscode.WebviewPanel | undefined;

function buildDashboardHtml(
  allIssues: Issue[],
  scannedFiles: number,
  enhancedMode: boolean,
): string {

  const HIGH  = allIssues.filter(i => i.severity === 'HIGH').length;
  const MED   = allIssues.filter(i => i.severity === 'MED').length;
  const LOW   = allIssues.filter(i => i.severity === 'LOW').length;
  const TOTAL = allIssues.length;

  const score = TOTAL === 0 ? 100 : Math.max(0, 100 - (HIGH * 10 + MED * 3 + LOW * 1));

  // category breakdown
  const catCount: Record<string, number> = {};
  for (const iss of allIssues) catCount[iss.id] = (catCount[iss.id] || 0) + 1;
  const TOP_CATS = Object.entries(catCount).sort((a,b) => b[1]-a[1]).slice(0, 6);

  const CAT_LABELS: Record<string, string> = {
    P1:'Hardcoded secret', P1b:'High-entropy key', P1_YAML:'YAML secret',
    P_SQL:'SQL injection', P_SQL_CONCAT:'SQL concat', P_CONNSTR:'Connection string',
    P_SHELL:'Shell injection', P_DESER:'Unsafe deserialise', P_EVAL:'eval/exec',
    P_ADMIN:'Admin credentials', P2:'Silent catch (Py)', P3:'Empty catch (JS)',
    P4:'Secret in log', P7:'Broad exception', P5:'TODO in prod',
    P6:'Hardcoded localhost', P8:'Debug flag', P_NOVALIDATE:'No input validation',
  };

  const escH = (s: string) =>
    s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Expandable issue rows
  const issueRows = allIssues.slice(0, 50).map((iss, i) => {
    const sevColor = iss.severity === 'HIGH' ? '#EF4444' : iss.severity === 'MED' ? '#F59E0B' : '#3B82F6';
    return `
    <div class="issue-card" data-idx="${i}">
      <div class="issue-header" onclick="this.parentElement.classList.toggle('expanded')">
        <div class="issue-sev-indicator" style="background:${sevColor}"></div>
        <div class="issue-title-group">
          <span class="issue-title">${escH(iss.name)}</span>
          <span class="issue-id">${escH(iss.id)}</span>
        </div>
        <div class="issue-location">${escH(path.basename(iss.file))}:${iss.line}</div>
        <div class="expand-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
        </div>
      </div>
      <div class="issue-body">
        <p class="issue-why">${escH(iss.why)}</p>
        ${iss.context ? `<div class="issue-code"><pre><code>${escH(iss.context)}</code></pre></div>` : ''}
      </div>
    </div>`;
  }).join('');

  // Bar chart bars (max bar = 100%)
  const maxCat = Math.max(1, ...TOP_CATS.map(c => c[1]));
  const barHtml = TOP_CATS.map(([id, count]) => {
    const pct = Math.round((count / maxCat) * 100);
    return `
    <div class="chart-row">
      <div class="chart-lbl" title="${escH(CAT_LABELS[id] || id)}">${escH(CAT_LABELS[id] || id)}</div>
      <div class="chart-track"><div class="chart-fill" style="width:${pct}%"></div></div>
      <div class="chart-val">${count}</div>
    </div>`;
  }).join('');

  const radius = 38;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const scoreColor = score >= 90 ? '#10B981' : score >= 70 ? '#F59E0B' : '#EF4444';

  const modeHtml = enhancedMode
    ? '<span class="badge-mode ast">⚡ AST Active</span>'
    : '<span class="badge-mode ts">TS Built-in</span>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; font-src https://fonts.gstatic.com; style-src 'unsafe-inline' https://fonts.googleapis.com; script-src 'unsafe-inline';">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<title>CodeSentry Dashboard</title>
<style>
  :root {
    --bg-main: #0A0D14;
    --bg-panel: #111520;
    --border: #1C2130;
    --text-main: #E2E8F0;
    --text-muted: #94A3B8;
    --accent: #3B82F6;
    --accent-hover: #2563EB;
    --high: #EF4444;
    --med: #F59E0B;
    --low: #3B82F6;
    --safe: #10B981;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 13px;
    background: var(--bg-main);
    color: var(--text-main);
    min-height: 100vh;
    background-image: linear-gradient(var(--border) 1px, transparent 1px), linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 40px 40px;
    background-position: center top;
  }
  
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; display: flex; flex-direction: column; gap: 24px; }
  
  .hdr {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 24px; background: var(--bg-panel); border: 1px solid var(--border);
    border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.2);
  }
  .hdr-left { display: flex; align-items: center; gap: 12px; }
  .logo { display:flex; align-items:center; justify-content:center; width:32px; height:32px; background:rgba(59,130,246,0.1); border-radius:8px; border:1px solid rgba(59,130,246,0.2); }
  .brand { font-size: 16px; font-weight: 700; letter-spacing: 0.5px; color: #F8FAFC; }
  .badge-mode { padding: 4px 8px; border-radius: 6px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-left:8px; }
  .badge-mode.ast { background: rgba(59,130,246,0.15); color: #60A5FA; border: 1px solid rgba(59,130,246,0.3); }
  .badge-mode.ts { background: var(--border); color: #CBD5E1; }
  .hdr-right { display: flex; align-items: center; gap: 12px; }
  
  .btn {
    font-family: 'Inter', sans-serif; font-size: 12px; font-weight: 600;
    padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer;
    transition: all 0.2s ease; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent-hover); transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
  .btn-ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
  .btn-ghost:hover { background: var(--border); color: var(--text-main); }
  .btn.loading { opacity: 0.7; pointer-events: none; }
  .btn.loading svg { animation: spin 1s linear infinite; }
  @keyframes spin { 100% { transform: rotate(360deg); } }
  
  .top-grid { display: grid; grid-template-columns: 280px 1fr; gap: 24px; }
  
  .panel {
    background: var(--bg-panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 24px; box-shadow: 0 4px 20px rgba(0,0,0,0.15);
  }
  .panel-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }
  
  .score-container { display: flex; flex-direction: column; align-items: center; position: relative; }
  .ring-wrapper { position: relative; width: 140px; height: 140px; }
  .ring-svg { transform: rotate(-90deg); width: 100%; height: 100%; }
  .ring-bg { fill: none; stroke: var(--border); stroke-width: 8; }
  .ring-fill { fill: none; stroke: ${scoreColor}; stroke-width: 8; stroke-linecap: round; stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset}; transition: stroke-dashoffset 1s ease-out; }
  .score-value { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
  .score-num { font-size: 36px; font-weight: 700; color: #F8FAFC; line-height: 1; }
  .score-lbl { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  
  .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 24px; width: 100%; }
  .stat-card { background: var(--bg-main); border: 1px solid var(--border); padding: 12px; border-radius: 8px; text-align: center; }
  .stat-val { font-size: 20px; font-weight: 700; line-height: 1.2; }
  .stat-val.high { color: var(--high); }
  .stat-val.med { color: var(--med); }
  .stat-val.low { color: var(--low); }
  .stat-lbl { font-size: 10px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-top: 4px; }

  .mid-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
  
  .issue-list { display: flex; flex-direction: column; gap: 8px; max-height: 500px; overflow-y: auto; padding-right: 8px; }
  .issue-list::-webkit-scrollbar { width: 6px; }
  .issue-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  
  .issue-card { background: var(--bg-main); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; transition: border-color 0.2s; }
  .issue-card:hover { border-color: rgba(255,255,255,0.1); }
  .issue-header { display: flex; align-items: center; padding: 12px 16px; cursor: pointer; gap: 12px; user-select: none; }
  .issue-sev-indicator { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; box-shadow: 0 0 8px currentColor; }
  .issue-title-group { flex: 1; display: flex; align-items: center; gap: 10px; }
  .issue-title { font-size: 13px; font-weight: 500; color: #F8FAFC; }
  .issue-id { font-size: 10px; background: var(--border); padding: 2px 6px; border-radius: 4px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }
  .issue-location { font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; text-align: right; }
  .expand-icon { transition: transform 0.2s; color: var(--text-muted); display:flex; align-items:center; }
  .issue-card.expanded .expand-icon { transform: rotate(180deg); }
  
  .issue-body { display: none; padding: 0 16px 16px 16px; border-top: 1px solid transparent; }
  .issue-card.expanded .issue-body { display: block; border-top-color: var(--border); padding-top: 16px; }
  .issue-why { font-size: 12px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.5; }
  .issue-code { background: #000; border: 1px solid var(--border); border-radius: 6px; padding: 12px; overflow-x: auto; }
  .issue-code pre { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #AEE2FF; line-height: 1.5; }
  
  .chart-row { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
  .chart-lbl { font-size: 11px; width: 120px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--text-muted); }
  .chart-track { flex: 1; height: 6px; background: var(--bg-main); border-radius: 3px; overflow: hidden; border: 1px solid var(--border); }
  .chart-fill { height: 100%; background: var(--med); border-radius: 3px; transition: width 0.6s ease; }
  .chart-val { font-size: 11px; font-weight: 600; width: 24px; text-align: right; }
  
  .ai-box {
    background: linear-gradient(145deg, rgba(59,130,246,0.1) 0%, rgba(59,130,246,0.02) 100%);
    border: 1px solid rgba(59,130,246,0.2); border-radius: 8px; padding: 16px; margin-top: 24px;
    display: flex; gap: 16px; align-items: flex-start;
  }
  .ai-icon { width: 32px; height: 32px; background: var(--accent); border-radius: 8px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; box-shadow: 0 4px 12px rgba(59,130,246,0.3); }
  .ai-content p { font-size: 12px; color: #CBD5E1; line-height: 1.5; margin-bottom: 12px; }
  .ai-content strong { color: #fff; font-weight: 600; }
  
  .empty-state { text-align: center; padding: 48px 24px; }
  .empty-icon { width: 48px; height: 48px; margin: 0 auto 16px; color: var(--safe); }
  .empty-state h3 { font-size: 16px; font-weight: 600; color: #F8FAFC; margin-bottom: 8px; }
  .empty-state p { font-size: 13px; color: var(--text-muted); }
</style>
</head>
<body>

<div class="container">
  
  <div class="hdr">
    <div class="hdr-left">
      <div class="logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
      </div>
      <span class="brand">CodeSentry</span>
      ${modeHtml}
    </div>
    <div class="hdr-right">
      <button class="btn btn-ghost" id="btn-refresh" onclick="refresh()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg>
        Rescan
      </button>
      <button class="btn btn-primary" onclick="copyAll()" id="btn-copy">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
        Auto-Fix Issues
      </button>
    </div>
  </div>

  <div class="top-grid">
    <div class="panel">
      <div class="panel-title">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
        Security Score
      </div>
      <div class="score-container">
        <div class="ring-wrapper">
          <svg class="ring-svg" viewBox="0 0 84 84">
            <circle class="ring-bg" cx="42" cy="42" r="38"></circle>
            <circle class="ring-fill" cx="42" cy="42" r="38"></circle>
          </svg>
          <div class="score-value">
            <span class="score-num" style="color:${scoreColor}">${score}</span>
            <span class="score-lbl">/ 100</span>
          </div>
        </div>
      </div>
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-val high">${HIGH}</div>
          <div class="stat-lbl">Critical</div>
        </div>
        <div class="stat-card">
          <div class="stat-val med">${MED}</div>
          <div class="stat-lbl">Warnings</div>
        </div>
        <div class="stat-card">
          <div class="stat-val low">${LOW}</div>
          <div class="stat-lbl">Info</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" style="color:var(--text-main)">${scannedFiles}</div>
          <div class="stat-lbl">Files Scanned</div>
        </div>
      </div>
    </div>

    <div class="mid-grid">
      <div class="panel">
        <div class="panel-title">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          Active Threats
        </div>
        ${TOTAL === 0 ? `
        <div class="empty-state">
          <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
          <h3>Workspace is Clean</h3>
          <p>No security vulnerabilities detected.</p>
        </div>` : `
        <div class="issue-list">${issueRows}</div>
        ${allIssues.length > 50 ? `<div style="text-align:center; padding-top:16px; color:var(--text-muted); font-size:12px;">+ ${allIssues.length - 50} more issues</div>` : ''}
        `}
      </div>

      <div style="display:flex; flex-direction:column; gap:24px;">
        <div class="panel" style="flex:1;">
          <div class="panel-title">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
            Vulnerability Types
          </div>
          ${TOTAL === 0 ? '<p style="color:var(--text-muted);font-size:12px;text-align:center;">No data available</p>' : barHtml}
        </div>
        
        ${TOTAL > 0 ? `
        <div class="ai-box">
          <div class="ai-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>
          </div>
          <div class="ai-content">
            <p><strong>CodeSentry AI</strong> can generate a complete fix prompt for all ${TOTAL} issues across ${scannedFiles} files.</p>
            <button class="btn btn-primary" onclick="copyAll()" id="btn-copy-small" style="padding:6px 12px; font-size:11px;">Copy Prompt</button>
          </div>
        </div>
        ` : ''}
      </div>
    </div>
  </div>

</div>

<script>
  const vscode = acquireVsCodeApi();

  function refresh() {
    const btn = document.getElementById('btn-refresh');
    btn.classList.add('loading');
    vscode.postMessage({ command: 'refresh' });
  }

  function copyAll() {
    vscode.postMessage({ command: 'copyAll' });
    const btn = document.getElementById('btn-copy');
    const btnSmall = document.getElementById('btn-copy-small');
    const oldHtml = btn.innerHTML;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
    if (btnSmall) btnSmall.textContent = 'Copied!';
    setTimeout(() => { 
      btn.innerHTML = oldHtml; 
      if (btnSmall) btnSmall.textContent = 'Copy Prompt';
    }, 2000);
  }

  window.addEventListener('message', e => {
    if (e.data.command === 'scanDone') {
      const btn = document.getElementById('btn-refresh');
      btn.classList.remove('loading');
    }
  });
</script>
</body>
</html>`;
}

function openDashboard(context: vscode.ExtensionContext): void {
  if (dashboardPanel) {
    dashboardPanel.reveal(vscode.ViewColumn.Beside);
    refreshDashboard();
    return;
  }

  dashboardPanel = vscode.window.createWebviewPanel(
    'codeSentryDashboard',
    'CodeSentry Dashboard',
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  dashboardPanel.onDidDispose(() => { dashboardPanel = undefined; }, null, context.subscriptions);

  dashboardPanel.webview.onDidReceiveMessage(msg => {
    switch (msg.command) {
      case 'refresh':
        scanWorkspace();
        setTimeout(() => {
          refreshDashboard();
          dashboardPanel?.webview.postMessage({ command: 'scanDone' });
        }, 3000);
        break;
      case 'copyAll': {
        const all: Issue[] = [];
        lastIssues.forEach(v => all.push(...v));
        vscode.env.clipboard.writeText(buildOnePrompt(all)).then(() =>
          vscode.window.showInformationMessage(`CodeSentry: fix prompt for ${all.length} issue(s) copied!`)
        );
        break;
      }
      case 'scanWorkspace':
        scanWorkspace();
        setTimeout(() => refreshDashboard(), 3000);
        break;
    }
  }, null, context.subscriptions);

  refreshDashboard();
}

function refreshDashboard(): void {
  if (!dashboardPanel) return;
  const all: Issue[] = [];
  lastIssues.forEach(v => all.push(...v));
  const files = new Set(all.map(i => i.file)).size;
  dashboardPanel.webview.html = buildDashboardHtml(all, files, enhancedMode);
}

// ─────────────────────────────────────────────────────────────────────────────
// CODE ACTION PROVIDER  (lightbulb menu)
// ─────────────────────────────────────────────────────────────────────────────

class CodeSentryActions implements vscode.CodeActionProvider {
  static readonly kinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(doc: vscode.TextDocument, range: vscode.Range): vscode.CodeAction[] {
    const allIssues = lastIssues.get(doc.uri.toString()) || [];
    if (!allIssues.length) return [];

    const ln = range.start.line + 1;  // 1-based
    const lineIssues = allIssues.filter(i => i.line === ln);
    const actions: vscode.CodeAction[] = [];

    // Per-issue "Copy fix prompt" action
    for (const iss of lineIssues) {
      const a = new vscode.CodeAction(
        `CodeSentry: Copy fix prompt — ${iss.id} (${iss.name})`,
        vscode.CodeActionKind.QuickFix
      );
      a.command = { command:'codesentry.copyFixPrompt', title:'Copy fix prompt', arguments:[iss] };
      a.isPreferred = lineIssues.indexOf(iss) === 0;
      actions.push(a);
    }

    // "Copy ONE prompt for all issues in file" (always visible if issues exist)
    if (allIssues.length > 0) {
      const a = new vscode.CodeAction(
        `CodeSentry: Copy ONE prompt for all ${allIssues.length} issue(s) in file`,
        vscode.CodeActionKind.QuickFix
      );
      a.command = { command:'codesentry.copyOnePrompt', title:'One prompt', arguments:[allIssues] };
      actions.push(a);
    }

    // "Explain all issues" shortcut
    if (allIssues.length > 0) {
      const a = new vscode.CodeAction(
        'CodeSentry: Open fix guidance panel',
        vscode.CodeActionKind.QuickFix
      );
      a.command = { command:'codesentry.explainIssues', title:'Explain' };
      actions.push(a);
    }

    return actions;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────────────────────────────────────

let diagCollection: vscode.DiagnosticCollection;
let statusBar:      vscode.StatusBarItem;
let scanTimeout:    ReturnType<typeof setTimeout>|undefined;
let enhancedMode =  false;
const lastIssues  = new Map<string, Issue[]>();   // uri → issues

// ─────────────────────────────────────────────────────────────────────────────
// ACTIVATE
// ─────────────────────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  diagCollection = vscode.languages.createDiagnosticCollection('codesentry');
  context.subscriptions.push(diagCollection);

  // Status bar
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'codesentry.openDashboard';   // click → dashboard
  context.subscriptions.push(statusBar);
  statusBar.show();
  updateBar(0, 0, false);

  // Python detection (async, non-blocking — never delays startup)
  checkPython().then(ok => {
    enhancedMode = ok;
    updateBar(0, 0, ok);
    if (ok) vscode.window.setStatusBarMessage('$(shield) CodeSentry: AST mode active ✦', 4000);
  });

  // Code action provider (lightbulb)
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      ['python','javascript','typescript','javascriptreact','typescriptreact','yaml','json'],
      new CodeSentryActions(),
      { providedCodeActionKinds: CodeSentryActions.kinds }
    )
  );

  // ── Commands ──────────────────────────────────────────────────────────────
  context.subscriptions.push(

    vscode.commands.registerCommand('codesentry.scanFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) scan(doc);
    }),

    vscode.commands.registerCommand('codesentry.scanWorkspace', scanWorkspace),

    vscode.commands.registerCommand('codesentry.clearDiagnostics', () => {
      diagCollection.clear(); lastIssues.clear(); updateBar(0,0,enhancedMode);
    }),

    // autofix: copy single-issue prompt
    vscode.commands.registerCommand('codesentry.copyFixPrompt', async (iss: Issue) => {
      await vscode.env.clipboard.writeText(buildFixPrompt(iss));
      vscode.window.showInformationMessage(
        `CodeSentry: Fix prompt for ${iss.id} copied! Paste into ChatGPT or Claude.`
      );
    }),

    // autofix --one-prompt: combine all issues in file
    vscode.commands.registerCommand('codesentry.copyOnePrompt', async (issues: Issue[]) => {
      await vscode.env.clipboard.writeText(buildOnePrompt(issues));
      vscode.window.showInformationMessage(
        `CodeSentry: Combined prompt for ${issues.length} issue(s) copied!`
      );
    }),

    // explain: open side panel
    vscode.commands.registerCommand('codesentry.explainIssues', () => {
      const doc    = vscode.window.activeTextEditor?.document;
      if (!doc) return;
      const issues = lastIssues.get(doc.uri.toString()) || [];
      if (!issues.length) {
        vscode.window.showInformationMessage('CodeSentry: No issues in this file.');
        return;
      }
      showExplainPanel(context, issues);
    }),

    // open live security dashboard
    vscode.commands.registerCommand('codesentry.openDashboard', () => {
      openDashboard(context);
    }),

    // copy prompt for ALL issues in workspace
    vscode.commands.registerCommand('codesentry.copyWorkspacePrompt', async () => {
      const all: Issue[] = [];
      lastIssues.forEach(v => all.push(...v));
      if (!all.length) {
        vscode.window.showInformationMessage('CodeSentry: No issues found in workspace.');
        return;
      }
      await vscode.env.clipboard.writeText(buildOnePrompt(all));
      vscode.window.showInformationMessage(
        `CodeSentry: Workspace prompt for ${all.length} issue(s) copied!`
      );
    }),

  );

  // ── Auto-scan on save ────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const cfg = vscode.workspace.getConfiguration('codesentry');
      if (cfg.get('enabled') && cfg.get('scanOnSave') && supported(doc)) scan(doc);
    })
  );

  // ── Scan on type (debounced) ────────────────────────────────────────────
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(ev => {
      const cfg = vscode.workspace.getConfiguration('codesentry');
      if (!cfg.get('enabled')||!cfg.get('scanOnType')||!supported(ev.document)) return;
      if (scanTimeout) clearTimeout(scanTimeout);
      scanTimeout = setTimeout(() => scan(ev.document), 1500);
    })
  );

  // ── Scan on file open ───────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(ed => {
      if (ed && supported(ed.document)) scan(ed.document);
    })
  );

  // ── Scan on startup ─────────────────────────────────────────────────────
  const active = vscode.window.activeTextEditor?.document;
  if (active && supported(active)) scan(active);
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

const SUPPORTED = new Set([
  'python','javascript','typescript','javascriptreact',
  'typescriptreact','yaml','json','shellscript',
]);
const supported = (doc: vscode.TextDocument) => SUPPORTED.has(doc.languageId) && !doc.isUntitled;

function scan(doc: vscode.TextDocument): void {
  const cfg    = vscode.workspace.getConfiguration('codesentry');
  if (!cfg.get('enabled',true)) return;
  const strict = cfg.get<boolean>('strict',false);
  const wsDir  = vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath
              || path.dirname(doc.uri.fsPath);

  statusBar.text = '$(sync~spin) CodeSentry…';

  const done = (issues: Issue[]) => {
    lastIssues.set(doc.uri.toString(), issues);
    diagCollection.set(doc.uri, todiags(issues, doc));
    recalcBar();
    refreshDashboard();   // keep dashboard in sync
  };

  if (enhancedMode) {
    pythonScan(doc.uri.fsPath, wsDir, strict, (issues, ok) =>
      done(ok ? issues : builtinScan(doc.getText(), doc.uri.fsPath, doc.languageId, strict))
    );
  } else {
    done(builtinScan(doc.getText(), doc.uri.fsPath, doc.languageId, strict));
  }
}

function scanWorkspace(): void {
  const cfg     = vscode.workspace.getConfiguration('codesentry');
  const strict  = cfg.get<boolean>('strict',false);
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return;
  const wsDir   = folders[0].uri.fsPath;
  statusBar.text = '$(sync~spin) CodeSentry: workspace…';

  if (enhancedMode) {
    const exe  = cfg.get<string>('codesentryPath','codesentry');
    const args = ['check',wsDir,'--output','json','--full'];
    if (strict) args.push('--strict');
    cp.execFile(exe, args, {cwd:wsDir,timeout:60000}, (_e,stdout) => {
      try {
        const out: PythonOutput = JSON.parse(stdout);
        diagCollection.clear();
        const byFile = new Map<string,Issue[]>();
        for (const i of out.issues) { if (!byFile.has(i.file)) byFile.set(i.file,[]); byFile.get(i.file)!.push(i); }
        for (const [rel,issues] of byFile) {
          const uri = vscode.Uri.file(path.join(wsDir,rel));
          lastIssues.set(uri.toString(),issues);
          diagCollection.set(uri,todiags(issues,null));
        }
        updateBar(out.summary.HIGH,out.summary.MED,true);
        vscode.window.showInformationMessage(`CodeSentry: ${out.scanned_files} files — ${out.summary.HIGH} HIGH · ${out.summary.MED} MED`);
      } catch { vscode.window.showWarningMessage('CodeSentry: workspace scan failed.'); }
    });
  } else {
    let high=0, med=0;
    diagCollection.clear();
    for (const doc of vscode.workspace.textDocuments) {
      if (!supported(doc)) continue;
      const issues = builtinScan(doc.getText(),doc.uri.fsPath,doc.languageId,strict);
      lastIssues.set(doc.uri.toString(),issues);
      diagCollection.set(doc.uri,todiags(issues,doc));
      for (const i of issues) { if(i.severity==='HIGH') high++; else if(i.severity==='MED') med++; }
    }
    updateBar(high,med,false);
    vscode.window.showInformationMessage(`CodeSentry: ${high} HIGH · ${med} MED`);
  }
}

function todiags(issues: Issue[], doc: vscode.TextDocument|null): vscode.Diagnostic[] {
  const cfg       = vscode.workspace.getConfiguration('codesentry');
  const showHints = cfg.get<boolean>('showInlineHints',true);
  return issues.map(iss => {
    const li = Math.max(0,iss.line-1);
    let range: vscode.Range;
    if (doc && li<doc.lineCount) {
      const l = doc.lineAt(li);
      range = new vscode.Range(li,l.firstNonWhitespaceCharacterIndex,li,l.text.length);
    } else { range = new vscode.Range(li,0,li,999); }

    const sev = iss.severity==='HIGH' ? vscode.DiagnosticSeverity.Error
              : iss.severity==='MED'  ? vscode.DiagnosticSeverity.Warning
              :                          vscode.DiagnosticSeverity.Information;

    const g   = FIX_GUIDANCE[iss.id];
    const fix = g ? `\n\nFix: ${g.short}\nBefore: ${g.before}\nAfter:  ${g.after}` : '';
    const msg = `[${iss.id}] ${iss.name}\n\n${iss.why}${showHints?fix:''}`;
    const d   = new vscode.Diagnostic(range, msg, sev);
    d.source  = 'codesentry';
    d.code    = iss.id;
    return d;
  });
}

function recalcBar(): void {
  let h=0, m=0;
  diagCollection.forEach((_,ds) => { for (const d of ds) { if(d.severity===0) h++; else if(d.severity===1) m++; } });
  updateBar(h,m,enhancedMode);
}

function updateBar(high: number, med: number, enhanced: boolean): void {
  const s = enhanced?' ✦':'';
  if (high>0) {
    statusBar.text            = `$(error) CodeSentry${s}: ${high} HIGH`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    statusBar.tooltip         = `${high} HIGH issue(s). Click to re-scan.${enhanced?'\n⚡ AST mode':''}`;
  } else if (med>0) {
    statusBar.text            = `$(warning) CodeSentry${s}: ${med} MED`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBar.tooltip         = `${med} MED issue(s). Click to re-scan.`;
  } else {
    statusBar.text            = `$(shield) CodeSentry${s}: clean`;
    statusBar.backgroundColor = undefined;
    statusBar.tooltip         = `No issues. Click to re-scan.${enhanced?'\n⚡ AST mode':''}`;
  }
}

export function deactivate(): void {
  diagCollection?.dispose();
  statusBar?.dispose();
  if (scanTimeout) clearTimeout(scanTimeout);
}
