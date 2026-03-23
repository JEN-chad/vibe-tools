/**
 * Vibeguard VS Code Extension v1.0.0
 *
 * TWO MODES — automatic, no config needed:
 *   Mode A  Built-in TypeScript scanner (zero prerequisites, works on any machine)
 *   Mode B  Python AST scanner (auto-activates when jenchad-guard is detected)
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
  vibeguard_version: string;
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
  if (!line.includes('vibecheck-ignore')) return false;
  if (/vibecheck-ignore(?!:)/.test(line)) return true;
  const m = line.match(/vibecheck-ignore:\s*([A-Za-z0-9_,\s]+)/i);
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
    cp.execFile('vibeguard',['--version'],{timeout:5000},(_e,stdout) => {
      pythonAvailable = !_e && stdout.includes('1.0');
      resolve(pythonAvailable);
    });
  });
}

function pythonScan(fp:string,wsDir:string,strict:boolean,cb:(i:Issue[],ok:boolean)=>void): void {
  const cfg      = vscode.workspace.getConfiguration('vibeguard');
  const exe      = cfg.get<string>('vibeguardPath','vibeguard');
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
    'vibeguardExplain','Vibeguard — Fix Guidance',
    vscode.ViewColumn.Beside, {enableScripts:false}
  );

  const escH = (s:string) => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const rows = issues.map((iss,i) => {
    const g   = FIX_GUIDANCE[iss.id];
    const col = iss.severity==='HIGH'?'#dc2626':iss.severity==='MED'?'#d97706':'#2563eb';
    return `
    <div class="issue">
      <div class="hdr">
        <span class="num">${i+1}</span>
        <span class="badge" style="background:${col}">${iss.id}</span>
        <span class="name">${escH(iss.name)}</span>
        <span class="loc">${escH(path.basename(iss.file))}:${iss.line}</span>
      </div>
      <p class="why">${escH(iss.why)}</p>
      ${iss.context?`<pre class="ctx">${escH(iss.context)}</pre>`:''}
      ${g?`
        <p class="fix-lbl">How to fix</p>
        <p>${escH(g.short)}</p>
        <table class="diff">
          <tr><td class="bl">Before</td><td class="bc">${escH(g.before)}</td></tr>
          <tr><td class="al">After</td><td class="ac">${escH(g.after)}</td></tr>
        </table>`:''}
    </div>`;
  }).join('');

  panel.webview.html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:var(--vscode-font-family);font-size:13px;padding:16px;
     background:var(--vscode-editor-background);color:var(--vscode-editor-foreground)}
h2{font-size:15px;margin:0 0 14px}
.issue{border:1px solid var(--vscode-panel-border);border-radius:6px;
       margin-bottom:12px;padding:14px}
.hdr{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.num{background:var(--vscode-badge-background);color:var(--vscode-badge-foreground);
     border-radius:50%;width:20px;height:20px;display:flex;align-items:center;
     justify-content:center;font-size:11px;flex-shrink:0}
.badge{color:#fff;border-radius:4px;padding:2px 7px;font-size:11px;
       font-weight:600;flex-shrink:0}
.name{font-weight:600;font-size:13px}
.loc{margin-left:auto;font-size:11px;color:var(--vscode-descriptionForeground)}
.why{color:var(--vscode-descriptionForeground);margin:0 0 8px}
pre.ctx{background:var(--vscode-textCodeBlock-background);border-radius:4px;
        padding:8px;font-size:12px;overflow:auto;margin:0 0 8px;white-space:pre-wrap}
.fix-lbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;
         color:var(--vscode-descriptionForeground);margin:8px 0 4px}
table.diff{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
td{padding:4px 8px}
.bl{color:#dc2626;font-weight:600;width:50px}
.al{color:#16a34a;font-weight:600;width:50px}
.bc{background:#fef2f2;color:#991b1b;font-family:monospace;border-radius:3px}
.ac{background:#f0fdf4;color:#166534;font-family:monospace;border-radius:3px}
</style></head><body>
<h2>Vibeguard — ${issues.length} issue(s)</h2>
${rows||'<p>No issues.</p>'}
</body></html>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// CODE ACTION PROVIDER  (lightbulb menu)
// ─────────────────────────────────────────────────────────────────────────────

class VibeguardActions implements vscode.CodeActionProvider {
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
        `Vibeguard: Copy fix prompt — ${iss.id} (${iss.name})`,
        vscode.CodeActionKind.QuickFix
      );
      a.command = { command:'vibeguard.copyFixPrompt', title:'Copy fix prompt', arguments:[iss] };
      a.isPreferred = lineIssues.indexOf(iss) === 0;
      actions.push(a);
    }

    // "Copy ONE prompt for all issues in file" (always visible if issues exist)
    if (allIssues.length > 0) {
      const a = new vscode.CodeAction(
        `Vibeguard: Copy ONE prompt for all ${allIssues.length} issue(s) in file`,
        vscode.CodeActionKind.QuickFix
      );
      a.command = { command:'vibeguard.copyOnePrompt', title:'One prompt', arguments:[allIssues] };
      actions.push(a);
    }

    // "Explain all issues" shortcut
    if (allIssues.length > 0) {
      const a = new vscode.CodeAction(
        'Vibeguard: Open fix guidance panel',
        vscode.CodeActionKind.QuickFix
      );
      a.command = { command:'vibeguard.explainIssues', title:'Explain' };
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
  diagCollection = vscode.languages.createDiagnosticCollection('vibeguard');
  context.subscriptions.push(diagCollection);

  // Status bar
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'vibeguard.scanFile';
  context.subscriptions.push(statusBar);
  statusBar.show();
  updateBar(0, 0, false);

  // Python detection (async, non-blocking — never delays startup)
  checkPython().then(ok => {
    enhancedMode = ok;
    updateBar(0, 0, ok);
    if (ok) vscode.window.setStatusBarMessage('$(shield) Vibeguard: AST mode active ✦', 4000);
  });

  // Code action provider (lightbulb)
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      ['python','javascript','typescript','javascriptreact','typescriptreact','yaml','json'],
      new VibeguardActions(),
      { providedCodeActionKinds: VibeguardActions.kinds }
    )
  );

  // ── Commands ──────────────────────────────────────────────────────────────
  context.subscriptions.push(

    vscode.commands.registerCommand('vibeguard.scanFile', () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) scan(doc);
    }),

    vscode.commands.registerCommand('vibeguard.scanWorkspace', scanWorkspace),

    vscode.commands.registerCommand('vibeguard.clearDiagnostics', () => {
      diagCollection.clear(); lastIssues.clear(); updateBar(0,0,enhancedMode);
    }),

    // autofix: copy single-issue prompt
    vscode.commands.registerCommand('vibeguard.copyFixPrompt', async (iss: Issue) => {
      await vscode.env.clipboard.writeText(buildFixPrompt(iss));
      vscode.window.showInformationMessage(
        `Vibeguard: Fix prompt for ${iss.id} copied! Paste into ChatGPT or Claude.`
      );
    }),

    // autofix --one-prompt: combine all issues in file
    vscode.commands.registerCommand('vibeguard.copyOnePrompt', async (issues: Issue[]) => {
      await vscode.env.clipboard.writeText(buildOnePrompt(issues));
      vscode.window.showInformationMessage(
        `Vibeguard: Combined prompt for ${issues.length} issue(s) copied!`
      );
    }),

    // explain: open side panel
    vscode.commands.registerCommand('vibeguard.explainIssues', () => {
      const doc    = vscode.window.activeTextEditor?.document;
      if (!doc) return;
      const issues = lastIssues.get(doc.uri.toString()) || [];
      if (!issues.length) {
        vscode.window.showInformationMessage('Vibeguard: No issues in this file.');
        return;
      }
      showExplainPanel(context, issues);
    }),

    // copy prompt for ALL issues in workspace
    vscode.commands.registerCommand('vibeguard.copyWorkspacePrompt', async () => {
      const all: Issue[] = [];
      lastIssues.forEach(v => all.push(...v));
      if (!all.length) {
        vscode.window.showInformationMessage('Vibeguard: No issues found in workspace.');
        return;
      }
      await vscode.env.clipboard.writeText(buildOnePrompt(all));
      vscode.window.showInformationMessage(
        `Vibeguard: Workspace prompt for ${all.length} issue(s) copied!`
      );
    }),

  );

  // ── Auto-scan on save ────────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const cfg = vscode.workspace.getConfiguration('vibeguard');
      if (cfg.get('enabled') && cfg.get('scanOnSave') && supported(doc)) scan(doc);
    })
  );

  // ── Scan on type (debounced) ────────────────────────────────────────────
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument(ev => {
      const cfg = vscode.workspace.getConfiguration('vibeguard');
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
  const cfg    = vscode.workspace.getConfiguration('vibeguard');
  if (!cfg.get('enabled',true)) return;
  const strict = cfg.get<boolean>('strict',false);
  const wsDir  = vscode.workspace.getWorkspaceFolder(doc.uri)?.uri.fsPath
              || path.dirname(doc.uri.fsPath);

  statusBar.text = '$(sync~spin) Vibeguard…';

  const done = (issues: Issue[]) => {
    lastIssues.set(doc.uri.toString(), issues);
    diagCollection.set(doc.uri, todiags(issues, doc));
    recalcBar();
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
  const cfg     = vscode.workspace.getConfiguration('vibeguard');
  const strict  = cfg.get<boolean>('strict',false);
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return;
  const wsDir   = folders[0].uri.fsPath;
  statusBar.text = '$(sync~spin) Vibeguard: workspace…';

  if (enhancedMode) {
    const exe  = cfg.get<string>('vibeguardPath','vibeguard');
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
        vscode.window.showInformationMessage(`Vibeguard: ${out.scanned_files} files — ${out.summary.HIGH} HIGH · ${out.summary.MED} MED`);
      } catch { vscode.window.showWarningMessage('Vibeguard: workspace scan failed.'); }
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
    vscode.window.showInformationMessage(`Vibeguard: ${high} HIGH · ${med} MED`);
  }
}

function todiags(issues: Issue[], doc: vscode.TextDocument|null): vscode.Diagnostic[] {
  const cfg       = vscode.workspace.getConfiguration('vibeguard');
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
    d.source  = 'vibeguard';
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
    statusBar.text            = `$(error) Vibeguard${s}: ${high} HIGH`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    statusBar.tooltip         = `${high} HIGH issue(s). Click to re-scan.${enhanced?'\n⚡ AST mode':''}`;
  } else if (med>0) {
    statusBar.text            = `$(warning) Vibeguard${s}: ${med} MED`;
    statusBar.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBar.tooltip         = `${med} MED issue(s). Click to re-scan.`;
  } else {
    statusBar.text            = `$(shield) Vibeguard${s}: clean`;
    statusBar.backgroundColor = undefined;
    statusBar.tooltip         = `No issues. Click to re-scan.${enhanced?'\n⚡ AST mode':''}`;
  }
}

export function deactivate(): void {
  diagCollection?.dispose();
  statusBar?.dispose();
  if (scanTimeout) clearTimeout(scanTimeout);
}
