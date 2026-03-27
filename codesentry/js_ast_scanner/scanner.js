#!/usr/bin/env node
/**
 * codesentry JS/TS AST scanner  v1.0.0
 * Uses the TypeScript compiler API (bundled with `tsc`) to parse
 * .js / .jsx / .ts / .tsx files and emit findings as a JSON array.
 *
 * Protocol (called by codesentry via subprocess):
 *   node scanner.js <filepath> [--strict]
 *   stdout : JSON array of finding objects (same shape as Python AST findings)
 *   exit 0 : success (array may be empty)
 *   exit 1 : parse / setup error  →  codesentry falls back to regex
 *
 * Requires: typescript package (ships with `tsc`).
 * Resolved at runtime via the same global that tsc lives in.
 */

"use strict";

// ─── locate TypeScript compiler API ─────────────────────────────────────────

function requireTS() {
  // 1. Inline require (works when scanner lives next to node_modules/typescript)
  try { return require("typescript"); } catch (_) {}

  // 2. Walk up from __dirname looking for node_modules/typescript
  const path = require("path");
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    try {
      return require(path.join(dir, "node_modules", "typescript"));
    } catch (_) {}
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }

  // 3. Try known global npm paths
  const candidates = [
    "/home/claude/.npm-global/lib/node_modules/typescript/lib/typescript.js",
    "/usr/local/lib/node_modules/typescript/lib/typescript.js",
    "/usr/lib/node_modules/typescript/lib/typescript.js",
  ];
  for (const c of candidates) {
    try { return require(c); } catch (_) {}
  }

  // 4. Ask `npm root -g` at runtime
  try {
    const { execSync } = require("child_process");
    const npmGlobal = execSync("npm root -g", { timeout: 3000 }).toString().trim();
    return require(require("path").join(npmGlobal, "typescript"));
  } catch (_) {}

  return null;
}

const ts = requireTS();
if (!ts) {
  process.stderr.write("TypeScript compiler API not found. Run: npm install -g typescript\n");
  process.exit(1);
}

// ─── constants ───────────────────────────────────────────────────────────────

const SECRET_KEYWORDS = new Set([
  "api_key","apikey","password","passwd","secret","token","auth_token",
  "access_token","private_key","stripe_key","sendgrid_key","twilio",
  "jwt_secret","db_password","database_password","client_secret","private",
  "credentials","credential","auth","authorization",
]);

const SAFE_CALL_NAMES = new Set([
  "getenv","get","getpass","read_secret","fetch_secret",
  "from_env","from_environment",
]);

const LOG_METHODS = new Set([
  "log","debug","info","warn","warning","error","trace","dir","group",
]);

const SENSITIVE_VAR = ["token","key","password","secret","auth","credential","passwd"];

const SQL_KW = ["SELECT","INSERT","UPDATE","DELETE","DROP","WHERE","TRUNCATE"];

const BAD_PLACEHOLDERS = [
  "your-key","your_key","replace","changeme","placeholder","example",
  "test","dummy","fake","xxxx","****","...","<your","<key","<secret",
];

const SHELL_EXEC_METHODS = new Set([
  "exec","execSync","spawn","spawnSync","execFile","execFileSync",
  "system",
]);

// ─── helpers ─────────────────────────────────────────────────────────────────

function looksLikeSecret(v) {
  if (typeof v !== "string" || v.length < 6) return false;
  const vl = v.toLowerCase();
  if (BAD_PLACEHOLDERS.some(p => vl.includes(p))) return false;
  if (v.length < 8 && /^[a-zA-Z]+$/.test(v)) return false;
  // Must have some non-alpha chars (real secrets usually do)
  if (/^[a-zA-Z\s]+$/.test(v) && v.length < 20) return false;
  return true;
}

function entropy(s) {
  if (!s || s.length < 8) return 0;
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((sum, v) => sum + (v / n) * Math.log2(v / n), 0);
}

// ─── ignore-comment parser ───────────────────────────────────────────────────

function buildIgnoreMap(lines) {
  const map = {};
  lines.forEach((line, i) => {
    const m = line.match(/codesentry-ignore(?::\s*([A-Za-z0-9_,\s]+))?/i);
    if (m) {
      const ids = m[1]
        ? new Set(m[1].split(",").map(s => s.trim().toUpperCase()))
        : new Set(["*"]);
      // Apply to the line the comment is on (inline: `code // codesentry-ignore`)
      map[i + 1] = ids;
      // Also apply to the NEXT line (standalone comment line above the code)
      map[i + 2] = ids;
    }
  });
  return map;
}

function isSuppressed(pid, lineno, ignoreMap) {
  const ids = ignoreMap[lineno] || new Set();
  return ids.has("*") || ids.has(pid.toUpperCase());
}

// ─── node text helpers ────────────────────────────────────────────────────────

function nodeText(node, src) {
  return src.slice(node.getStart(), node.getEnd());
}

function lineOf(node, sf) {
  return sf.getLineAndCharacterOfPosition(node.getStart()).line + 1; // 1-based
}

function getContext(lines, lineno) {
  const start = Math.max(0, lineno - 3);
  const end   = Math.min(lines.length, lineno + 2);
  return lines.slice(start, end).join("\n");
}

// ─── scope tracker (test-scope severity downgrade) ───────────────────────────

const TEST_NAMES = new Set([
  "test","it","describe","beforeEach","afterEach","beforeAll","afterAll",
  "setUp","tearDown",
]);

function isTestFunctionName(name) {
  if (!name) return false;
  const n = name.toLowerCase();
  return TEST_NAMES.has(name) ||
    n.startsWith("test") || n.endsWith("test") ||
    n.startsWith("spec") || n.endsWith("spec") ||
    n.includes("mock") || n.includes("stub") || n.includes("fixture");
}

function downgradeSev(base) {
  const order = ["HIGH","MED","LOW"];
  const i = order.indexOf(base);
  return i >= 0 ? order[Math.min(i + 1, 2)] : "LOW";
}

// ─── get property/variable name from a TS node ───────────────────────────────

function identifierName(node) {
  if (!node) return "";
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isStringLiteral(node)) return node.text;
  return "";
}

// ─── main scanner ────────────────────────────────────────────────────────────

function scan(filepath, source, strict) {
  const lines     = source.split("\n");
  const ignoreMap = buildIgnoreMap(lines);
  const findings  = [];

  // Determine script kind for the parser
  const isTS  = /\.tsx?$/i.test(filepath);
  const isJSX = /\.[jt]sx$/i.test(filepath);
  const scriptKind =
    isTS && isJSX ? ts.ScriptKind.TSX :
    isTS          ? ts.ScriptKind.TS  :
    isJSX         ? ts.ScriptKind.JSX :
                    ts.ScriptKind.JS;

  const sf = ts.createSourceFile(
    filepath, source, ts.ScriptTarget.Latest,
    /* setParentNodes */ true, scriptKind
  );

  // Scope stack: array of { name, isTest }
  const scopeStack = [];
  function inTest() { return scopeStack.some(s => s.isTest); }
  function sev(base) { return inTest() ? downgradeSev(base) : base; }

  const seen = new Set(); // deduplicate id:line

  function emit(pid, baseSev, name, why, lineno) {
    if (isSuppressed(pid, lineno, ignoreMap)) return;
    const key = `${pid}:${lineno}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({
      id:       pid,
      severity: sev(baseSev),
      name,
      why,
      file:     filepath,
      line:     lineno,
      context:  getContext(lines, lineno),
      via:      "ast_js",
    });
  }

  // ── helpers that need sf/src ─────────────────────────────────────────────

  function ln(node) { return lineOf(node, sf); }
  function txt(node) { return nodeText(node, source); }

  // Check if a node is a process.env access
  function isEnvAccess(node) {
    if (!ts.isPropertyAccessExpression(node) &&
        !ts.isElementAccessExpression(node)) return false;
    const obj = node.expression;
    if (!ts.isPropertyAccessExpression(obj)) return false;
    return (
      ts.isIdentifier(obj.expression) && obj.expression.text === "process" &&
      ts.isIdentifier(obj.name)       && obj.name.text === "env"
    );
  }

  // Check if a call expression is a "safe" secret retrieval
  function isSecretSafeCall(node) {
    if (!ts.isCallExpression(node)) return false;
    const callee = node.expression;
    const calleeName =
      ts.isIdentifier(callee)               ? callee.text :
      ts.isPropertyAccessExpression(callee) ? callee.name.text : "";
    return SAFE_CALL_NAMES.has(calleeName);
  }

  // Check if a node resolves to a safe value (env var, safe call)
  function isSafeValue(node) {
    if (isEnvAccess(node)) return true;
    if (isSecretSafeCall(node)) return true;
    // process.env itself
    if (ts.isPropertyAccessExpression(node) &&
        ts.isIdentifier(node.expression) && node.expression.text === "process" &&
        ts.isIdentifier(node.name) && node.name.text === "env") return true;
    return false;
  }

  // Check a name+value pair for hardcoded secrets
  function checkSecretAssign(keyName, valueNode, lineno) {
    if (!keyName) return;
    const kl = keyName.toLowerCase();
    if (![...SECRET_KEYWORDS].some(k => kl.includes(k))) return;
    if (isSafeValue(valueNode)) return;
    if (!ts.isStringLiteral(valueNode) && !ts.isNoSubstitutionTemplateLiteral(valueNode)) return;
    const v = valueNode.text;
    if (!looksLikeSecret(v)) return;
    emit("P1", "HIGH", "Hardcoded secret",
      "Ships to version control and gets scraped by bots within hours.", lineno);
  }

  // ── recursive walk ────────────────────────────────────────────────────────

  function visit(node) {
    // ── scope push ───────────────────────────────────────────────────────────
    let pushedScope = false;
    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) ||
        ts.isMethodDeclaration(node)   || ts.isArrowFunction(node)) {
      const name =
        (node.name && ts.isIdentifier(node.name)) ? node.name.text : "";
      scopeStack.push({ name, isTest: isTestFunctionName(name) });
      pushedScope = true;
    }
    // Also catch: it("should...", () => {}) — detect test runner calls
    if (ts.isCallExpression(node) &&
        ts.isIdentifier(node.expression) &&
        TEST_NAMES.has(node.expression.text)) {
      scopeStack.push({ name: node.expression.text, isTest: true });
      pushedScope = true;
    }

    // ── P1: hardcoded secrets ─────────────────────────────────────────────

    // const api_key = "sk-..."
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const name = identifierName(node.name);
      checkSecretAssign(name, node.initializer, ln(node));
    }

    // { api_key: "sk-..." }  object literal property
    if (ts.isPropertyAssignment(node)) {
      const key = identifierName(node.name);
      checkSecretAssign(key, node.initializer, ln(node));
    }

    // api_key = "sk-..."  assignment expression
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = node.left;
      const keyName =
        ts.isIdentifier(left) ? left.text :
        ts.isPropertyAccessExpression(left) ? left.name.text : "";
      if (keyName) checkSecretAssign(keyName, node.right, ln(node));
    }

    // ── P_EVAL: eval() / new Function() ──────────────────────────────────

    if (ts.isCallExpression(node)) {
      const callee = node.expression;
      // eval(nonLiteral)
      if (ts.isIdentifier(callee) && callee.text === "eval") {
        const arg = node.arguments[0];
        if (arg && !ts.isStringLiteral(arg)) {
          emit("P_EVAL", "HIGH", "eval() on dynamic input",
            "eval() on user-controlled input = remote code execution.", ln(node));
        }
      }

      // Function("code")  — dynamic function constructor
      if (ts.isIdentifier(callee) && callee.text === "Function") {
        emit("P_EVAL", "HIGH", "Function() constructor (dynamic code)",
          "new Function() / Function() constructs executable code at runtime — equivalent to eval().",
          ln(node));
      }

      // ── P_SHELL: child_process.exec/execSync with non-literal arg ────────
      if (ts.isPropertyAccessExpression(callee) &&
          SHELL_EXEC_METHODS.has(callee.name.text)) {
        const arg = node.arguments[0];
        if (arg && !ts.isStringLiteral(arg)) {
          const objTxt = txt(callee.expression);
          if (["exec","child_process","cp","shell","sh"].some(n => objTxt.includes(n)) ||
              SHELL_EXEC_METHODS.has(callee.name.text)) {
            emit("P_SHELL", "HIGH", "Shell injection risk",
              `${callee.name.text}() with dynamic argument — command injection risk. Avoid shell interpolation.`,
              ln(node));
          }
        }
      }

      // ── P4: sensitive variable in console.log / logger calls ──────────────
      if (ts.isPropertyAccessExpression(callee)) {
        const method = callee.name.text;
        const obj    = txt(callee.expression).toLowerCase();
        const isLog  = LOG_METHODS.has(method) &&
          (obj === "console" || obj.includes("log") || obj.includes("logger") || obj.includes("winston") || obj.includes("bunyan") || obj.includes("pino"));
        if (isLog) {
          for (const arg of node.arguments) {
            function checkSensitiveId(n) {
              if (ts.isIdentifier(n)) {
                if (SENSITIVE_VAR.some(s => n.text.toLowerCase().includes(s))) {
                  emit("P4", "HIGH", "Sensitive data in log",
                    "Credentials written to logs end up in monitoring tools and SIEM dashboards.", ln(node));
                }
              }
              if (ts.isPropertyAccessExpression(n)) {
                if (SENSITIVE_VAR.some(s => n.name.text.toLowerCase().includes(s))) {
                  emit("P4", "HIGH", "Sensitive data in log",
                    "Credentials written to logs end up in monitoring tools and SIEM dashboards.", ln(node));
                }
              }
              ts.forEachChild(n, checkSensitiveId);
            }
            checkSensitiveId(arg);
          }
        }
      }

      // ── P_DESER: JSON.parse on suspicious input ───────────────────────────
      if (ts.isPropertyAccessExpression(callee) &&
          ts.isIdentifier(callee.expression) && callee.expression.text === "JSON" &&
          callee.name.text === "parse") {
        const arg = node.arguments[0];
        if (arg && !ts.isStringLiteral(arg)) {
          const argTxt = txt(arg).toLowerCase();
          if (["body","input","data","req","request","payload","text","str","raw","buf"].some(k => argTxt.includes(k))) {
            emit("P_DESER", "MED", "JSON.parse on request data without error handling",
              "JSON.parse on untrusted input without try/catch crashes the process on malformed data.", ln(node));
          }
        }
      }
    }

    // ── P_EVAL: new Function() ────────────────────────────────────────────
    if (ts.isNewExpression(node) &&
        ts.isIdentifier(node.expression) && node.expression.text === "Function") {
      emit("P_EVAL", "HIGH", "new Function() (dynamic code)",
        "new Function() constructs executable code at runtime — equivalent to eval().", ln(node));
    }

    // ── P_XSS: innerHTML / outerHTML / document.write assignment ─────────
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = node.left;
      if (ts.isPropertyAccessExpression(left) || ts.isElementAccessExpression(left)) {
        const propName = ts.isPropertyAccessExpression(left) ? left.name.text : "";
        if (["innerHTML","outerHTML","document.write"].includes(propName)) {
          if (!ts.isStringLiteral(node.right)) {
            emit("P_XSS", "HIGH", "XSS via innerHTML / outerHTML",
              "Assigning user-controlled HTML to innerHTML / outerHTML enables stored and reflected XSS.", ln(node));
          }
        }
      }
    }
    // document.write(expr)
    if (ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression)) {
      const expr = node.expression;
      if (ts.isIdentifier(expr.expression) && expr.expression.text === "document" &&
          expr.name.text === "write") {
        const arg = node.arguments[0];
        if (arg && !ts.isStringLiteral(arg)) {
          emit("P_XSS", "HIGH", "XSS via document.write()",
            "document.write() with dynamic content enables XSS. Use DOM methods instead.", ln(node));
        }
      }
    }

    // ── P_SQL: template literal with SQL keyword + interpolation ──────────
    if (ts.isTemplateExpression(node)) {
      const hasInterp = node.templateSpans.length > 0;
      const rawText   = [node.head.text, ...node.templateSpans.map(s => s.literal.text)]
        .join(" ").toUpperCase();
      if (hasInterp && SQL_KW.some(kw => rawText.includes(kw))) {
        emit("P_SQL", "HIGH", "SQL injection via template literal",
          "Dynamic SQL built with template literals — SQL injection risk. Use parameterised queries.", ln(node));
      }
    }

    // ── P2 / P7: empty or silent catch blocks ─────────────────────────────
    if (ts.isCatchClause(node)) {
      const body = node.block.statements;
      if (body.length === 0) {
        emit("P2", "HIGH", "Empty catch block",
          "Exception swallowed silently — app fails with no trace.", ln(node));
      } else if (body.length === 1) {
        const stmt = body[0];
        if (ts.isReturnStatement(stmt) && !stmt.expression) {
          emit("P7", "MED", "Catch-and-return (silent)",
            "Error silently ignored with bare return — bugs vanish without a trace.", ln(node));
        }
        if (ts.isExpressionStatement(stmt) &&
            ts.isCallExpression(stmt.expression)) {
          // catch (e) { next(e) } — acceptable; skip
        }
      }
    }

    // ── P_PROTO: prototype pollution via __proto__ ────────────────────────
    if (ts.isPropertyAccessExpression(node) &&
        ts.isIdentifier(node.name) && node.name.text === "__proto__") {
      emit("P_PROTO", "HIGH", "Prototype pollution risk",
        "Accessing / assigning __proto__ can corrupt the prototype chain and enable attacks.", ln(node));
    }
    // Object.assign(target, req.body) — heuristic
    if (ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression)) {
      const callee = node.expression;
      if (ts.isIdentifier(callee.expression) && callee.expression.text === "Object" &&
          callee.name.text === "assign" && node.arguments.length >= 2) {
        const src2 = txt(node.arguments[node.arguments.length - 1]).toLowerCase();
        if (["req.body","req.query","req.params","body","query","params","input","data"]
            .some(k => src2.includes(k))) {
          emit("P_PROTO", "MED", "Prototype pollution via Object.assign",
            "Object.assign with untrusted user data can pollute the prototype chain.", ln(node));
        }
      }
    }

    // ── P_REDOS: nested quantifiers in regex literals ─────────────────────
    if (ts.isRegularExpressionLiteral(node)) {
      const raw = node.text; // e.g. /pattern/flags
      const pattern = raw.replace(/^\//, "").replace(/\/[gimsuy]*$/, "");
      if (/\([^)]*[*+{][^)]*\)[*+{]/.test(pattern)) {
        emit("P_REDOS", "MED", "Potential ReDoS (nested quantifier)",
          "Regex with nested quantifiers can take exponential time on crafted input.", ln(node));
      }
    }

    // ── P_NOVALIDATE (strict): API route handlers without validation hint ─
    if (strict && ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression)) {
      const callee = node.expression;
      const method = callee.name.text;
      if (["get","post","put","patch","delete"].includes(method)) {
        // Last argument is a handler function
        const lastArg = node.arguments[node.arguments.length - 1];
        if (lastArg && (ts.isFunctionExpression(lastArg) || ts.isArrowFunction(lastArg))) {
          const routePath = node.arguments[0];
          if (routePath && ts.isStringLiteral(routePath)) {
            emit("P_NOVALIDATE", "MED", "Route handler without validation hint",
              "API route — confirm inputs are validated. AI-generated handlers often skip this.", ln(node));
          }
        }
      }
    }

    // ── recurse ───────────────────────────────────────────────────────────
    ts.forEachChild(node, visit);

    if (pushedScope) scopeStack.pop();
  }

  visit(sf);
  return findings;
}

// ─── entry point ─────────────────────────────────────────────────────────────

const args    = process.argv.slice(2);
const strict  = args.includes("--strict");
const filepath = args.find(a => !a.startsWith("--"));

if (!filepath) {
  process.stderr.write("Usage: node scanner.js <filepath> [--strict]\n");
  process.exit(1);
}

let source;
try {
  source = require("fs").readFileSync(filepath, "utf8");
} catch (e) {
  process.stderr.write(`Cannot read file: ${e.message}\n`);
  process.exit(1);
}

try {
  const results = scan(filepath, source, strict);
  process.stdout.write(JSON.stringify(results));
  process.exit(0);
} catch (e) {
  process.stderr.write(`Scanner error: ${e.message}\n${e.stack}\n`);
  process.exit(1);
}
