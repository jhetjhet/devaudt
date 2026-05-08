/**
 * analyze.mjs — Deterministic TS/JS static analysis helper
 *
 * Usage:  node analyze.mjs <repo-path>
 *
 * Outputs a single JSON object to stdout:
 * {
 *   functions:  [...],
 *   classes:    [...],
 *   imports:    [...],
 *   todos:      [...],
 *   security:   [...],
 *   dep_graph:  { "file.ts": ["dep1.ts", ...] },
 *   circular_dependencies: [["a.ts", "b.ts"], ...],
 *   errors:     [...]
 * }
 */

import { Project, SyntaxKind } from "ts-morph";
import madge from "madge";
import path from "node:path";
import fs from "node:fs";

const repoPath = process.argv[2];
if (!repoPath) {
  process.stderr.write("Usage: node analyze.mjs <repo-path>\n");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const IGNORE_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".cache",
  ".venv", "venv", "__pycache__", "coverage", ".nyc_output",
]);
const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
const TODO_RE = /\/\/\s*(?:TODO|FIXME|HACK|XXX)\b/i;

// ---------------------------------------------------------------------------
// File discovery (sorted, deterministic)
// ---------------------------------------------------------------------------
function findSourceFiles(dir) {
  const files = [];
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d).sort(); } catch { return; }
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry) || entry.startsWith(".")) continue;
      const full = path.join(d, entry);
      let stat;
      try { stat = fs.statSync(full); } catch { continue; }
      if (stat.isDirectory()) {
        walk(full);
      } else if (SOURCE_EXTS.has(path.extname(entry))) {
        files.push(full);
      }
    }
  }
  walk(dir);
  return files;
}

// ---------------------------------------------------------------------------
// Complexity estimator
// ---------------------------------------------------------------------------
function estimateComplexity(bodyText) {
  if (!bodyText) return 1;
  let c = 1;
  const patterns = [
    /\bif\s*\(/g, /\belse\s+if\s*\(/g, /\bfor\s*\(/g, /\bwhile\s*\(/g,
    /\bcase\s+/g, /\bcatch\s*\(/g, /\?\s*[^:]/g, /&&/g, /\|\|/g,
    /\?\?/g,
  ];
  for (const p of patterns) {
    const m = bodyText.match(p);
    if (m) c += m.length;
  }
  return c;
}

// ---------------------------------------------------------------------------
// AST analysis via ts-morph
// ---------------------------------------------------------------------------
async function analyzeAST(sourceFiles) {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: {
      allowJs: true,
      checkJs: false,
      strict: false,
      noEmit: true,
      skipLibCheck: true,
    },
  });

  const functions = [];
  const classes   = [];
  const imports   = [];
  const todos     = [];
  const security  = [];
  const errors    = [];

  for (const absPath of sourceFiles) {
    const relPath = path.relative(repoPath, absPath).replace(/\\/g, "/");
    let sf;
    try {
      sf = project.addSourceFileAtPath(absPath);
    } catch (e) {
      errors.push({ file: relPath, error: String(e.message) });
      continue;
    }

    // ---- imports --------------------------------------------------------
    for (const imp of sf.getImportDeclarations()) {
      imports.push({
        file: relPath,
        module: imp.getModuleSpecifierValue(),
        line: imp.getStartLineNumber(),
        names: imp.getNamedImports().map(n => n.getName()),
        default: imp.getDefaultImport()?.getText() ?? null,
      });
    }
    // Dynamic import() calls
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (call.getExpression().getKind() === SyntaxKind.ImportKeyword) {
        const args = call.getArguments();
        if (args[0]) {
          imports.push({
            file: relPath,
            module: args[0].getText().replace(/['"]/g, ""),
            line: call.getStartLineNumber(),
            names: [],
            dynamic: true,
          });
        }
      }
    }

    // ---- top-level & exported functions ---------------------------------
    for (const fn of sf.getFunctions()) {
      const s = fn.getStartLineNumber();
      const e = fn.getEndLineNumber();
      functions.push({
        file: relPath,
        name: fn.getName() ?? "<anonymous>",
        start_line: s,
        end_line: e,
        line_count: e - s + 1,
        param_count: fn.getParameters().length,
        complexity: estimateComplexity(fn.getBodyText()),
        is_method: false,
      });
    }

    // ---- arrow / variable functions -------------------------------------
    for (const vd of sf.getVariableDeclarations()) {
      const init = vd.getInitializer();
      if (!init) continue;
      const kind = init.getKind();
      if (
        kind === SyntaxKind.ArrowFunction ||
        kind === SyntaxKind.FunctionExpression
      ) {
        const s = init.getStartLineNumber();
        const e = init.getEndLineNumber();
        functions.push({
          file: relPath,
          name: vd.getName(),
          start_line: s,
          end_line: e,
          line_count: e - s + 1,
          param_count: init.getParameters?.()?.length ?? 0,
          complexity: estimateComplexity(init.getBodyText?.() ?? ""),
          is_method: false,
        });
      }
    }

    // ---- classes + methods ----------------------------------------------
    for (const cls of sf.getClasses()) {
      const cs = cls.getStartLineNumber();
      const ce = cls.getEndLineNumber();
      const methods = cls.getMethods();
      classes.push({
        file: relPath,
        name: cls.getName() ?? "<anonymous>",
        start_line: cs,
        end_line: ce,
        line_count: ce - cs + 1,
        method_count: methods.length,
      });
      for (const method of methods) {
        const ms = method.getStartLineNumber();
        const me = method.getEndLineNumber();
        functions.push({
          file: relPath,
          name: `${cls.getName() ?? "<anon>"}.${method.getName()}`,
          start_line: ms,
          end_line: me,
          line_count: me - ms + 1,
          param_count: method.getParameters().length,
          complexity: estimateComplexity(method.getBodyText()),
          is_method: true,
        });
      }
    }

    // ---- TODOs ----------------------------------------------------------
    const text = sf.getFullText();
    const lines = text.split("\n");
    lines.forEach((ln, i) => {
      if (TODO_RE.test(ln)) {
        todos.push({ file: relPath, line: i + 1, text: ln.trim() });
      }
    });

    // ---- security: eval / innerHTML / document.write -------------------
    for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expr = call.getExpression().getText();
      if (expr === "eval") {
        security.push({
          file: relPath, line: call.getStartLineNumber(),
          type: "eval_usage", severity: "high",
          description: "Direct call to eval()",
        });
      }
      if (expr === "document.write" || expr === "document.writeln") {
        security.push({
          file: relPath, line: call.getStartLineNumber(),
          type: "document_write", severity: "medium",
          description: `${expr}() — potential XSS`,
        });
      }
      if (expr === "Function") {
        security.push({
          file: relPath, line: call.getStartLineNumber(),
          type: "new_function", severity: "high",
          description: "new Function() — dynamic code execution",
        });
      }
    }
    // innerHTML / outerHTML assignment
    for (const assign of sf.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      const left = assign.getLeft().getText();
      if (
        assign.getOperatorToken().getText() === "=" &&
        (left.endsWith(".innerHTML") || left.endsWith(".outerHTML"))
      ) {
        security.push({
          file: relPath, line: assign.getStartLineNumber(),
          type: "innerHTML_assignment", severity: "medium",
          description: `${left} assignment — potential XSS`,
        });
      }
    }
  }

  return { functions, classes, imports, todos, security, errors };
}

// ---------------------------------------------------------------------------
// Dependency graph via madge
// ---------------------------------------------------------------------------
async function analyzeDeps() {
  try {
    const result = await madge(repoPath, {
      fileExtensions: ["ts", "tsx", "js", "jsx", "mjs", "cjs"],
      excludeRegExp: [
        /node_modules/, /\.git/, /dist\//, /build\//, /\.next\//,
      ],
      tsConfig: fs.existsSync(path.join(repoPath, "tsconfig.json"))
        ? path.join(repoPath, "tsconfig.json")
        : undefined,
    });
    return {
      dep_graph: result.obj(),
      circular_dependencies: result.circular(),
    };
  } catch (e) {
    return { dep_graph: {}, circular_dependencies: [], dep_error: String(e.message) };
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
const allFiles = findSourceFiles(repoPath);
const [astData, depData] = await Promise.all([
  analyzeAST(allFiles),
  analyzeDeps(),
]);

const output = {
  functions:             astData.functions,
  classes:               astData.classes,
  imports:               astData.imports,
  todos:                 astData.todos,
  security:              astData.security,
  dep_graph:             depData.dep_graph,
  circular_dependencies: depData.circular_dependencies,
  errors:                astData.errors,
};

process.stdout.write(JSON.stringify(output));
