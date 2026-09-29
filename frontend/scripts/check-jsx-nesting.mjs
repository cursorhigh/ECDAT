/**
 * Find invalid HTML nesting in JSX, using the TypeScript parser rather than a
 * regex.
 *
 * Two rules, both from the HTML spec and both things the browser only reports
 * *after* hydration -- by which point the page has already logged a console
 * error and may have mismatched the server HTML:
 *
 *   1. a <button> inside a <button> is invalid
 *   2. flow content (<p>, <div>, <ul>, ...) is not phrasing content, so it is
 *      invalid inside a <button>
 *
 * A hand-rolled tag regex cannot do this reliably: `onClick={() => x}` contains
 * `>`, which truncates the match. Parsing to an AST avoids the whole class of
 * problem, and typescript is already a devDependency.
 */
import ts from "typescript";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOTS = ["app", "components", "lib"];
const SKIP = new Set(["node_modules", ".next", ".git"]);

/** Flow content, which a <button> may not contain. */
const BLOCK_TAGS = new Set([
  "address", "article", "aside", "blockquote", "details", "dialog", "div", "dl",
  "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4",
  "h5", "h6", "header", "hgroup", "hr", "li", "main", "nav", "ol", "p", "pre",
  "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul"
]);

function* walkFiles(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (SKIP.has(entry)) continue;
    const full = join(dir, entry);
    const stats = statSync(full);
    if (stats.isDirectory()) yield* walkFiles(full);
    else if (entry.endsWith(".tsx")) yield full;
  }
}

function tagNameOf(node, source) {
  if (!node) return null;
  // A JsxElement has no `tagName` of its own -- the tag lives on its
  // openingElement. Only JsxSelfClosingElement carries it directly. Reading
  // `node.tagName` on a JsxElement yields undefined and silently skips the
  // element, which is exactly the element type most likely to be nested.
  const tag = ts.isJsxElement(node) ? node.openingElement?.tagName : node.tagName;
  if (!tag) return null;
  // <button>, <Foo>, <Foo.Bar> and <ns:tag> all appear here.
  return ts.isIdentifier(tag) ? tag.text : tag.getText(source);
}

function check(file, sourceText) {
  const source = ts.createSourceFile(
    file,
    sourceText,
    ts.ScriptTarget.ESNext,
    /* setParentNodes */ true,
    ts.ScriptKind.TSX
  );
  const findings = [];

  const visit = (node, buttonDepth) => {
    if (!node) return;
    let depth = buttonDepth;
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) {
      const name = tagNameOf(node, source);
      const line = source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
      if (name === "button") {
        if (buttonDepth > 0) {
          findings.push({ line, message: "<button> nested inside <button>" });
        }
        depth = buttonDepth + 1;
      } else if (buttonDepth > 0 && name && BLOCK_TAGS.has(name)) {
        findings.push({ line, message: `<${name}> is not allowed inside <button>` });
      }
    }
    // forEachChild has two callback forms: one for a single child and one for a
    // NodeArray of children. JSX children arrive through the second form, so a
    // single-argument callback silently skips every nested element.
    ts.forEachChild(
      node,
      (child) => visit(child, depth),
      (children) => {
        for (const child of children) visit(child, depth);
      }
    );
  };

  ts.forEachChild(
    source,
    (child) => visit(child, 0),
    (children) => {
      for (const child of children) visit(child, 0);
    }
  );
  return findings;
}

let scanned = 0;
const all = [];

for (const root of ROOTS) {
  for (const file of walkFiles(root)) {
    scanned += 1;
    for (const finding of check(file, readFileSync(file, "utf8"))) {
      all.push(`${relative(process.cwd(), file)}:${finding.line}  ${finding.message}`);
    }
  }
}

if (all.length) {
  console.log(`${all.length} invalid nesting issue(s) across ${scanned} file(s):`);
  for (const line of all) console.log(`  ${line}`);
  process.exit(1);
}
console.log(`No invalid button nesting or block-in-button across ${scanned} file(s).`);
