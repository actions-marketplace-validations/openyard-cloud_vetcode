// Cheap, static undoing of the tricks that hide code from pattern scanners: string literals
// split into pieces, characters written as \xNN or \uNNNN escapes, and a payload packed into
// base64 and handed to eval/exec. Nothing is run; the decoded text is only read.
//
// decoded(text) returns the same text with literals joined and escapes decoded, line for line
// (escapes that would add a line break are left alone, so line numbers still match), or null
// when there was nothing to undo. payloads(text) returns base64 blobs given to eval/exec,
// decoded, with the line they sit on.

const LIT = String.raw`(["'])((?:[^"'\\\n]|\\.)*?)\1`;
const JOIN = new RegExp(String.raw`${LIT}[ \t]*\+[ \t]*${LIT.replace(/\\1/g, "\\3")}`, "g");
const ESC = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\u\{[0-9a-fA-F]{1,6}\}/;

function unescapeLiteral(s) {
  return s.replace(/\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\u\{([0-9a-fA-F]{1,6})\}/g, (m, x, u, cp) => {
    const n = parseInt(x || u || cp, 16);
    // Only printable ASCII: hidden code is ASCII, while libraries escape Unicode on purpose
    // (bidi marks in a sanitiser, glyph tables). Line breaks stay escaped so lines still match.
    return n >= 0x20 && n <= 0x7e ? String.fromCharCode(n) : m;
  });
}

export function decoded(text) {
  if (!text.includes("+") && !ESC.test(text)) return null;
  let out = text;
  // "a" + "b" + "c" -> "abc" on the same line (twice covers the pieces each pass leaves).
  for (let pass = 0; pass < 4; pass++) {
    const next = out.replace(JOIN, (m, q1, a, q2, b) => q1 === q2 || (!a.includes(q1) && !b.includes(q1)) ? `${q1}${a}${b}${q1}` : m);
    if (next === out) break;
    out = next;
  }
  if (ESC.test(out)) out = out.replace(new RegExp(LIT, "g"), (m, q, body) => ESC.test(body) ? q + unescapeLiteral(body) + q : m);
  return out === text ? null : out;
}

// eval(Buffer.from("…", "base64").toString()), eval(atob("…")), exec(base64.b64decode("…")),
// exec(__import__("base64").b64decode("…")), exec(codecs.decode("…", "base64")).
const PACKED = /\b(?:eval|exec|Function|execSync)\s*\(\s*(?:Buffer\.from\(\s*|atob\(\s*|(?:__import__\(\s*["']base64["']\s*\)|base64)\.b64decode\(\s*|codecs\.decode\(\s*)(["'])([A-Za-z0-9+/=\s\\]{40,}?)\1/g;

export function payloads(text, depth = 0) {
  const out = [];
  for (const m of text.matchAll(PACKED)) {
    const b64 = m[2].replace(/\\n|\s/g, "");
    let body;
    try { body = Buffer.from(b64, "base64").toString("utf8"); } catch { continue; }
    // Only text that looks like code: mostly printable, not a binary blob.
    if (!body || /[\x00-\x08\x0e-\x1f]/.test(body.slice(0, 2000))) continue;
    const line = text.slice(0, m.index).split("\n").length;
    out.push({ line, text: body });
    // A payload packed twice is still one payload.
    if (depth < 2) for (const inner of payloads(body, depth + 1)) out.push({ line, text: inner.text });
  }
  return out;
}

/** The text plus its decoded view and any packed payloads, for checks that ask what a file can do. */
export function expanded(text) {
  const alt = decoded(text), packed = payloads(text);
  return alt || packed.length ? [text, alt || "", ...packed.map(p => p.text)].join("\n") : text;
}
