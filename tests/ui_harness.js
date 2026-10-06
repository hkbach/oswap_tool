"use strict";
// Runs websec_scanner/static/app.js against a tiny fake DOM and returns the result of an expression as JSON.
//   node ui_harness.js <path to app.js> "<expression>"   one expression, result on stdout
//   node ui_harness.js <path to app.js> --serve          one JSON line {"expression": ...} in, one JSON line out
// Each expression runs in a fresh context (a new fake DOM and a new load of app.js), so tests cannot leak state
// into each other. No dependency: just enough of `document` for app.js to load and for its rendering to run.

const fs = require("fs");
const readline = require("readline");
const vm = require("vm");

class Node {
  constructor(tag) {
    this.tag = tag;
    this.className = "";
    this.textContent = "";
    this.children = [];
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.value = "";
    this.listeners = {};
    this.attrs = {};
    this.tabIndex = 0;
    this.focused = false;
  }
  setAttribute(name, value) { this.attrs[name] = String(value); }
  getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
  get childElementCount() { return this.children.length; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  removeAttribute() {}
  focus() { this.focused = true; }
  click() {}
}

function dump(node) {
  if (node && node.text !== undefined) return { text: node.text };
  return { tag: node.tag, className: node.className, text: node.textContent, children: node.children.map(dump) };
}

function freshContext(source) {
  const byId = new Map();
  let boxes = [];
  const document = {
    getElementById(id) {
      if (!byId.has(id)) byId.set(id, new Node(`#${id}`));
      return byId.get(id);
    },
    createElement: (tag) => new Node(tag),
    createTextNode: (text) => ({ text }),
    querySelectorAll: () => boxes,
  };
  class FakeBlob {
    constructor(parts) { context.__blob = parts.join(""); }
  }
  const FakeURL = class extends URL {
    static createObjectURL() { return "blob:fake"; }
    static revokeObjectURL() {}
  };
  const context = {
    document,
    fetch: (url, options) => {
      context.__lastFetch = { url, body: options && options.body };
      return context.__fetchImpl(url, options);
    },
    __fetchImpl: () => Promise.reject(new Error("no network in this harness")),
    Blob: FakeBlob,
    URL: FakeURL,
    dump,
    __setBoxes: (list) => { boxes = list; },
    __byId: (id) => document.getElementById(id),
  };
  vm.createContext(context);
  vm.runInContext(source, context, { filename: "app.js" });
  return context;
}

async function evaluate(source, expression) {
  const result = await Promise.resolve(vm.runInContext(expression, freshContext(source)));
  return result === undefined ? null : result;
}

const source = fs.readFileSync(process.argv[2], "utf8");
if (process.argv[3] === "--serve") {
  const lines = readline.createInterface({ input: process.stdin });
  lines.on("line", async (line) => {
    let reply;
    try {
      reply = { ok: true, value: await evaluate(source, JSON.parse(line).expression) };
    } catch (error) {
      reply = { ok: false, error: String((error && error.stack) || error) };
    }
    process.stdout.write(JSON.stringify(reply) + "\n");
  });
} else {
  evaluate(source, process.argv[3]).then((value) => {
    process.stdout.write(JSON.stringify(value));
    process.exit(0);
  });
}
