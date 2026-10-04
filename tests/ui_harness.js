"use strict";
// Runs websec_scanner/static/app.js against a tiny fake DOM and prints the result of one expression as JSON.
// Usage: node ui_harness.js <path to app.js> "<expression>"
// No dependency: just enough of `document` for app.js to load and for its rendering functions to run.

const fs = require("fs");
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
  }
  get childElementCount() { return this.children.length; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  removeAttribute() {}
  focus() {}
  click() {}
}

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

function dump(node) {
  if (node && node.text !== undefined) return { text: node.text };
  return { tag: node.tag, className: node.className, text: node.textContent, children: node.children.map(dump) };
}

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
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), context, { filename: "app.js" });
Promise.resolve(vm.runInContext(process.argv[3], context)).then((result) => {
  process.stdout.write(JSON.stringify(result === undefined ? null : result));
  process.exit(0);
});
