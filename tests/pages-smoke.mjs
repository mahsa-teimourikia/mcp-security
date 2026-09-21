import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const required = [
  "out/index.html",
  "out/quiz/index.html",
  "out/quiz/app.js",
  "out/quiz/questions.mjs",
  "out/assets/one-plus-i.png",
];
for (const path of required) await access(resolve(root, path));

const index = await readFile(resolve(root, "out/index.html"), "utf8");
if (!index.includes("MCP Security Engineering")) throw new Error("Built Hub title is missing.");
if (!index.match(/assets\/index-[^"']+\.js/)) throw new Error("Built Hub JavaScript bundle is missing.");
console.log("PASS: Learning Hub and quiz production output smoke test");
