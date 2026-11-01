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

const quizIndex = await readFile(resolve(root, "out/quiz/index.html"), "utf8");
const quizApp = await readFile(resolve(root, "out/quiz/app.js"), "utf8");
const questionBank = await readFile(resolve(root, "out/quiz/questions.mjs"), "utf8");
if (!quizIndex.includes('id="course-select"')) throw new Error("Quiz course selector is missing.");
if (!quizApp.includes("question.course === activeCourse")) throw new Error("Quiz course filtering is missing.");
if (!quizApp.includes('<fieldset class="question"')) throw new Error("Quiz question grouping is not accessible.");
if (!questionBank.includes("course:30")) throw new Error("Course 30 checkpoint questions are missing.");
console.log("PASS: Learning Hub and quiz production output smoke test");
