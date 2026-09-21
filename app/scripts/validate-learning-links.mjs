import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const generated = await readFile(resolve(root, "app/generated-lessons.ts"), "utf8");
const paths = [...generated.matchAll(/"(curriculum\/[^"]+\.(?:md|py|ipynb))"/g)].map((match) => match[1]);

if (paths.length === 0) throw new Error("No generated lesson links found.");
for (const path of new Set(paths)) await access(resolve(root, path));

const lessonCount = (generated.match(/"id":/g) ?? []).length;
if (lessonCount !== 29) throw new Error(`Expected 29 lessons, found ${lessonCount}.`);
console.log(`Validated ${paths.length} lesson resources across ${lessonCount} lessons.`);
