import { useEffect, useMemo, useState } from "react";
import { lessons, type Lesson, type Level } from "./generated-lessons";

const REPO = "https://github.com/mahsa-teimourikia/mcp-security";
const levels: Array<"All" | Level> = ["All", "Beginner", "Intermediate", "Advanced"];

function sourceUrl(path: string) {
  return `${REPO}/blob/main/${path}`;
}

export function App() {
  const [level, setLevel] = useState<(typeof levels)[number]>("All");
  const [selected, setSelected] = useState<Lesson>(lessons[0]);
  const [completed, setCompleted] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem("mcp-security-progress") ?? "[]");
    } catch {
      return [];
    }
  });

  useEffect(() => {
    localStorage.setItem("mcp-security-progress", JSON.stringify(completed));
  }, [completed]);

  const visible = useMemo(
    () => lessons.filter((lesson) => level === "All" || lesson.level === level),
    [level],
  );

  const toggleComplete = () => {
    setCompleted((current) =>
      current.includes(selected.id)
        ? current.filter((id) => id !== selected.id)
        : [...current, selected.id],
    );
  };

  return (
    <>
      <header className="hero">
        <nav className="topbar" aria-label="Primary navigation">
          <a className="brand" href="https://oneplusi.io">One+i / Field Guide</a>
          <div>
            <a href={`${REPO}/blob/main/LEARNING.md`}>Learning guide</a>
            <a href="quiz/">Knowledge check</a>
            <a className="repo" href={REPO}>GitHub ↗</a>
          </div>
        </nav>
        <div className="hero-grid">
          <div>
            <p className="eyebrow">Notebook-first · defensive · production-minded</p>
            <h1>MCP Security<br /><em>Engineering</em></h1>
            <p className="lede">Secure the servers, tools, resources, prompts, identities, dependencies, and protocols that agentic systems trust.</p>
            <a className="button" href="#curriculum">Explore {lessons.length} lessons</a>
          </div>
          <div className="boundary" aria-label="Security responsibility boundary">
            <span>UNTRUSTED INPUT</span>
            <strong>Model / agent</strong>
            <p>proposes · predicts · extracts · recommends</p>
            <i>↓</i>
            <span>ENFORCEMENT BOUNDARY</span>
            <strong>Trusted application</strong>
            <p>validates · authorizes · executes · verifies · records</p>
          </div>
        </div>
      </header>

      <main>
        <section className="principles" aria-label="Course principles">
          <div><b>01</b><span>Authority stays in deterministic application code.</span></div>
          <div><b>02</b><span>Every normal path has an adversarial counterpart.</span></div>
          <div><b>03</b><span>Evidence includes decisions, traces, tests, and recovery.</span></div>
        </section>

        <section id="curriculum" className="curriculum">
          <div className="section-heading">
            <div><p className="eyebrow">Curriculum</p><h2>Learn by boundary,<br />failure, and proof.</h2></div>
            <p>Start with protocol mechanics, progress through identity and isolation, then design enterprise detection, governance, and recovery.</p>
          </div>

          <div className="filters" role="group" aria-label="Filter lessons by level">
            {levels.map((item) => (
              <button key={item} className={level === item ? "active" : ""} onClick={() => setLevel(item)}>
                {item} <span>{item === "All" ? lessons.length : lessons.filter((lesson) => lesson.level === item).length}</span>
              </button>
            ))}
          </div>

          <div className="lesson-grid">
            {visible.map((lesson) => (
              <button
                className={`lesson-card ${selected.id === lesson.id ? "selected" : ""}`}
                key={lesson.id}
                onClick={() => setSelected(lesson)}
                aria-pressed={selected.id === lesson.id}
              >
                <span className={`pill ${lesson.level.toLowerCase()}`}>{lesson.level}</span>
                <span className="number">{lesson.step}</span>
                <h3>{lesson.title}{completed.includes(lesson.id) ? <small> ✓</small> : null}</h3>
                <p>{lesson.summary}</p>
              </button>
            ))}
          </div>
        </section>

        <section className="workspace" aria-live="polite">
          <div>
            <p className="eyebrow">{selected.level} · Course {selected.step}</p>
            <h2>{selected.title}</h2>
            <p className="workspace-copy">{selected.summary}</p>
            <button className="complete" onClick={toggleComplete}>
              {completed.includes(selected.id) ? "Mark as incomplete" : "Mark lesson complete"}
            </button>
            <p className="progress">{completed.length} of {lessons.length} lessons completed on this device</p>
          </div>
          <div className="resources">
            <h3>Study this lesson</h3>
            <a href={sourceUrl(selected.readme)}><b>01</b><span>Read the chapter<small>Theory, architecture, failures, and production guidance</small></span></a>
            <a href={sourceUrl(selected.lab)}><b>02</b><span>Run the lab<small>Credential-free reusable implementation</small></span></a>
            <a href={sourceUrl(selected.notebook)}><b>03</b><span>Open the notebook<small>Guided execution, failure injection, and reflection</small></span></a>
            <a href="quiz/"><b>04</b><span>Take the checkpoint<small>Architecture judgment and failure analysis</small></span></a>
          </div>
        </section>

        <section className="cta">
          <p className="eyebrow">Ready to verify your understanding?</p>
          <h2>From discovered capability<br />to defensible evidence.</h2>
          <a className="button dark" href="quiz/">Take the knowledge check</a>
        </section>
      </main>

      <footer>
        <span>MCP Security Engineering</span>
        <span>Learning with <a href="https://oneplusi.io">One+i</a></span>
      </footer>
    </>
  );
}
