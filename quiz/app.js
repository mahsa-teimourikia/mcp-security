import { gradeQuiz } from "./grading.js";
import { QUESTIONS } from "./questions.mjs";

const quiz = document.querySelector("#quiz");
const progress = document.querySelector("#progress");
const result = document.querySelector("#result");
const courseSelect = document.querySelector("#course-select");
const requestedCourse = Number(new URLSearchParams(window.location.search).get("course"));
const activeCourse = Number.isInteger(requestedCourse) && requestedCourse >= 1 && requestedCourse <= 30
  ? requestedCourse
  : null;

for (let course = 1; course <= 30; course += 1) {
  const option = document.createElement("option");
  option.value = String(course);
  option.textContent = `Course ${String(course).padStart(2, "0")}`;
  option.selected = course === activeCourse;
  courseSelect.append(option);
}

courseSelect.addEventListener("change", () => {
  window.location.href = courseSelect.value ? `?course=${courseSelect.value}` : "./";
});

const questions = activeCourse
  ? QUESTIONS.filter((question) => question.course === activeCourse)
  : QUESTIONS;

if (questions.length === 0) throw new Error(`No questions found for Course ${activeCourse}.`);

if (activeCourse) {
  const courseLabel = `Course ${String(activeCourse).padStart(2, "0")} Checkpoint`;
  document.title = `${courseLabel} · MCP Security`;
  document.querySelector("#quiz-title").textContent = courseLabel;
  document.querySelector("#quiz-intro").textContent =
    "Answer this course checkpoint, review every explanation, and return to the lesson for any invariant you cannot defend.";
}

document.querySelector("#question-count").textContent = `${questions.length} questions`;

quiz.innerHTML = questions.map((question, index) => `
  <fieldset class="question" data-question="${index}">
    <span class="level">${question.level}</span>
    <legend>${index + 1}. ${question.text}</legend>
    ${question.options.map((option, optionIndex) => `
      <label class="option"><input type="radio" name="q${index}" value="${optionIndex}"> ${option}</label>
    `).join("")}
    <div class="explanation" hidden></div>
  </fieldset>
`).join("");

function answers() {
  return questions.map((_, index) => {
    const selected = document.querySelector(`input[name="q${index}"]:checked`);
    return selected ? Number(selected.value) : null;
  });
}

quiz.addEventListener("change", () => {
  const answered = answers().filter(Number.isInteger).length;
  progress.textContent = `${answered} of ${questions.length} answered`;
});

document.querySelector("#grade").addEventListener("click", () => {
  const grade = gradeQuiz(questions, answers());
  grade.details.forEach((detail, index) => {
    const explanation = document.querySelector(`[data-question="${index}"] .explanation`);
    explanation.hidden = false;
    explanation.textContent = `${detail.correct ? "Correct" : "Review"} — ${detail.explanation}`;
  });
  result.hidden = false;
  result.innerHTML = `<h2>${grade.score}/${grade.total} · ${grade.percent}%</h2><p>${grade.answered === grade.total ? "All questions answered." : `${grade.total - grade.answered} unanswered question(s) counted as incorrect.`}</p>`;
  result.scrollIntoView({ behavior: "smooth" });
});

document.querySelector("#reset").addEventListener("click", () => window.location.reload());
