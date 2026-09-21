import { gradeQuiz } from "./grading.js";
import { QUESTIONS } from "./questions.mjs";

const quiz = document.querySelector("#quiz");
const progress = document.querySelector("#progress");
const result = document.querySelector("#result");
document.querySelector("#question-count").textContent = `${QUESTIONS.length} questions`;

quiz.innerHTML = QUESTIONS.map((question, index) => `
  <section class="question" data-question="${index}">
    <span class="level">${question.level}</span>
    <p>${index + 1}. ${question.text}</p>
    ${question.options.map((option, optionIndex) => `
      <label class="option"><input type="radio" name="q${index}" value="${optionIndex}"> ${option}</label>
    `).join("")}
    <div class="explanation" hidden></div>
  </section>
`).join("");

function answers() {
  return QUESTIONS.map((_, index) => {
    const selected = document.querySelector(`input[name="q${index}"]:checked`);
    return selected ? Number(selected.value) : null;
  });
}

quiz.addEventListener("change", () => {
  const answered = answers().filter(Number.isInteger).length;
  progress.textContent = `${answered} of ${QUESTIONS.length} answered`;
});

document.querySelector("#grade").addEventListener("click", () => {
  const grade = gradeQuiz(QUESTIONS, answers());
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
