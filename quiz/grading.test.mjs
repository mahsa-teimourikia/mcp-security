import assert from "node:assert/strict";
import test from "node:test";
import { gradeQuiz } from "./grading.js";
import { QUESTIONS } from "./questions.mjs";

test("question bank has no sparse or malformed entries", () => {
  assert.ok(QUESTIONS.length >= 18);
  for (const question of QUESTIONS) {
    assert.ok(Number.isInteger(question.course));
    assert.ok(question.course >= 1 && question.course <= 30);
    assert.equal(typeof question.text, "string");
    assert.ok(question.options.length >= 3);
    assert.ok(Number.isInteger(question.answer));
    assert.ok(question.answer >= 0 && question.answer < question.options.length);
    assert.ok(question.explanation.length > 10);
  }
  for (let course = 1; course <= 30; course += 1) {
    assert.ok(QUESTIONS.some((question) => question.course === course), `Course ${course} has no checkpoint`);
  }
});

test("grading reports correct, incorrect, and unanswered responses", () => {
  const correct = QUESTIONS.map((question) => question.answer);
  assert.deepEqual(gradeQuiz(QUESTIONS, correct), {
    score: QUESTIONS.length,
    total: QUESTIONS.length,
    answered: QUESTIONS.length,
    percent: 100,
    details: QUESTIONS.map((question) => ({ correct: true, explanation: question.explanation })),
  });
  const partial = gradeQuiz(QUESTIONS.slice(0, 2), [QUESTIONS[0].answer, null]);
  assert.equal(partial.score, 1);
  assert.equal(partial.answered, 1);
  assert.equal(partial.percent, 50);
});

test("course checkpoints grade independently from the comprehensive bank", () => {
  const checkpoint = QUESTIONS.filter((question) => question.course === 30);
  assert.ok(checkpoint.length >= 3);
  const grade = gradeQuiz(checkpoint, checkpoint.map((question) => question.answer));
  assert.equal(grade.total, checkpoint.length);
  assert.equal(grade.score, checkpoint.length);
  assert.equal(grade.percent, 100);
});
