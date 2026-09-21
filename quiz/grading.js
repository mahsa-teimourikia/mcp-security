export function gradeQuiz(questions, answers) {
  if (!Array.isArray(questions) || !Array.isArray(answers)) {
    throw new TypeError("questions and answers must be arrays");
  }
  const details = questions.map((question, index) => ({
    correct: answers[index] === question.answer,
    explanation: question.explanation,
  }));
  const score = details.filter((detail) => detail.correct).length;
  return {
    score,
    total: questions.length,
    answered: answers.filter((answer) => Number.isInteger(answer)).length,
    percent: questions.length ? Math.round((score / questions.length) * 100) : 0,
    details,
  };
}
