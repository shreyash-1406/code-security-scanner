// Deliberately vulnerable snippets for the scanner demo.
const token = Math.random().toString(36);
function showComment(comment) {
  document.getElementById("c").innerHTML = comment;   // XSS
}
const result = eval(userInput);
const awsKey = "AKIAIOSFODNN7EXAMPLE";
