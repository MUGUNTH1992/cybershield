const byId = (id) => document.getElementById(id);
const urlForm = byId('url-form');

urlForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = urlForm.querySelector('button[type="submit"]');
  button.disabled = true;
  const resultBox = byId('url-result');
  resultBox.hidden = false;
  resultBox.className = 'result loading';
  resultBox.textContent = 'Checking URL structure…';
  try {
    const response = await fetch('/api/analyze-url', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: byId('url-input').value})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Unable to analyze this URL.');
    resultBox.className = `result ${data.classification}`;
    resultBox.replaceChildren();
    const title = document.createElement('strong');
    title.textContent = `${data.label} · ${data.score}/10`; resultBox.append(title);
    const list = document.createElement('ul');
    data.reasons.forEach((reason) => { const li = document.createElement('li'); li.textContent = reason; list.append(li); });
    resultBox.append(list);
    await refreshDashboard();
  } catch (error) {
    resultBox.className = 'result error'; resultBox.textContent = error.message;
  } finally { button.disabled = false; }
});

async function refreshDashboard() {
  const response = await fetch('/api/dashboard');
  const data = await response.json();
  byId('total-scans').textContent = data.total_scans;
  byId('safe-urls').textContent = data.safe_urls;
  byId('suspicious-urls').textContent = data.suspicious_urls;
  byId('password-assessments').textContent = data.password_assessments;
}

const password = byId('password-input');
let passwordCounted = false;
function assessPassword() {
  const value = password.value;
  const checks = {
    length: value.length >= 12, upper: /[A-Z]/.test(value),
    lower: /[a-z]/.test(value), number: /\d/.test(value), special: /[^A-Za-z0-9]/.test(value)
  };
  let score = Object.values(checks).filter(Boolean).length;
  if (value.length >= 16) score = Math.min(5, score + 1);
  document.querySelectorAll('.criteria li').forEach((item) => item.classList.toggle('checked', checks[item.dataset.check]));
  byId('strength-score').textContent = `${score} / 5`;
  byId('meter-fill').style.width = `${score * 20}%`;
  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
  byId('strength-label').textContent = value ? labels[score] : 'Enter a sample to begin';
  byId('meter-fill').dataset.score = score;
  const suggestions = [];
  if (value.length < 12) suggestions.push('make it at least 12 characters');
  if (!checks.upper || !checks.lower) suggestions.push('mix uppercase and lowercase letters');
  if (!checks.number) suggestions.push('add a number');
  if (!checks.special) suggestions.push('add a special character');
  byId('password-tip').textContent = value && suggestions.length ? `Try to ${suggestions.join(', ')}.` : 'Great baseline. Keep it unique and consider using a passphrase.';
  if (value && !passwordCounted) {
    passwordCounted = true;
    // Deliberately send an empty request: the password is never transmitted.
    fetch('/api/password-assessment', {method: 'POST'}).then(refreshDashboard).catch(() => {});
  }
  if (!value) passwordCounted = false;
}
password.addEventListener('input', assessPassword);
byId('toggle-password').addEventListener('click', () => {
  const visible = password.type === 'password'; password.type = visible ? 'text' : 'password';
  byId('toggle-password').setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
});
