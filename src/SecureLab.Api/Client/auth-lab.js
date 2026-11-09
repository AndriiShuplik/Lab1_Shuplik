const result = document.querySelector("#result");
const stateLabel = document.querySelector("#state");
const profileBox = document.querySelector("#profile");
const incidentForm = document.querySelector("#incident");

const stateText = {
  anonymous: "Не ввійшли",
  active: "Сеанс активний",
  unknown: "Стан невідомий"
};

async function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) {
    throw new Error("Потрібна адреса цього застосунку.");
  }
  return fetch(url, { ...options, credentials: "same-origin" });
}

function setState(kind) {
  stateLabel.textContent = stateText[kind];
}

function clearProfile() {
  profileBox.replaceChildren();
}

function renderProfile(data) {
  clearProfile();
  const fields = [
    ["Id", data.id],
    ["Ім’я користувача", data.userName],
    ["Відображуване ім’я", data.displayName]
  ];
  for (const [label, value] of fields) {
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    detail.textContent = String(value ?? "");
    profileBox.append(term, detail);
  }
}

async function loadProfile() {
  const response = await apiFetch("/api/me");
  if (response.status === 401) {
    clearProfile();
    setState("anonymous");
    return response.status;
  }
  const type = response.headers.get("content-type") ?? "";
  if (!response.ok || !type.includes("application/json")) {
    clearProfile();
    setState("unknown");
    return response.status;
  }
  renderProfile(await response.json());
  setState("active");
  return response.status;
}

async function fieldNames(response) {
  try {
    const problem = await response.json();
    return Object.keys(problem.errors ?? {}).join(", ");
  } catch {
    return "";
  }
}

document.querySelector("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const body = JSON.stringify({
    userName: data.get("userName"),
    email: data.get("email"),
    displayName: data.get("displayName"),
    password: data.get("password")
  });
  form.elements.password.value = "";
  const response = await apiFetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });
  if (response.status === 201) {
    form.reset();
    result.textContent = "Реєстрація: 201. Тепер увійдіть.";
  } else if (response.status === 400) {
    result.textContent = `Реєстрація: 400. Поля: ${await fieldNames(response)}`;
  } else {
    result.textContent = `Реєстрація: ${response.status}`;
  }
});

document.querySelector("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const body = JSON.stringify({
    userName: form.elements.userName.value,
    password: form.elements.password.value
  });
  form.elements.password.value = "";
  const response = await apiFetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });
  result.textContent = `Login: ${response.status}`;
  if (response.status === 204) {
    await loadProfile();
  }
});

document.querySelector("#me").addEventListener("click", async () => {
  const status = await loadProfile();
  result.textContent = `GET /api/me: ${status}`;
});

document.querySelector("#logout").addEventListener("click", async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  if (response.status !== 204) {
    result.textContent = `Logout: ${response.status}`;
    return;
  }
  clearProfile();
  incidentForm.reset();
  const status = await loadProfile();
  result.textContent = `Logout: 204; GET /api/me: ${status}`;
});

incidentForm.addEventListener("submit", async event => {
  event.preventDefault();
  const data = new FormData(incidentForm);
  const body = JSON.stringify({
    title: data.get("title"),
    description: data.get("description"),
    severity: data.get("severity"),
    occurredAtUtc: new Date(data.get("occurredAt")).toISOString()
  });
  const response = await apiFetch("/api/incidents", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body
  });
  if (response.status === 201) {
    const created = await response.json();
    result.textContent = `Створено: ${created.title} (${created.severity}, ${created.status}), id ${created.id}`;
    incidentForm.reset();
  } else if (response.status === 400) {
    result.textContent = `Створення: 400. Поля: ${await fieldNames(response)}`;
  } else if (response.status === 401) {
    clearProfile();
    setState("anonymous");
    result.textContent = "Створення: 401. Потрібен вхід.";
  } else {
    result.textContent = `Створення: ${response.status}`;
  }
});

loadProfile().catch(() => setState("unknown"));