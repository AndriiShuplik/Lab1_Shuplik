await (async () => {
  const MARKER_ID = "#lab05-marker-target";
  const SEED_WITH_COMMENT_MARKER = "20000000-0000-0000-0000-000000000001";
  const runId = Date.now();
  const results = [];
  const check = (name, condition, details = "") => {
    results.push({ name, ok: !!condition, details: String(details) });
  };
  const markerValue = () => document.querySelector(MARKER_ID).getAttribute("data-lab05-marker");
  const resetMarker = () => document.querySelector(MARKER_ID).removeAttribute("data-lab05-marker");
  const settle = ms => new Promise(resolve => setTimeout(resolve, ms));
  const idField = document.querySelector("#incident-id");
  const getJson = async id => {
    const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
    return response.status === 200 ? response.json() : null;
  };
  const createIncident = async (title, description) => {
    const response = await fetch("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title, description, severity: "Low", occurredAtUtc: new Date().toISOString() })
    });
    return response.status === 201 ? (await response.json()).id : null;
  };
  const markerIncidentId = await createIncident(`ЛР5 DOM-тест: marker ${runId}`, "<img src=x onerror=\"document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')\">");
  check("створено запис з marker у описі", markerIncidentId);
  idField.value = markerIncidentId;
  resetMarker();
  await load();
  const stored = await getJson(markerIncidentId);
  const box = document.querySelector("#description");
  await settle(500);
  check("description: textContent дорівнює збереженому значенню", box.textContent === stored.description, `довжина ${box.textContent.length}`);
  check("description: немає дочірніх елементів", box.childElementCount === 0, `елементів ${box.childElementCount}`);
  check("description: marker не виконано", markerValue() === null, `data-lab05-marker=${markerValue()}`);
  await load();
  await load();
  check("description: повторний render лишає один вузол", box.childNodes.length === 1 && box.firstChild.nodeType === 3, `вузлів ${box.childNodes.length}`);
  resetMarker();
  idField.value = SEED_WITH_COMMENT_MARKER;
  await load();
  await settle(500);
  const seed = await getJson(SEED_WITH_COMMENT_MARKER);
  const paragraphs = [...document.querySelectorAll("#comments > p")];
  check("comments: кількість абзаців дорівнює comments[] з API", paragraphs.length === seed.comments.length, `${paragraphs.length} з ${seed.comments.length}`);
  check("comments: текст кожного абзацу дорівнює comments[].text", paragraphs.every((p, i) => p.textContent === seed.comments[i].text));
  check("comments: жоден абзац не містить елементів", paragraphs.every(p => p.childElementCount === 0));
  check("comments: marker не виконано", markerValue() === null, `data-lab05-marker=${markerValue()}`);
  await load();
  check("comments: повторний render не дублює абзаци", document.querySelectorAll("#comments > p").length === seed.comments.length);
  const samples = [
    "Користувач O'Brien написав \"терміново\"",
    "5 < 7 і 9 > 3",
    "Київ — Ω",
    "<b>жирний</b> текст",
    "А".repeat(4000)
  ];
  for (const sample of samples) {
    const id = await createIncident(`ЛР5 DOM-тест: позитивний рядок ${runId}-${samples.indexOf(sample)}`, sample);
    idField.value = id;
    await load();
    const shown = document.querySelector("#description");
    check(`позитивний рядок (${sample.length > 40 ? sample.length + " символів" : sample})`,
      shown.textContent === sample && shown.childElementCount === 0, `елементів ${shown.childElementCount}`);
  }

  const failed = results.filter(item => !item.ok);
  for (const item of results) console.log(`${item.ok ? "PASS" : "FAIL"}: ${item.name} ${item.details}`);
  console.log(failed.length === 0 ? "RESULT: PASS" : `RESULT: FAIL (${failed.length} з ${results.length})`);
  return { pass: failed.length === 0, results };
})();
