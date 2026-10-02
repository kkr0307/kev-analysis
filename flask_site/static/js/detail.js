function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function infoRow(label, value) {
  const row = el("div", "info-row");
  row.appendChild(el("span", "label", label));
  row.appendChild(el("span", "value", value || "-"));
  return row;
}

function renderDetail(root, data) {
  root.innerHTML = "";

  const header = el("div", "detail-header");
  header.appendChild(el("h1", null, data.cveID));
  header.appendChild(el("p", null, data.vulnerabilityName || ""));
  root.appendChild(header);

  const grid = el("div", "detail-grid");

  const infoCard = el("div", "info-card");
  infoCard.appendChild(el("h2", null, "기본 정보"));
  infoCard.appendChild(infoRow("벤더", data.vendorProject));
  infoCard.appendChild(infoRow("제품", data.product));
  infoCard.appendChild(infoRow("취약점 이름", data.vulnerabilityName));
  infoCard.appendChild(infoRow("KEV 등록일", data.dateAdded));
  infoCard.appendChild(infoRow("대응 기한", data.dueDate));
  infoCard.appendChild(infoRow("대응 기간", data.responseDays !== null ? `${data.responseDays}일` : "-"));

  const isKnown = (data.knownRansomwareCampaignUse || "").toLowerCase() === "known";
  const ransomValue = el("span", `badge ${isKnown ? "badge-known" : "badge-unknown"}`, data.knownRansomwareCampaignUse || "Unknown");
  const ransomRow = el("div", "info-row");
  ransomRow.appendChild(el("span", "label", "랜섬웨어 연관 여부"));
  ransomRow.appendChild(ransomValue);
  infoCard.appendChild(ransomRow);

  grid.appendChild(infoCard);

  const cweCard = el("div", "info-card");
  cweCard.appendChild(el("h2", null, "CWE"));
  const tagWrap = el("div", "cwe-tags");
  if (data.cwes && data.cwes.length > 0) {
    for (const cwe of data.cwes) {
      tagWrap.appendChild(el("span", "cwe-tag", cwe));
    }
  } else {
    tagWrap.appendChild(el("span", "cwe-tag", "정보 없음"));
  }
  cweCard.appendChild(tagWrap);
  grid.appendChild(cweCard);

  root.appendChild(grid);

  const descCard = el("div", "text-card");
  descCard.appendChild(el("h2", null, "취약점 설명"));
  descCard.appendChild(el("p", null, data.shortDescription || "설명이 없습니다."));
  root.appendChild(descCard);

  const actionCard = el("div", "text-card");
  actionCard.appendChild(el("h2", null, "권고 조치"));
  actionCard.appendChild(el("p", null, data.requiredAction || "권고 조치 정보가 없습니다."));
  root.appendChild(actionCard);

  const notesCard = el("div", "text-card");
  notesCard.appendChild(el("h2", null, "참고자료"));
  notesCard.appendChild(el("p", null, data.notes || "참고자료가 없습니다."));
  root.appendChild(notesCard);
}

async function loadDetail() {
  const root = document.getElementById("detail-root");
  const cveId = root.dataset.cveId;

  try {
    const res = await fetch(`/api/vulnerabilities/${encodeURIComponent(cveId)}`);
    if (!res.ok) {
      root.innerHTML = "";
      root.appendChild(el("div", "table-status", "해당 CVE 정보를 찾을 수 없습니다."));
      return;
    }
    const data = await res.json();
    renderDetail(root, data);
  } catch (err) {
    console.error(err);
    root.innerHTML = "";
    root.appendChild(el("div", "table-status", "데이터를 불러오지 못했습니다."));
  }
}

loadDetail();
