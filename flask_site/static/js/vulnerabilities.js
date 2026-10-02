const form = document.getElementById("search-form");
const tableBody = document.getElementById("table-body");
const resultCount = document.getElementById("result-count");
const vendorSelect = document.getElementById("filter-vendor");
const yearSelect = document.getElementById("filter-year");
const pagination = document.getElementById("pagination");

const PAGE_SIZE = 50;
let allResults = [];
let currentPage = 1;

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Request failed: ${url}`);
  return res.json();
}

async function loadFilterOptions() {
  try {
    const { vendors, years } = await fetchJSON("/api/filters");
    for (const vendor of vendors) {
      const opt = document.createElement("option");
      opt.value = vendor;
      opt.textContent = vendor;
      vendorSelect.appendChild(opt);
    }
    for (const year of years) {
      const opt = document.createElement("option");
      opt.value = year;
      opt.textContent = year;
      yearSelect.appendChild(opt);
    }
  } catch (err) {
    console.error(err);
  }
}

function renderRows(rows) {
  tableBody.innerHTML = "";

  if (rows.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.className = "table-status";
    td.textContent = "검색 결과가 없습니다.";
    tr.appendChild(td);
    tableBody.appendChild(tr);
    return;
  }

  for (const row of rows) {
    const tr = document.createElement("tr");
    tr.addEventListener("click", () => {
      window.location.href = `/vulnerability/${encodeURIComponent(row.cveID)}`;
    });

    const cells = [row.cveID, row.vendorProject, row.product, row.vulnerabilityName, row.dateAdded];
    for (const value of cells) {
      const td = document.createElement("td");
      td.textContent = value || "-";
      tr.appendChild(td);
    }

    const ransomTd = document.createElement("td");
    const badge = document.createElement("span");
    const isKnown = (row.knownRansomwareCampaignUse || "").toLowerCase() === "known";
    badge.className = `badge ${isKnown ? "badge-known" : "badge-unknown"}`;
    badge.textContent = row.knownRansomwareCampaignUse || "Unknown";
    ransomTd.appendChild(badge);
    tr.appendChild(ransomTd);

    tableBody.appendChild(tr);
  }
}

function renderPagination() {
  pagination.innerHTML = "";
  const totalPages = Math.max(1, Math.ceil(allResults.length / PAGE_SIZE));
  if (totalPages <= 1) return;

  const prevBtn = document.createElement("button");
  prevBtn.textContent = "이전";
  prevBtn.disabled = currentPage <= 1;
  prevBtn.addEventListener("click", () => {
    currentPage -= 1;
    renderPage();
  });
  pagination.appendChild(prevBtn);

  const label = document.createElement("span");
  label.textContent = `${currentPage} / ${totalPages}`;
  pagination.appendChild(label);

  const nextBtn = document.createElement("button");
  nextBtn.textContent = "다음";
  nextBtn.disabled = currentPage >= totalPages;
  nextBtn.addEventListener("click", () => {
    currentPage += 1;
    renderPage();
  });
  pagination.appendChild(nextBtn);
}

function renderPage() {
  const start = (currentPage - 1) * PAGE_SIZE;
  renderRows(allResults.slice(start, start + PAGE_SIZE));
  renderPagination();
}

async function runSearch() {
  tableBody.innerHTML = '<tr><td colspan="6" class="table-status">불러오는 중...</td></tr>';
  pagination.innerHTML = "";

  const params = new URLSearchParams();
  const keyword = document.getElementById("filter-keyword").value.trim();
  const vendor = vendorSelect.value;
  const ransomware = document.getElementById("filter-ransomware").value;
  const year = yearSelect.value;

  if (keyword) params.set("keyword", keyword);
  if (vendor && vendor !== "all") params.set("vendor", vendor);
  if (ransomware && ransomware !== "all") params.set("ransomware", ransomware);
  if (year && year !== "all") params.set("year", year);

  try {
    const data = await fetchJSON(`/api/vulnerabilities?${params.toString()}`);
    resultCount.textContent = `총 ${data.count.toLocaleString()}건`;
    allResults = data.results;
    currentPage = 1;
    renderPage();
  } catch (err) {
    console.error(err);
    tableBody.innerHTML = '<tr><td colspan="6" class="table-status">데이터를 불러오지 못했습니다.</td></tr>';
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runSearch();
});

loadFilterOptions();
runSearch();
