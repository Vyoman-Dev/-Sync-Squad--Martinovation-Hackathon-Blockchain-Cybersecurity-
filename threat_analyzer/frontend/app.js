const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const loader = document.getElementById('loader');
const dashboard = document.getElementById('resultsDashboard');

const scoreDisplay = document.getElementById('scoreDisplay');
const verdictBadge = document.getElementById('verdictBadge');
const fileNameDisplay = document.getElementById('fileNameDisplay');
const sha256Display = document.getElementById('sha256Display');
const fileSizeDisplay = document.getElementById('fileSizeDisplay');
const threatList = document.getElementById('threatList');
const permissionsList = document.getElementById('permissionsList');
const threatCountBadge = document.getElementById('threatCountBadge');


dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('border-emerald-500');
});

// Reset border styling when dragging away
dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('border-emerald-500');
});

// Handle dropped files
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('border-emerald-500');
  if (e.dataTransfer.files.length) {
    uploadAndAnalyze(e.dataTransfer.files[0]);
  }
});

// Handle standard file selection via file dialog
fileInput.addEventListener('change', (e) => {
  if (e.target.files.length) {
    uploadAndAnalyze(e.target.files[0]);
  }
});

async function uploadAndAnalyze(file) {
  // Client-side extension validation
  if (!file.name.endsWith('.apk')) {
    alert('Please upload a valid .apk file');
    return;
  }

  // UI state management: Show loader, hide old results
  loader.classList.remove('hidden');
  dashboard.classList.add('hidden');

  const formData = new FormData();
  formData.append('apkFile', file);

  try {
    const res = await fetch('http://localhost:5000/api/scan', {
      method: 'POST',
      body: formData
    });

    if (!res.ok) throw new Error('Analysis request failed');

    const data = await res.json();
    renderResults(data);
  } catch (err) {
    console.error(err);
    alert('Failed to connect to backend server or parse APK. Ensure the backend is active at port 5000.');
  } finally {
    loader.classList.add('hidden');
  }
}

function renderResults(data) {
  dashboard.classList.remove('hidden');

  // Populate basic metadata
  fileNameDisplay.innerText = data.fileName;
  fileSizeDisplay.innerText = data.fileSize;
  sha256Display.innerText = data.meta.sha256;
  scoreDisplay.innerText = data.riskScore;

  // Render Verdict badge and score colors based on severity
  verdictBadge.innerText = data.verdict;
  if (data.verdict === 'Malicious') {
    verdictBadge.className = 'px-3 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-rose-950 text-rose-400 border border-rose-800';
    scoreDisplay.className = 'text-5xl font-extrabold my-2 text-rose-400';
  } else if (data.verdict === 'Suspicious') {
    verdictBadge.className = 'px-3 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-amber-950 text-amber-400 border border-amber-800';
    scoreDisplay.className = 'text-5xl font-extrabold my-2 text-amber-400';
  } else {
    verdictBadge.className = 'px-3 py-0.5 rounded text-xs font-bold uppercase tracking-wider bg-emerald-950 text-emerald-400 border border-emerald-800';
    scoreDisplay.className = 'text-5xl font-extrabold my-2 text-emerald-400';
  }

  // Render Detected Threats list
  threatCountBadge.innerText = `${data.threats.length} Threats`;
  threatList.innerHTML = '';

  if (data.threats.length === 0) {
    threatList.innerHTML = `
      <div class="p-4 bg-emerald-950/20 border border-emerald-900 rounded-lg text-emerald-400 text-sm">
        <i class="fa-solid fa-check-circle mr-2"></i> No high-risk behavioral indicators or dangerous permissions detected.
      </div>`;
  } else {
    data.threats.forEach(t => {
      const card = document.createElement('div');
      card.className = 'p-4 rounded-lg bg-slate-900 border border-slate-800 flex flex-col gap-1.5';

      let sevClass = 'bg-amber-950 text-amber-300 border-amber-800';
      if (t.severity === 'Critical') sevClass = 'bg-rose-950 text-rose-300 border-rose-800';

      card.innerHTML = `
        <div class="flex items-center justify-between">
          <div class="font-bold text-slate-200 text-sm">${t.title}</div>
          <span class="text-xs px-2 py-0.5 rounded border font-semibold ${sevClass}">${t.severity} (+${t.scoreImpact})</span>
        </div>
        <div class="text-xs font-mono text-indigo-400 font-semibold tracking-wide">Type: ${t.category}</div>
        <p class="text-xs text-slate-400">${t.detail}</p>
      `;
      threatList.appendChild(card);
    });
  }
// Render Permissions list
  permissionsList.innerHTML = '';
  if (data.permissions.length === 0) {
    permissionsList.innerHTML = `<span class="text-xs text-slate-500">No permissions declared.</span>`;
  } else {
    data.permissions.forEach(p => {
      const pill = document.createElement('span');
      pill.className = 'px-2.5 py-1 text-xs font-mono rounded bg-slate-800 border border-slate-700 text-slate-300';
      pill.innerText = p;
      permissionsList.appendChild(pill);
    });
  }
}