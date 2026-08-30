/* ECDAT dashboard JS helpers (ECharts + modal). */

function initChart(id, option) {
  const el = document.getElementById(id);
  if (!el) return null;
  const chart = echarts.init(el);
  chart.setOption(option);
  window.addEventListener('resize', () => chart.resize());
  return chart;
}

function showAssetModal(asset) {
  const body = document.getElementById('modal-body');
  if (!body || !asset) return;
  const rows = [
    ['Name', asset.name],
    ['Family', asset.family_display || asset.family],
    ['Algorithm', asset.algorithm || '—'],
    ['Key size', asset.key_size ?? '—'],
    ['Curve', asset.curve || '—'],
    ['Protocol', asset.protocol || '—'],
    ['Library', (asset.library || '—') + (asset.library_version ? ' ' + asset.library_version : '')],
    ['Source', asset.source_type],
    ['Location', asset.location || '—'],
    ['Owner', asset.owner || '—'],
    ['Status', asset.inventory_status_display || asset.inventory_status],
  ];
  body.innerHTML = '<table class="table"><tbody>' +
    rows.map(r => `<tr><td class="muted">${r[0]}</td><td>${r[1] ?? '—'}</td></tr>`).join('') +
    '</tbody></table>';
  const line = document.createElement('div');
  line.className = 'mt-3 text-sm';
  line.innerHTML = '<a class="text-ecdat-primary hover:underline font-semibold" href="/graph/?asset=' +
    encodeURIComponent(asset.id) + '">Open in Asset Graph</a>';
  body.appendChild(line);
  document.getElementById('modal-backdrop').hidden = false;
}

function closeModal() {
  document.getElementById('modal-backdrop').hidden = true;
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});
document.getElementById('modal-backdrop')?.addEventListener('click', (e) => {
  if (e.target.id === 'modal-backdrop') closeModal();
});

async function fetchAsset(id) {
  const r = await fetch(`/api/assets/${id}/`);
  return r.ok ? r.json() : null;
}

function getCsrf() {
  const m = document.cookie.match(/csrftoken=([^; ]+)/);
  return m ? m[1] : '';
}
