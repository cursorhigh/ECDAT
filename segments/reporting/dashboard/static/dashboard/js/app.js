/* ECDAT dashboard JS helpers (ECharts + modal). */

function initChart(id, option) {
  if (typeof echarts === 'undefined') return null;
  const el = document.getElementById(id);
  if (!el) return null;
  const chart = echarts.init(el);
  chart.setOption(option);
  window.addEventListener('resize', () => chart.resize());
  return chart;
}

function showAssetModal(asset, extraLinked) {
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
  let html = '<table class="table"><tbody>' +
    rows.map(r => `<tr><td class="muted">${r[0]}</td><td>${r[1] ?? '—'}</td></tr>`).join('') +
    '</tbody></table>';

  const linked = extraLinked && extraLinked.length
    ? extraLinked.slice(0, 12)
    : (Array.isArray(asset.linked_findings) ? asset.linked_findings.slice(0, 12) : []);
  if (linked.length) {
    html += '<h4 class="mt-3 mb-1 text-sm font-semibold">Linked discoveries (' + linked.length + (extraLinked && extraLinked.length > 12 ? '+' : '') + ')</h4>';
    html += '<ul class="text-xs space-y-0.5">' +
      linked.map(f => `<li><a class="hover:underline" href="/graph/?asset=${encodeURIComponent(asset.id)}" title="Open in Asset Graph"><span class="text-[var(--ec-muted)]">${f.family_label || ''}</span> — <b>${f.algorithm}</b></a></li>`).join('') +
      '</ul>';
  }

  body.innerHTML = html;
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
