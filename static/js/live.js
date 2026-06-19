// NEXUS INTEL — Live Detection — Real GPS Location Only
const vid         = document.getElementById('vid');
const overlay     = document.getElementById('overlay');
const ctx         = overlay.getContext('2d');
const btnStart    = document.getElementById('btnStart');
const btnStop     = document.getElementById('btnStop');
const btnSnap     = document.getElementById('btnSnap');
const autoScan    = document.getElementById('autoScan');
const statusBadge = document.getElementById('statusBadge');
const resultsBox  = document.getElementById('results');
const savedList   = document.getElementById('savedList');
const locTxt      = document.getElementById('locTxt');

let stream = null, scanTimer = null, busy = false;
let lastAlertAt = 0, lastAlertName = '';

// Real GPS coords — null until browser grants permission
let geo = { lat: null, lon: null, city: null, address: null };

// ── GPS: demand real browser location, no fakes ───────────────────────────
function onGPSSuccess(pos) {
  const lat = pos.coords.latitude;
  const lon = pos.coords.longitude;
  geo.lat = lat;
  geo.lon = lon;

  // Show raw coords immediately
  locTxt.innerHTML = `<span style="color:#00e676">📡 GPS Locked</span>
    <span style="font-family:'Share Tech Mono',monospace;color:var(--cyan)">
      ${lat.toFixed(6)}, ${lon.toFixed(6)}
    </span>
    <span style="color:var(--muted2);font-size:.68rem"> ±${Math.round(pos.coords.accuracy||0)}m</span>`;

  // Reverse-geocode to get real street name (Nominatim via our proxy)
  fetch(`/api/reverse_geocode?lat=${lat}&lon=${lon}`)
    .then(r => r.json())
    .then(j => {
      geo.city    = j.city    || `${lat.toFixed(3)},${lon.toFixed(3)}`;
      geo.address = j.address || geo.city;
      locTxt.innerHTML = `<span style="color:#00e676">📡 GPS</span>
        <span style="color:#e2e8f0"> ${geo.address}</span>
        <span style="font-family:'Share Tech Mono',monospace;color:var(--muted2);font-size:.68rem">
          (${lat.toFixed(5)}, ${lon.toFixed(5)})
        </span>`;
    })
    .catch(() => {
      geo.city    = `${lat.toFixed(4)},${lon.toFixed(4)}`;
      geo.address = geo.city;
    });
}

function onGPSError(err) {
  const msgs = {
    1: 'Location permission DENIED. Click the 🔒 lock icon in your browser address bar → allow Location → reload.',
    2: 'Location unavailable. Make sure GPS/location services are enabled on your device.',
    3: 'Location request timed out. Check your GPS signal and reload.'
  };
  locTxt.innerHTML = `<span style="color:#ff5252">⚠ ${msgs[err.code] || 'GPS error: ' + err.message}</span>`;
  geo.lat = null; geo.lon = null;

  // Show a prominent warning banner
  const warn = document.getElementById('gpsWarning');
  if (warn) {
    warn.style.display = 'block';
    warn.innerHTML = `<strong>⚠ Location Permission Required</strong><br>
      ${msgs[err.code] || err.message}<br>
      <small>Without GPS, detections will not have accurate location data on the map.</small>`;
  }
}

if (!navigator.geolocation) {
  locTxt.innerHTML = '<span style="color:#ff5252">⚠ This browser does not support GPS location</span>';
} else {
  locTxt.innerHTML = '<span style="color:var(--amber)">📡 Requesting GPS permission…</span>';

  // Get current position
  navigator.geolocation.getCurrentPosition(onGPSSuccess, onGPSError, {
    enableHighAccuracy: true,
    timeout: 15000,
    maximumAge: 0
  });

  // Watch for updates — fires every time position changes
  navigator.geolocation.watchPosition(onGPSSuccess, onGPSError, {
    enableHighAccuracy: true,
    timeout: 15000,
    maximumAge: 0        // always fresh, never cached
  });
}

// ── Camera ────────────────────────────────────────────────────────────────
async function start() {
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { width: 640, height: 480, facingMode: 'user' }, audio: false
    });
    vid.srcObject = stream;
    await vid.play();
    overlay.width  = vid.videoWidth;
    overlay.height = vid.videoHeight;
    btnStart.disabled = true;
    btnStop.disabled  = false;
    btnSnap.disabled  = false;
    statusBadge.textContent = 'LIVE';
    statusBadge.style.cssText = 'background:rgba(0,230,118,.15);color:#00e676;border:1px solid rgba(0,230,118,.4);border-radius:20px;padding:3px 10px;font-size:.72rem;font-weight:700;letter-spacing:1px';
  } catch(e) { alert('Camera error: ' + e.message); }
}

function stop() {
  if (scanTimer) { clearInterval(scanTimer); scanTimer = null; autoScan.checked = false; }
  if (stream)    { stream.getTracks().forEach(t => t.stop()); stream = null; }
  btnStart.disabled = false;
  btnStop.disabled  = true;
  btnSnap.disabled  = true;
  statusBadge.textContent = 'IDLE';
  statusBadge.style.cssText = 'background:rgba(100,116,139,.15);color:#94a3b8;border:1px solid rgba(100,116,139,.3);border-radius:20px;padding:3px 10px;font-size:.72rem;font-weight:700;letter-spacing:1px';
  ctx.clearRect(0, 0, overlay.width, overlay.height);
}

function frameJPEG() {
  const c = document.createElement('canvas');
  c.width = vid.videoWidth; c.height = vid.videoHeight;
  c.getContext('2d').drawImage(vid, 0, 0);
  return c.toDataURL('image/jpeg', 0.85);
}

// ── Canvas overlays ───────────────────────────────────────────────────────
function drawBoxes(results) {
  ctx.clearRect(0, 0, overlay.width, overlay.height);
  results.forEach(r => {
    const [l, t, rt, b] = r.box;
    const known = r.name !== 'UNKNOWN PERSON';
    const conf  = r.confidence || 0;
    const prio  = r.priority;
    const sc    = prio ? '#ff0000' : (known ? '#ff1744' : '#ffd740');
    const fc    = prio ? 'rgba(255,0,0,.78)' : (known ? 'rgba(255,23,68,.78)' : 'rgba(255,215,64,.78)');

    ctx.lineWidth = prio ? 4 : 3;
    ctx.strokeStyle = sc;
    ctx.strokeRect(l, t, rt-l, b-t);

    const cs = 14;
    ctx.lineWidth = 3;
    [[l,t,1,1],[rt,t,-1,1],[l,b,1,-1],[rt,b,-1,-1]].forEach(([x,y,dx,dy]) => {
      ctx.beginPath(); ctx.moveTo(x, y+dy*cs); ctx.lineTo(x,y); ctx.lineTo(x+dx*cs, y); ctx.stroke();
    });

    const label = known ? (conf >= 50 ? `${r.name}  ${conf.toFixed(0)}%` : r.name) : 'UNKNOWN PERSON';
    ctx.font = 'bold 14px "Exo 2", sans-serif';
    const tw = ctx.measureText(label).width + 14, th = 22;
    ctx.fillStyle = fc;   ctx.fillRect(l, t-th-2, tw, th);
    ctx.fillStyle = '#fff'; ctx.fillText(label, l+7, t-7);

    if (known && conf >= 50) {
      const bw = rt - l;
      ctx.fillStyle = 'rgba(0,0,0,.5)'; ctx.fillRect(l, b+2, bw, 7);
      ctx.fillStyle = conf>=80?'#00e676':conf>=60?'#00e5ff':'#ffd740';
      ctx.fillRect(l, b+2, bw*(conf/100), 7);
    }
  });
}

// ── Results panel ─────────────────────────────────────────────────────────
function renderResults(results, savedMap) {
  if (!results.length) {
    resultsBox.innerHTML = '<div style="color:var(--muted2);font-size:.85rem;text-align:center;padding:20px">No faces in frame</div>';
    return;
  }

  const hasGPS = geo.lat !== null;
  const locLine = hasGPS
    ? `<div style="font-size:.7rem;color:#00e676;margin-top:4px">
         📡 <b>GPS</b>: ${geo.address || geo.city}
         <span style="color:var(--muted2)">(${geo.lat.toFixed(5)}, ${geo.lon.toFixed(5)})</span>
       </div>`
    : `<div style="font-size:.7rem;color:#ff9800;margin-top:4px">
         ⚠ No GPS — allow location permission for accurate map pinpoint
       </div>`;

  resultsBox.innerHTML = results.map(r => {
    const known = r.name !== 'UNKNOWN PERSON';
    const conf  = r.confidence || 0;
    const grade = conf>=80?'high':conf>=60?'medium':conf>=40?'low':'unknown';
    const saved = savedMap && savedMap[r.name];

    const confBar = known && conf >= 50
      ? `<div class="conf-bar-wrap mt-1">
           <div class="conf-bar-label"><span>Match</span><span>${conf.toFixed(1)}%</span></div>
           <div class="conf-bar-track" style="height:5px">
             <div class="conf-bar-fill conf-${grade}" style="width:${conf}%;height:5px"></div>
           </div>
         </div>`
      : (known ? `<div style="color:var(--red2);font-size:.72rem;margin-top:3px">⚠ Low confidence</div>` : '');

    const mapBtn = saved
      ? `<a href="/map?uid=${saved.uid}" target="_blank"
           style="background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.35);
           border-radius:7px;color:#00e5ff;padding:3px 9px;font-size:.72rem;
           font-weight:700;text-decoration:none">🗺 On Map</a>` : '';

    const detailBtn = known && r.criminal_id
      ? `<button onclick="showCriminalDetails(${r.criminal_id},'${encodeURIComponent(saved?.path||'')}',${conf.toFixed(1)})"
           style="background:rgba(255,23,68,.1);border:1px solid rgba(255,23,68,.35);
           border-radius:7px;color:#ff5252;padding:3px 9px;font-size:.72rem;
           font-weight:700;cursor:pointer">👤 Details</button>` : '';

    return `<div class="result-row ${known?'hit':'unknown'}" style="margin-bottom:8px">
      <div class="d-flex justify-content-between align-items-center">
        <b style="color:${known?'#ff5252':'#ffd740'}">${r.name}</b>
        ${known&&conf>=50?`<span class="loc-badge ${grade}">${conf.toFixed(1)}%</span>`:''}
      </div>
      ${r.crime_type&&known?`<div style="font-size:.75rem;color:var(--muted2)">⚠ ${r.crime_type}</div>`:''}
      ${r.status&&known?`<div style="font-size:.75rem;color:var(--muted2)">Status: ${r.status}</div>`:''}
      ${confBar}
      ${locLine}
      <div style="display:flex;gap:5px;margin-top:5px">${mapBtn}${detailBtn}</div>
    </div>`;
  }).join('');
}

// ── Criminal detail modal ─────────────────────────────────────────────────
function showCriminalDetails(cid, snapPath, conf) {
  const modal = document.getElementById('crimDetailModal');
  const body  = document.getElementById('crimDetailBody');
  body.innerHTML = '<div style="text-align:center;padding:30px;color:var(--muted2)">Loading…</div>';
  modal.style.display = 'flex';

  fetch(`/api/criminal/${cid}`)
    .then(r => r.json())
    .then(c => {
      const snap  = snapPath ? decodeURIComponent(snapPath) : c.mugshot;
      const ts    = c.threat_score || 0;
      const tcol  = ts>=8?'#ff1744':ts>=5?'#ff6d00':ts>=2?'#ffd740':'#64748b';
      const grade = conf>=80?'high':conf>=60?'medium':conf>=40?'low':'unknown';

      const snapImg = snap
        ? `<img src="/file/by_rel?p=${encodeURIComponent(snap)}"
              style="width:100%;max-height:200px;object-fit:cover;border-radius:10px;
                     margin-bottom:12px;border:2px solid rgba(255,23,68,.5)"
              onerror="this.style.display='none'">`
        : `<div style="height:70px;display:flex;align-items:center;justify-content:center;font-size:40px;margin-bottom:12px">👤</div>`;

      const detRows = (c.detections||[]).slice(0,5).map(d =>
        `<tr>
          <td style="font-family:monospace;font-size:.68rem;color:var(--muted2);padding:3px 8px 3px 0">
            🕐 ${d.timestamp?.slice(0,16)||'—'}
          </td>
          <td style="font-size:.7rem;color:var(--cyan)">📍 ${d.city||'—'}</td>
          <td style="font-size:.7rem">${d.confidence?d.confidence.toFixed(0)+'%':'—'}</td>
        </tr>`).join('');

      // Current GPS location at time of detection
      const curLoc = geo.lat
        ? `<div style="background:rgba(0,230,118,.08);border:1px solid rgba(0,230,118,.3);
              border-radius:8px;padding:8px;margin-bottom:10px">
             <div style="font-size:.62rem;color:var(--muted2);text-transform:uppercase;letter-spacing:1px">Detection Location (GPS)</div>
             <div style="color:#00e676;font-size:.82rem">📍 ${geo.address||geo.city}</div>
             <div style="font-family:monospace;font-size:.7rem;color:var(--muted2)">${geo.lat.toFixed(6)}, ${geo.lon.toFixed(6)}</div>
           </div>`
        : `<div style="background:rgba(255,148,0,.08);border:1px solid rgba(255,148,0,.3);
              border-radius:8px;padding:8px;margin-bottom:10px">
             <div style="color:#ff9800;font-size:.78rem">⚠ GPS not available — allow location permission</div>
           </div>`;

      body.innerHTML = `
        ${snapImg}
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px">
          <span style="font-size:1.2rem;font-weight:800;color:#ff5252;font-family:'Orbitron',monospace">${c.name}</span>
          <span style="background:rgba(255,23,68,.18);border:1px solid rgba(255,23,68,.4);
            border-radius:20px;color:#ff5252;font-size:.68rem;font-weight:700;padding:2px 8px">${c.status||'Wanted'}</span>
          <span class="loc-badge ${grade}">${conf}% match</span>
        </div>
        ${curLoc}
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
          <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px">
            <div style="font-size:.6rem;color:var(--muted2);text-transform:uppercase;letter-spacing:1px">Crime</div>
            <div style="font-weight:600;color:var(--amber);font-size:.82rem">${c.crime_type||'—'}</div>
          </div>
          <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px">
            <div style="font-size:.6rem;color:var(--muted2);text-transform:uppercase;letter-spacing:1px">Threat Score</div>
            <div style="font-weight:700;color:${tcol};font-size:1.1rem">${ts.toFixed(1)}/10</div>
          </div>
          <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px">
            <div style="font-size:.6rem;color:var(--muted2);text-transform:uppercase;letter-spacing:1px">CNIC</div>
            <div style="font-family:monospace;font-size:.75rem">${c.cnic||'—'}</div>
          </div>
          <div style="background:rgba(255,255,255,.04);border-radius:8px;padding:8px">
            <div style="font-size:.6rem;color:var(--muted2);text-transform:uppercase;letter-spacing:1px">Nationality</div>
            <div style="font-size:.75rem">${c.nationality||'—'}</div>
          </div>
        </div>
        ${c.notes?`<div style="background:rgba(255,215,64,.05);border:1px solid rgba(255,215,64,.2);
          border-radius:8px;padding:8px;margin-bottom:10px;font-size:.78rem">${c.notes}</div>`:''}
        ${detRows?`
          <div style="font-size:.65rem;color:var(--muted2);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px">Detection History</div>
          <table style="width:100%;border-collapse:collapse">${detRows}</table>`:
          '<div style="color:var(--muted);font-size:.78rem;margin-bottom:8px">No detection history</div>'}
        <div style="display:flex;gap:8px;margin-top:12px">
          <a href="/map" target="_blank" style="flex:1;text-align:center;background:rgba(0,229,255,.1);
            border:1px solid rgba(0,229,255,.3);border-radius:8px;color:#00e5ff;
            padding:6px;font-size:.75rem;font-weight:700;text-decoration:none">🗺 View on Map</a>
          <a href="/snapshots?source=live" style="flex:1;text-align:center;background:rgba(255,23,68,.1);
            border:1px solid rgba(255,23,68,.3);border-radius:8px;color:#ff5252;
            padding:6px;font-size:.75rem;font-weight:700;text-decoration:none">📷 Snapshots</a>
        </div>`;
    })
    .catch(() => { body.innerHTML = '<div style="color:var(--red2);padding:20px">Failed to load.</div>'; });
}
window.showCriminalDetails = showCriminalDetails;

// ── Main scan ─────────────────────────────────────────────────────────────
async function scan(save) {
  if (busy || !stream) return;
  busy = true;
  try {
    const payload = {
      image:   frameJPEG(),
      save:    !!save,
      lat:     geo.lat,       // real GPS or null — server will NOT fake it
      lon:     geo.lon,
      city:    geo.city,
      address: geo.address
    };
    const res = await fetch('/api/scan_frame', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const j = await res.json();
    drawBoxes(j.results || []);

    const savedMap = {};
    (j.saved || []).forEach(s => { savedMap[s.name] = s; });

    renderResults(j.results || [], savedMap);

    // Beep + alert for criminals
    (j.results || []).forEach(rr => {
      if (rr.name !== 'UNKNOWN PERSON') {
        const now = Date.now();
        if (now - lastAlertAt > 8000 || rr.name !== lastAlertName) {
          lastAlertAt = now; lastAlertName = rr.name;
          CFS.alertCriminal(rr.name, rr.confidence || 0,
            `${rr.crime_type||''}${rr.status?' · '+rr.status:''}`,
            savedMap[rr.name]?.path || null);
        }
      }
    });

    if (j.saved && j.saved.length) {
      savedList.innerHTML = j.saved.map(s =>
        `<img src="/file/by_rel?p=${encodeURIComponent(s.path)}"
          title="${s.name}${s.city?' @ '+s.city:''}"
          style="cursor:pointer"
          onclick="window.open('/file/by_rel?p=${encodeURIComponent(s.path)}')">` 
      ).join('') + savedList.innerHTML;
    }
  } catch(e) { console.error('scan error:', e); }
  finally { busy = false; }
}

btnStart.onclick  = start;
btnStop.onclick   = stop;
btnSnap.onclick   = () => scan(true);
autoScan.onchange = e => {
  if (e.target.checked) { scanTimer = setInterval(() => scan(true), 1500); }
  else if (scanTimer)   { clearInterval(scanTimer); scanTimer = null; }
};
window.addEventListener('beforeunload', stop);
