// ── Meisentis — Shared shell, nav, and design tokens ────────────────────────
// Include this script in every page. It injects the nav and applies global CSS.

const BASE_URL = '';
const BACKEND  = 'https://meisentinel.onrender.com';

const NAV_HTML = `
<nav class="ssa-nav">
  <a class="nav-logo" href="${BASE_URL}landing.html">
    <div class="nav-logomark">M</div>
    <div class="nav-logotype">
      <span class="nav-logotype-main">Meisentis</span>
      <span class="nav-logotype-sub">The Truth Sentinel</span>
    </div>
  </a>
  <div class="nav-links">
    <a href="${BASE_URL}landing.html" class="nav-link" data-page="landing">Product</a>
    <a href="${BASE_URL}dashboard.html" class="nav-link" data-page="dashboard">Dashboard</a>
    <a href="${BASE_URL}portal.html" class="nav-link" data-page="portal">Scan</a>
  </div>
  <div class="nav-right">
    <div class="nav-status"><span class="nav-dot"></span>LIVE</div>
    <a href="${BASE_URL}portal.html" class="nav-cta">New Scan →</a>
  </div>
</nav>`;

const NAV_CSS = `
  .ssa-nav {
    position: fixed; top: 0; left: 0; right: 0; z-index: 200;
    height: 56px;
    display: flex; align-items: center;
    padding: 0 32px; gap: 32px;
    background: rgba(10,12,15,0.92);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid #1e242c;
  }
  .nav-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
  .nav-logomark {
    width:32px; height:32px; border:1.5px solid #00d4ff;
    display:grid; place-items:center;
    font-family:'IBM Plex Mono',monospace; font-size:13px; font-weight:700;
    color:#00d4ff; letter-spacing:-0.5px;
    box-shadow: 0 0 10px rgba(0,212,255,0.15);
  }
  .nav-logotype { display:flex; flex-direction:column; gap:1px; }
  .nav-logotype-main { font-family:'IBM Plex Mono',monospace; font-size:12px; font-weight:700; color:#c8d0da; letter-spacing:0.02em; }
  .nav-logotype-sub  { font-family:'IBM Plex Mono',monospace; font-size:8px; color:#5a6672; letter-spacing:0.08em; }
  .nav-links { display:flex; gap:4px; margin-left:auto; }
  .nav-link {
    font-family:'IBM Plex Mono',monospace; font-size:11px; letter-spacing:0.06em;
    color:#5a6672; text-decoration:none; padding:6px 14px;
    border:1px solid transparent; transition:all 0.15s;
  }
  .nav-link:hover, .nav-link.active { color:#c8d0da; border-color:#1e242c; background:rgba(255,255,255,0.03); }
  .nav-right { display:flex; align-items:center; gap:16px; }
  .nav-status { display:flex; align-items:center; gap:6px; font-family:'IBM Plex Mono',monospace; font-size:10px; color:#5a6672; }
  .nav-dot { width:6px; height:6px; border-radius:50%; background:#00c96e; animation: ndot 2s ease-in-out infinite; }
  @keyframes ndot { 0%,100%{opacity:1} 50%{opacity:0.3} }
  .nav-cta {
    font-family:'IBM Plex Mono',monospace; font-size:11px; font-weight:700;
    color:#0a0c0f; background:#00d4ff; padding:7px 16px;
    text-decoration:none; letter-spacing:0.06em; transition:all 0.15s;
  }
  .nav-cta:hover { background:#00b8d9; }
`;

function injectNav(activePage) {
  const style = document.createElement('style');
  style.textContent = NAV_CSS;
  document.head.appendChild(style);

  const nav = document.createElement('div');
  nav.innerHTML = NAV_HTML;
  document.body.prepend(nav.firstElementChild);

  document.querySelectorAll('.nav-link').forEach(a => {
    if (a.dataset.page === activePage) a.classList.add('active');
  });

  document.body.style.paddingTop = '56px';
}
