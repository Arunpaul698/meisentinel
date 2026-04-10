// ── Meisentis — Shared nav shell ─────────────────────────────────────────────
// Include this script in every page. Injects the nav and applies global CSS.

const BACKEND = 'https://meisentinel.onrender.com';
const BASE_URL = '';

const NAV_HTML = `
<nav class="m-nav">
  <a class="m-nav-logo" href="${BASE_URL}landing.html">
    <div class="m-nav-logomark">M</div>
    <div class="m-nav-logotype">
      <span class="m-nav-name">Meisentis</span>
      <span class="m-nav-sub">Truth Sentinel</span>
    </div>
  </a>
  <div class="m-nav-links">
    <a href="${BASE_URL}landing.html"   class="m-nav-link" data-page="landing">Product</a>
    <a href="${BASE_URL}dashboard.html" class="m-nav-link" data-page="dashboard">Dashboard</a>
    <a href="${BASE_URL}portal.html"    class="m-nav-link" data-page="portal">Scan</a>
  </div>
  <div class="m-nav-right">
    <div class="m-nav-status"><span class="m-nav-dot"></span>Live</div>
    <a href="${BASE_URL}portal.html" class="m-nav-cta">New Scan →</a>
  </div>
</nav>`;

const NAV_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; }

  body {
    margin: 0;
    font-family: 'DM Sans', sans-serif;
    background: #F7F8FA;
    color: #0F1923;
  }

  .m-nav {
    position: fixed; top: 0; left: 0; right: 0; z-index: 200;
    height: 56px;
    display: flex; align-items: center;
    padding: 0 32px; gap: 32px;
    background: #ffffff;
    border-bottom: 1px solid #E8ECF0;
  }
  .m-nav-logo {
    display: flex; align-items: center; gap: 10px;
    text-decoration: none;
  }
  .m-nav-logomark {
    width: 30px; height: 30px;
    background: #0F1923;
    border-radius: 7px;
    display: flex; align-items: center; justify-content: center;
    font-family: 'DM Mono', monospace;
    font-size: 13px; font-weight: 500;
    color: #fff;
  }
  .m-nav-logotype { display: flex; flex-direction: column; gap: 1px; }
  .m-nav-name { font-family: 'DM Sans', sans-serif; font-size: 14px; font-weight: 600; color: #0F1923; letter-spacing: -0.2px; }
  .m-nav-sub  { font-family: 'DM Mono', monospace; font-size: 9px; color: #94A3B8; letter-spacing: 0.04em; }

  .m-nav-links { display: flex; gap: 2px; margin-left: auto; }
  .m-nav-link {
    font-family: 'DM Sans', sans-serif; font-size: 13px; font-weight: 500;
    color: #64748B; text-decoration: none;
    padding: 6px 14px; border-radius: 7px;
    transition: all 0.15s;
  }
  .m-nav-link:hover { background: #F1F5F9; color: #0F1923; }
  .m-nav-link.active { background: #F1F5F9; color: #0F1923; }

  .m-nav-right { display: flex; align-items: center; gap: 16px; }
  .m-nav-status {
    display: flex; align-items: center; gap: 6px;
    font-family: 'DM Mono', monospace; font-size: 11px; color: #94A3B8;
  }
  .m-nav-dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: #22C55E;
    animation: pulse-dot 2s ease-in-out infinite;
  }
  @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:0.3} }

  .m-nav-cta {
    font-family: 'DM Sans', sans-serif; font-size: 13px; font-weight: 600;
    color: #fff; background: #0F1923;
    padding: 7px 16px; border-radius: 8px;
    text-decoration: none; letter-spacing: 0.01em;
    transition: background 0.15s;
  }
  .m-nav-cta:hover { background: #1E293B; }
`;

function injectNav(activePage) {
  const style = document.createElement('style');
  style.textContent = NAV_CSS;
  document.head.appendChild(style);

  const nav = document.createElement('div');
  nav.innerHTML = NAV_HTML;
  document.body.prepend(nav.firstElementChild);

  document.querySelectorAll('.m-nav-link').forEach(a => {
    if (a.dataset.page === activePage) a.classList.add('active');
  });

  document.body.style.paddingTop = '56px';
}
