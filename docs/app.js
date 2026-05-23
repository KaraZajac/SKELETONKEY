/* SKELETONKEY landing page — interactive bits.
 * No frameworks. ~150 lines vanilla JS. Respects prefers-reduced-motion. */

(function () {
  'use strict';

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ============================================================
   * 1. typed install command in the hero
   * ============================================================ */
  const installCmd =
    'curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh \\\n  && skeletonkey --auto --i-know';
  const typedEl  = document.getElementById('install-typed');
  const cursorEl = document.getElementById('install-cursor');

  function typeInstall(cb) {
    if (reduceMotion) {
      typedEl.textContent = installCmd;
      if (cursorEl) cursorEl.style.display = 'none';
      if (cb) cb();
      return;
    }
    let i = 0;
    function step() {
      typedEl.textContent = installCmd.slice(0, i);
      i++;
      if (i <= installCmd.length) {
        setTimeout(step, 18 + Math.random() * 22);
      } else {
        if (cursorEl) {
          // keep cursor blinking for 2s, then hide
          setTimeout(() => { cursorEl.style.display = 'none'; }, 2000);
        }
        if (cb) cb();
      }
    }
    step();
  }

  /* ============================================================
   * 2. copy install command
   * ============================================================ */
  window.copyInstall = function (btn) {
    const text = installCmd;
    navigator.clipboard.writeText(text).then(() => {
      const original = btn.textContent;
      btn.textContent = 'copied!';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = original;
        btn.classList.remove('copied');
      }, 1500);
    }).catch(() => {
      btn.textContent = '(copy failed)';
      setTimeout(() => { btn.textContent = 'copy'; }, 1500);
    });
  };

  /* ============================================================
   * 3. stat count-up animation on view
   * ============================================================ */
  function countUp(el) {
    const target = parseInt(el.dataset.target, 10);
    if (!target || reduceMotion) { el.textContent = target; return; }
    const dur = 1100;
    const start = performance.now();
    function tick(now) {
      const t = Math.min((now - start) / dur, 1);
      // ease-out
      const v = Math.round(target * (1 - Math.pow(1 - t, 3)));
      el.textContent = v;
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* ============================================================
   * 4. --explain terminal: line-by-line reveal
   * ============================================================ */
  const explainHTML = [
    '\n',
    '<span class="t-rule">════════════════════════════════════════════════════</span>\n',
    ' <span class="t-mod">nf_tables</span>   <span class="t-cve">CVE-2024-1086</span>\n',
    '<span class="t-rule">════════════════════════════════════════════════════</span>\n',
    ' <span class="t-summary">nf_tables nft_verdict_init UAF (cross-cache) → arbitrary kernel R/W</span>\n',
    '\n',
    '<span class="t-header">WEAKNESS</span>\n',
    '  <span class="t-cwe">CWE-416</span>\n',
    '  <span class="t-label">MITRE ATT&amp;CK:</span> <span class="t-tech">T1068</span>\n',
    '\n',
    '<span class="t-header">THREAT INTEL</span>\n',
    '  <span class="t-kev-yes">★ In CISA Known Exploited Vulnerabilities catalog (added 2024-05-30)</span>\n',
    '  <span class="t-label">Affected:</span> 5.14 ≤ K, fixed mainline 6.8; backports: 6.7.2 / 6.6.13 / 6.1.74 / 5.15.149 / 5.10.210\n',
    '\n',
    '<span class="t-header">HOST FINGERPRINT</span>\n',
    '  <span class="t-label">kernel:</span>        5.15.0-43-generic (x86_64)\n',
    '  <span class="t-label">distro:</span>        Ubuntu 22.04.5 LTS\n',
    '  <span class="t-label">unpriv userns:</span> ALLOWED\n',
    '\n',
    '<span class="t-header">DETECT() TRACE (live; reads ctx->host, fires gates)</span>\n',
    '<span class="t-i">[i] nf_tables: kernel 5.15.0-43-generic in vulnerable range</span>\n',
    '<span class="t-i">[i] nf_tables: userns gate passed</span>\n',
    '<span class="t-i">[i] nf_tables: nft_verdict_init reachable; bug is fireable here</span>\n',
    '\n',
    '<span class="t-header">VERDICT:</span> <span class="t-vuln">VULNERABLE</span>\n',
    '  -&gt; bug is reachable. The OPSEC section below shows what a successful\n',
    '     exploit() would leave on this host.\n',
    '\n',
    '<span class="t-header">OPSEC FOOTPRINT (what exploit() leaves on this host)</span>\n',
    '  unshare(CLONE_NEWUSER|CLONE_NEWNET) + nfnetlink batch (NEWTABLE +\n',
    '  NEWCHAIN/LOCAL_OUT + NEWSET verdict-key + NEWSETELEM malformed NFT_GOTO)\n',
    '  committed twice. msg_msg cg-96 groom; dmesg: KASAN double-free on vuln\n',
    '  kernels. Cleanup is finisher-gated; no persistent files on success.\n',
    '\n',
    '<span class="t-header">DETECTION COVERAGE (rules embedded in this binary)</span>\n',
    '  <span class="t-check">✓</span> auditd    <span class="t-check">✓</span> sigma    <span class="t-check">✓</span> yara    <span class="t-check">✓</span> falco\n',
  ];
  function playExplain(el) {
    if (reduceMotion) { el.innerHTML = explainHTML.join(''); return; }
    let i = 0;
    el.innerHTML = '';
    function step() {
      if (i >= explainHTML.length) return;
      el.innerHTML += explainHTML[i];
      i++;
      // pause longer on blank lines to feel like real terminal output
      const next = explainHTML[i - 1];
      const delay = next === '\n' ? 60 : (45 + Math.random() * 50);
      setTimeout(step, delay);
    }
    step();
  }

  /* ============================================================
   * 5. quickstart tabs
   * ============================================================ */
  function initTabs() {
    const tabs   = document.querySelectorAll('.tab');
    const panels = document.querySelectorAll('.tab-panel');
    tabs.forEach((t) => {
      t.addEventListener('click', () => {
        const tab = t.dataset.tab;
        tabs.forEach((x) => x.classList.toggle('active', x === t));
        panels.forEach((p) => p.classList.toggle('active', p.dataset.tab === tab));
      });
    });
  }

  /* ============================================================
   * 6. scroll-triggered reveal + first-time triggers
   * ============================================================ */
  function initReveal() {
    if (!('IntersectionObserver' in window) || reduceMotion) {
      document.querySelectorAll('.reveal').forEach((el) => el.classList.add('in'));
      // also fire one-shot animations immediately
      countAllStats();
      const explainEl = document.getElementById('explain-output');
      if (explainEl) playExplain(explainEl);
      return;
    }

    const obs = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) {
          e.target.classList.add('in');
          // fire one-shot effects when the right section becomes visible
          if (e.target.id === 'explain') {
            const out = e.target.querySelector('#explain-output');
            if (out && !out.dataset.played) {
              out.dataset.played = '1';
              playExplain(out);
            }
          }
          obs.unobserve(e.target);
        }
      });
    }, { threshold: 0.15 });

    document.querySelectorAll('.reveal').forEach((el) => obs.observe(el));
  }

  function countAllStats() {
    document.querySelectorAll('.stat-chip .num').forEach(countUp);
  }

  /* fire the stats count-up as soon as the hero shows */
  function initStatsCountUp() {
    if (!('IntersectionObserver' in window) || reduceMotion) {
      countAllStats();
      return;
    }
    const row = document.getElementById('stats-row');
    if (!row) return;
    const o = new IntersectionObserver((es) => {
      if (es[0].isIntersecting) {
        countAllStats();
        o.disconnect();
      }
    });
    o.observe(row);
  }

  /* ============================================================
   * boot
   * ============================================================ */
  document.addEventListener('DOMContentLoaded', () => {
    typeInstall();
    initTabs();
    initReveal();
    initStatsCountUp();
  });
})();
