/* THE VOID marketing site — black hole field + interactions */

(function () {
  "use strict";

  // ── Accretion disk / event horizon field ────────────────
  const canvas = document.getElementById("voidfield");
  if (canvas && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const ctx = canvas.getContext("2d");
    let w, h, cx, cy;
    /** @type {{a:number,r:number,s:number,w:number,hue:number}[]} */
    let particles = [];
    const N = 180;

    function resize() {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
      cx = w * 0.72;
      cy = h * 0.42;
      particles = Array.from({ length: N }, () => spawn(true));
    }

    function spawn(randomPhase) {
      return {
        a: Math.random() * Math.PI * 2,
        r: 40 + Math.random() * Math.min(w, h) * 0.38,
        s: 0.003 + Math.random() * 0.012,
        w: 0.6 + Math.random() * 1.8,
        hue: Math.random() < 0.55 ? 12 + Math.random() * 25 : 250 + Math.random() * 40,
      };
    }

    function frame() {
      // Deep fade — space, not trail-smear
      ctx.fillStyle = "rgba(2, 2, 4, 0.22)";
      ctx.fillRect(0, 0, w, h);

      // Soft photon-sphere glow
      const g = ctx.createRadialGradient(cx, cy, 8, cx, cy, Math.min(w, h) * 0.22);
      g.addColorStop(0, "rgba(0,0,0,0.95)");
      g.addColorStop(0.35, "rgba(20, 8, 12, 0.5)");
      g.addColorStop(0.55, "rgba(255, 77, 46, 0.08)");
      g.addColorStop(0.75, "rgba(124, 106, 239, 0.06)");
      g.addColorStop(1, "transparent");
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.ellipse(cx, cy, Math.min(w, h) * 0.28, Math.min(w, h) * 0.16, -0.25, 0, Math.PI * 2);
      ctx.fill();

      // Singularity core
      const core = Math.min(w, h) * 0.028;
      ctx.fillStyle = "#000";
      ctx.beginPath();
      ctx.arc(cx, cy, core, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = "rgba(255, 77, 46, 0.35)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, core * 1.35, 0, Math.PI * 2);
      ctx.stroke();

      // Orbiting dust
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.a += p.s * (80 / Math.max(p.r, 20));
        // slow spiral inward
        p.r -= 0.015 + p.s * 2;
        if (p.r < core * 1.6) {
          particles[i] = spawn(false);
          continue;
        }
        // elliptical disk
        const x = cx + Math.cos(p.a) * p.r;
        const y = cy + Math.sin(p.a) * p.r * 0.42;
        const dist = p.r / (Math.min(w, h) * 0.4);
        const alpha = Math.max(0.08, 0.7 * (1 - dist));
        ctx.beginPath();
        ctx.fillStyle = `hsla(${p.hue}, 85%, ${55 + dist * 15}%, ${alpha})`;
        ctx.arc(x, y, p.w, 0, Math.PI * 2);
        ctx.fill();
      }

      // Sparse distant stars
      ctx.fillStyle = "rgba(235, 232, 240, 0.35)";
      for (let i = 0; i < 40; i++) {
        const sx = ((i * 97) % w) + (i % 7);
        const sy = ((i * 53) % h) + (i % 5);
        if (Math.hypot(sx - cx, sy - cy) > Math.min(w, h) * 0.2) {
          ctx.fillRect(sx, sy, 1, 1);
        }
      }

      requestAnimationFrame(frame);
    }

    resize();
    window.addEventListener("resize", resize);
    requestAnimationFrame(frame);
  }

  // ── Typing line in hero ─────────────────────────────────
  const typeEl = document.getElementById("type-line");
  if (typeEl) {
    const lines = [
      "event horizon · scope gate · no escape without ROE",
      "warlog never forgets · boneyard never lies",
      "everything falls toward evidence",
      "local-first · MCP-aware · operator-owned",
    ];
    let li = 0;
    let ci = 0;
    let deleting = false;

    function tick() {
      const full = lines[li];
      if (!deleting) {
        ci++;
        typeEl.textContent = full.slice(0, ci);
        if (ci === full.length) {
          deleting = true;
          setTimeout(tick, 1800);
          return;
        }
      } else {
        ci--;
        typeEl.textContent = full.slice(0, ci);
        if (ci === 0) {
          deleting = false;
          li = (li + 1) % lines.length;
        }
      }
      setTimeout(tick, deleting ? 28 : 42);
    }
    tick();
  }

  // ── Terminal fake session ───────────────────────────────
  const termOut = document.getElementById("term-session");
  if (termOut) {
    const script = [
      { t: 200, html: '<span class="prompt">void@kali</span>:<span class="cyan">~</span>$ <span class="cmd">thevoid version</span>' },
      { t: 500, html: '<span class="out">THE VOID 1.1.0 — operator-authorized AI red team</span>' },
      { t: 400, html: '<span class="prompt">void@kali</span>:<span class="cyan">~</span>$ <span class="cmd">thevoid recon 10.0.0.5 --profile demo --dry-run</span>' },
      { t: 700, html: '<span class="warn">[*]</span> <span class="out">scope check · ROE loaded · high-risk phases denied</span>' },
      { t: 500, html: '<span class="ok">[+]</span> <span class="out">planned: recon</span>' },
      { t: 400, html: '<span class="ok">[+]</span> <span class="out">dry-run complete · zero tools fired</span>' },
      { t: 450, html: '<span class="prompt">void@kali</span>:<span class="cyan">~</span>$ <span class="cmd">thevoid status</span>' },
      { t: 600, html: '<span class="out">warlog_entries: 1410 · boneyard: 144 · engaged: false</span>' },
      { t: 400, html: '<span class="prompt">void@kali</span>:<span class="cyan">~</span>$ <span class="cmd"># nothing escapes the log</span>' },
    ];

    let delay = 0;
    termOut.innerHTML = "";
    script.forEach((row) => {
      delay += row.t;
      setTimeout(() => {
        const line = document.createElement("div");
        line.innerHTML = row.html;
        termOut.appendChild(line);
        termOut.parentElement.scrollTop = termOut.parentElement.scrollHeight;
      }, delay);
    });
  }

  // ── Demo tabs ───────────────────────────────────────────
  const tabs = document.querySelectorAll(".demo-tab");
  const body = document.getElementById("demo-body");
  const panes = {
    dryrun: `$ thevoid recon 127.0.0.1 --profile demo --dry-run

[*] Engaging 127.0.0.1 (mode=quick, dry-run)
→ phases: recon
→ AuthorizationGate: ALLOW (loopback / lab ROE)
→ DifficultyAssessor: advisory score logged
→ status: dry_run

# No nmap. No nuclei. No noise.
# The gate holds. The horizon does not move.`,
    recon: `$ thevoid recon 10.0.0.5 --profile demo

[*] Phase 1/1: recon
    OSINT · PortScan · WebRecon · HostEnum
[+] findings written → Boneyard
[+] spans closed → WarLog (HMAC chain intact)

$ thevoid report --format html -o results/lab.html
[+] Report written · exec_summary ready for the room`,
    mcp: `$ # MCP is the new gravity well

[*] Phase: mcp_scan
[*] Phase: mcp_attack
    tool enum · auth posture · attack-class patterns
[*] Phase: mcp_chain
    findings → DAG → cascade detection
[*] Phase: mcp_c2  (aggressive+)
    beacon through tool calls · blend into legitimate traffic

# Attack surface. C2 channel. Defense suite.
# Same protocol. Different side of the event horizon.`,
    ops: `# Operator surfaces (clean · professional)

CLI:   thevoid engage|recon|report|status
CC:    http://127.0.0.1:7070
       dense · dark · no marketing chrome

WarLog  → what happened (WORM, chained)
Boneyard → what was found (HMAC integrity)
Reporter → what you hand the human

# Marketing is the accretion glow.
# Ops is the quiet instrument panel.`,
  };

  if (tabs.length && body) {
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        tabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        const key = tab.dataset.pane;
        body.textContent = panes[key] || "";
      });
    });
    body.textContent = panes.dryrun;
  }

  // ── Mobile nav ──────────────────────────────────────────
  const toggle = document.querySelector(".nav-toggle");
  const links = document.querySelector(".nav-links");
  if (toggle && links) {
    toggle.addEventListener("click", () => links.classList.toggle("open"));
    links.querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", () => links.classList.remove("open"));
    });
  }

  // ── Scroll reveal ───────────────────────────────────────
  const revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add("visible");
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" },
    );
    revealEls.forEach((el) => io.observe(el));
  } else {
    revealEls.forEach((el) => el.classList.add("visible"));
  }

  // ── Active nav on scroll ────────────────────────────────
  const sections = [...document.querySelectorAll("section[id]")];
  const navAs = [...document.querySelectorAll(".nav-links a[href^='#']")];

  function onScroll() {
    const y = window.scrollY + 90;
    let current = "";
    sections.forEach((s) => {
      if (s.offsetTop <= y) current = s.id;
    });
    navAs.forEach((a) => {
      a.classList.toggle("active", a.getAttribute("href") === `#${current}`);
    });
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
})();
