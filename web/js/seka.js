/* SEKA TUNEL UI — connected to real backend /api/* */
(function () {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const API = (path, opts = {}) =>
    fetch(path, {
      headers: {
        "Content-Type": "application/json",
        ...(localStorage.getItem("seka-token")
          ? { "X-Token": localStorage.getItem("seka-token") }
          : {}),
        ...(opts.headers || {}),
      },
      ...opts,
    }).then(async (r) => {
      const j = await r.json().catch(() => ({}));
      if (!r.ok || j.ok === false) throw new Error(j.error || r.statusText);
      return j;
    });

  window.addEventListener("load", () => {
    setTimeout(() => {
      $("#boot").classList.add("hidden");
      $("#app").classList.remove("hidden");
      toast("خوش آمدید به SEKA TUNEL");
      refreshAll();
    }, 900);
  });

  const titles = {
    dash: "داشبورد",
    tunnels: "تانل‌ها",
    gaaf: "پروتکل GAAF",
    balancer: "بالانسر",
    nodes: "نودهای خارج",
    test: "تست اتصال",
    settings: "تنظیمات",
  };

  $$(".nav").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".nav").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      $$(".tab").forEach((t) => t.classList.remove("active"));
      const el = $("#tab-" + tab);
      if (el) el.classList.add("active");
      $("#pageTitle").textContent = titles[tab] || "SEKA";
      if (tab === "tunnels") loadTunnels();
      if (tab === "gaaf") loadGaaf();
      if (tab === "nodes") loadNodes();
      if (tab === "balancer") loadPools();
      if (tab === "dash") loadStats();
    });
  });

  function setTheme(t) {
    document.documentElement.setAttribute("data-theme", t);
    localStorage.setItem("seka-theme", t);
  }
  setTheme(localStorage.getItem("seka-theme") || "dark");
  $$(".td").forEach((d) => d.addEventListener("click", () => setTheme(d.dataset.t)));
  $$("[data-theme]").forEach((b) =>
    b.addEventListener("click", () => setTheme(b.dataset.theme))
  );

  async function loadStats() {
    try {
      const j = await API("/api/stats");
      const d = j.data || {};
      $("#statTunnels").textContent = d.tunnels ?? 0;
      $("#statNodes").textContent = d.nodes ?? 0;
      $("#statGaaf").textContent = d.gaaf ?? 0;
      $("#statSpeed").textContent = d.running_gaaf ? "GAAF ON" : "—";
    } catch (e) {
      console.warn(e);
    }
  }

  async function loadTunnels() {
    const body = $("#tunnelBody");
    try {
      const j = await API("/api/tunnels");
      const rows = j.data || [];
      if (!rows.length) {
        body.innerHTML =
          '<tr><td colspan="5" class="empty">هنوز تانلی ساخته نشده</td></tr>';
        return;
      }
      body.innerHTML = rows
        .map(
          (t) => `<tr>
          <td><b>${esc(t.name || "tunnel"+t.id)}</b><br><span class="muted">${esc(t.type)} · ${esc(t.ip)}</span></td>
          <td class="ltr">${esc(t.port)}</td>
          <td>${t.pending ? "⏳ انتظار" : t.active ? "✅ فعال" : "⏸"}</td>
          <td>${esc((t.tr || "udp").toUpperCase())}</td>
          <td>—</td>
        </tr>`
        )
        .join("");
    } catch (e) {
      body.innerHTML = `<tr><td colspan="5" class="empty">خطا: ${esc(e.message)}</td></tr>`;
    }
  }

  async function loadGaaf() {
    try {
      const j = await API("/api/gaaf");
      const n = (j.data || []).length;
      toast("تانل‌های GAAF: " + n);
    } catch (e) {
      toast("GAAF: " + e.message);
    }
  }

  async function loadNodes() {
    const box = $("#nodeList");
    try {
      const j = await API("/api/nodes");
      const rows = j.data || [];
      if (!rows.length) {
        box.innerHTML = '<div class="empty">نودی ثبت نشده</div>';
        return;
      }
      box.innerHTML = rows
        .map(
          (n) => `<div class="node-item">
          <div><b>${esc(n.name)}</b><br><span>${esc(n.host)}:${esc(n.port)} · w=${esc(n.weight)}</span></div>
          <div>${esc(n.status)}</div>
        </div>`
        )
        .join("");
    } catch (e) {
      box.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    }
  }

  async function loadPools() {
    const box = $("#poolList");
    try {
      const j = await API("/api/pools");
      const rows = j.data || [];
      if (!rows.length) {
        box.innerHTML = '<div class="empty">استخری تعریف نشده</div>';
        return;
      }
      box.innerHTML = rows
        .map(
          (p) => `<div class="node-item">
          <div><b>${esc(p.name)}</b><br><span>${esc(p.strategy)} · nodes: ${esc(p.nodes)}</span></div>
          <div>#${esc(p.id)}</div>
        </div>`
        )
        .join("");
    } catch (e) {
      box.innerHTML = `<div class="empty">${esc(e.message)}</div>`;
    }
  }

  function refreshAll() {
    loadStats();
    loadTunnels();
    loadNodes();
    loadPools();
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  window.openWizard = function () {
    $("#wizard").classList.remove("hidden");
  };
  window.closeWizard = function () {
    $("#wizard").classList.add("hidden");
  };
  $$(".ch").forEach((c) => {
    c.addEventListener("click", () => {
      $$(".ch").forEach((x) => x.classList.remove("on"));
      c.classList.add("on");
    });
  });

  $("#wizNext").addEventListener("click", async () => {
    const type = $(".ch.on")?.dataset.v || "rev";
    closeWizard();
    try {
      if (type === "gaaf") {
        const profile = localStorage.getItem("seka-gaaf-profile") || "balanced";
        const j = await API("/api/gaaf/create", {
          method: "POST",
          body: JSON.stringify({ direction: "rev", profile }),
        });
        toast("تانل GAAF ساخته شد #" + (j.id || ""));
      } else {
        // classic forward via UI
        const listen = prompt("پورت ورودی روی این سرور:", "443");
        if (!listen) return;
        const dest_ip = prompt("IP مقصد (سرور خارج یا سرویس):", "");
        if (!dest_ip) return;
        const dest_port = prompt("پورت مقصد:", listen) || listen;
        const name = prompt("نام تانل:", "fwd-" + listen) || ("fwd-" + listen);
        const j = await API("/api/tunnels/add", {
          method: "POST",
          body: JSON.stringify({
            name,
            proto: "tcp",
            listen,
            dest_ip,
            dest_port,
            direction: type,
          }),
        });
        toast("فوروارد ساخته شد: " + (j.name || name) + " → " + dest_ip);
      }
      refreshAll();
      loadTunnels();
    } catch (e) {
      toast("خطا: " + e.message);
    }
  });

  $("#btnNewTunnel").addEventListener("click", openWizard);
  $("#btnRefresh").addEventListener("click", () => {
    refreshAll();
    toast("بروزرسانی شد");
  });

  $("#btnNewNode")?.addEventListener("click", async () => {
    const host = prompt("آدرس نود (IP یا دامنه):");
    if (!host) return;
    const name = prompt("نام نود:", "kharej-1") || "kharej-1";
    try {
      await API("/api/nodes/add", {
        method: "POST",
        body: JSON.stringify({ host, name, port: "24444", weight: "100" }),
      });
      toast("نود اضافه شد");
      loadNodes();
      loadStats();
    } catch (e) {
      toast(e.message);
    }
  });

  $("#btnNewPool")?.addEventListener("click", async () => {
    const name = prompt("نام استخر:", "pool-main") || "pool-main";
    const nodes = prompt("شناسه نودها با کاما:", "") || "";
    try {
      await API("/api/pools/add", {
        method: "POST",
        body: JSON.stringify({ name, strategy: "weighted", nodes }),
      });
      toast("استخر ساخته شد");
      loadPools();
    } catch (e) {
      toast(e.message);
    }
  });

  $("#btnTest")?.addEventListener("click", async () => {
    const out = $("#testOut");
    out.classList.remove("hidden");
    out.textContent = "در حال اجرای چکر...";
    try {
      const j = await API("/api/check/run", { method: "POST", body: "{}" });
      out.textContent = j.output || "بدون خروجی";
      toast("چکر تمام شد");
    } catch (e) {
      out.textContent = "خطا: " + e.message + "\nCLI: seka-tunel check all";
    }
  });

  $$(".prof").forEach((p) => {
    p.addEventListener("click", () => {
      $$(".prof").forEach((x) => x.classList.remove("active"));
      p.classList.add("active");
      localStorage.setItem("seka-gaaf-profile", p.dataset.p);
      toast("پروفایل: " + p.dataset.p);
    });
  });

  window.toast = function (msg) {
    const t = document.createElement("div");
    t.className = "toast";
    t.textContent = msg;
    $("#toast").appendChild(t);
    setTimeout(() => t.remove(), 2800);
  };
})();
