package concentrator

// uiHTML is the whole observability UI: one page, no build step, no external
// requests. It is deliberately plain — the value is in the numbers being
// visible at all, since the device itself reports nothing useful.
const uiHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>icgd</title>
<style>
:root{
  --bg:#f7f7f8; --panel:#fff; --ink:#16181d; --dim:#6a7080; --line:#e2e4ea;
  --ok:#177245; --warn:#8a5300; --bad:#a11; --accent:#1f4f8f;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#14161a; --panel:#1c1f25; --ink:#e6e8ee; --dim:#98a0b0; --line:#2b2f38;
        --ok:#57c98b; --warn:#e0a44a; --bad:#f0736f; --accent:#7fb1f0;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;flex-wrap:wrap;gap:.75rem 1.5rem;align-items:baseline;
  padding:1rem 1.25rem;border-bottom:1px solid var(--line);background:var(--panel)}
h1{font-size:1.05rem;margin:0;letter-spacing:.02em}
h1 span{color:var(--dim);font-weight:400}
main{padding:1.25rem;max-width:1200px;margin:0 auto}
section{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:1rem 1.1rem;margin-bottom:1.1rem}
h2{font-size:.82rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
  margin:0 0 .8rem}
.kv{display:flex;flex-wrap:wrap;gap:.35rem 1.6rem;font-variant-numeric:tabular-nums}
.kv div{white-space:nowrap}
.kv b{font-weight:600}
.kv i{color:var(--dim);font-style:normal;margin-right:.35rem}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:.4rem .55rem;border-bottom:1px solid var(--line);
  white-space:nowrap}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--dim);font-weight:600}
tbody tr:last-child td{border-bottom:0}
.wrap{overflow-x:auto}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.86em}
.pill{display:inline-block;padding:.05rem .45rem;border-radius:999px;font-size:.75rem;
  border:1px solid currentColor}
.ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
.dim{color:var(--dim)}
.notice{border-left:3px solid var(--warn);padding:.5rem .7rem;margin-bottom:.5rem;
  background:color-mix(in srgb,var(--warn) 8%,transparent);border-radius:0 5px 5px 0}
.notice .fix{color:var(--dim);font-size:.9em}
.notice.info{border-left-color:var(--accent);background:color-mix(in srgb,var(--accent) 8%,transparent)}
form{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center}
input,button{font:inherit;padding:.4rem .6rem;border-radius:6px;border:1px solid var(--line);
  background:var(--bg);color:var(--ink)}
button{cursor:pointer;border-color:var(--accent);color:var(--accent)}
.empty{color:var(--dim);font-style:italic}
#err{color:var(--bad)}
</style>
</head>
<body>
<header>
  <h1>icgd <span id="ver"></span></h1>
  <div class="kv" id="top"></div>
  <div style="margin-left:auto" class="dim" id="tick"></div>
</header>
<main>
  <section id="login" hidden>
    <h2>API key</h2>
    <form onsubmit="saveKey(event)">
      <input id="key" type="password" size="40" placeholder="shared secret" autocomplete="off">
      <button type="submit">Connect</button>
    </form>
    <p class="dim">icgd prints a generated key at startup, or set one with
      <code>-http-key</code>. It is kept in this browser only.</p>
    <p id="err"></p>
  </section>

  <section id="listeners" hidden>
    <h2>Listeners</h2>
    <div class="kv" id="lsn"></div>
  </section>

  <section id="sessions" hidden>
    <h2>Devices</h2>
    <div id="sessbody"></div>
  </section>

  <section id="notices" hidden>
    <h2>Recent problems</h2>
    <div id="notebody"></div>
  </section>
</main>
<script>
"use strict";
const $ = id => document.getElementById(id);
let key = localStorage.getItem("icgd.key") || new URLSearchParams(location.search).get("key") || "";

function saveKey(e){
  e.preventDefault();
  key = $("key").value.trim();
  localStorage.setItem("icgd.key", key);
  $("err").textContent = "";
  poll();
}

function show(on){
  for (const id of ["listeners","sessions","notices"]) $(id).hidden = !on;
  $("login").hidden = on;
}

const num = n => (n===undefined||n===null) ? "-" : n.toLocaleString();
const secs = s => s === undefined ? "-" :
  s < 90 ? s.toFixed(1)+"s" : s < 5400 ? (s/60).toFixed(1)+"m" : (s/3600).toFixed(1)+"h";
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// A counter that should normally be zero: call it out when it is not.
function bad(n, label){
  if (!n) return "";
  return ' <span class="pill bad">'+num(n)+" "+label+"</span>";
}

function stateClass(st){
  if (st === "ICG_AND_SRV_BOTH_OK") return "ok";
  if (st === "ICG_INIT_STATE") return "warn";
  return "";
}

function renderTop(d){
  $("ver").textContent = d.version ? "· " + d.version : "";
  $("top").innerHTML =
    '<div><i>uptime</i><b>'+secs(d.uptime_sec)+'</b></div>' +
    '<div><i>magic</i><b class="mono">'+esc(d.magic)+'</b></div>' +
    '<div><i>devices</i><b>'+d.sessions.length+'</b></div>' +
    '<div><i>admission</i><b>'+(d.admission.enabled
        ? d.admission.devices.length+' allowed' : 'any device')+'</b></div>';
  $("lsn").innerHTML =
    '<div><i>tcp</i><b class="mono">'+esc(d.listeners.tcp||"-")+'</b></div>' +
    '<div><i>udp</i><b class="mono">'+esc((d.listeners.udp||[]).join(" ")||"-")+'</b></div>' +
    (d.admission.enabled
      ? '<div><i>allowed</i><b class="mono">'+esc(d.admission.devices.join(" "))+'</b></div>' : "");
}

function renderSessions(list){
  if (!list.length){
    $("sessbody").innerHTML = '<p class="empty">No device has connected yet. '+
      'If one should have, check "Recent problems" below.</p>';
    return;
  }
  $("sessbody").innerHTML = list.map(s => {
    const c = s.counters, r = s.reassembly;
    const legs = (s.legs||[]).map(l =>
      '<tr><td>'+esc(l.kind)+(l.tunnel_id>=0?" #"+l.tunnel_id:"")+'</td>'+
      '<td class="mono">'+esc(l.remote)+'</td>'+
      '<td>'+(l.rtt_ms?l.rtt_ms.toFixed(0)+" ms":'<span class="dim">unmeasured</span>')+'</td>'+
      '<td>'+secs(l.idle_sec)+'</td>'+
      '<td>'+(l.closed?'<span class="bad">closed</span>':'<span class="ok">up</span>')+
        bad(l.write_errors,"write err")+'</td></tr>').join("");
    return '<div style="margin-bottom:1.2rem">'+
      '<div class="kv" style="margin-bottom:.5rem">'+
        '<div><i>tun ip</i><b class="mono">'+esc(s.tun_ip)+'</b></div>'+
        '<div><i>state</i><b class="'+stateClass(s.state)+'">'+esc(s.state)+'</b></div>'+
        '<div><i>mac</i><b class="mono">'+esc(s.client_mac)+'</b></div>'+
        '<div><i>admitted</i><b class="'+(s.admitted?"ok":"bad")+'">'+(s.admitted?"yes":"no")+'</b></div>'+
        '<div><i>idle</i><b>'+secs(s.idle_sec)+'</b></div>'+
      '</div>'+
      (legs
        ? '<div class="wrap"><table><thead><tr><th>leg</th><th>peer</th><th>rtt</th>'+
          '<th>idle</th><th>state</th></tr></thead><tbody>'+legs+'</tbody></table></div>'
        : '<p class="empty">No legs attached. The device has disconnected every tunnel; '+
          'the session is kept briefly so it can reconnect without re-handshaking.</p>')+
      '<div class="kv" style="margin-top:.5rem">'+
        '<div><i>frames</i><b>'+num(c.frames_in)+' in / '+num(c.frames_out)+' out</b>'+
          bad(c.dropped_in,"dropped")+'</div>'+
        '<div><i>tcp flows</i><b>'+num(s.flows.tcp_active)+' active / '+num(s.flows.tcp_total)+' total</b>'+
          bad(c.upstream_dial_failures,"dial fail")+'</div>'+
        '<div><i>udp flows</i><b>'+num(s.flows.udp_active)+' / '+num(s.flows.udp_total)+'</b></div>'+
        '<div><i>reorder</i><b>'+num(r.tcp_pending)+' pending</b>'+
          bad(r.tcp_skipped,"tcp skipped")+bad(r.udp_skipped,"udp skipped")+'</div>'+
        '<div><i>retransmit</i><b>'+num(c.retransmits_served)+' served / '+
          num(c.retransmits_requested)+' asked</b>'+bad(r.stash_misses,"stash miss")+'</div>'+
        bad(c.icmp_dropped,"icmp dropped")+
        bad(c.refused,"refused")+
        bad(c.unknown_frames,"unknown frames")+
      '</div></div>';
  }).join("");
}

function renderNotices(list){
  if (!list.length){
    $("notebody").innerHTML = '<p class="empty">Nothing to report.</p>';
    return;
  }
  $("notebody").innerHTML = list.map(n =>
    '<div class="notice '+(n.level==="warn"?"":"info")+'">'+
      '<div>'+esc(n.msg)+(n.count>1?' <span class="pill">x'+n.count+'</span>':"")+'</div>'+
      (n.peer?'<div class="fix mono">'+esc(n.peer)+'</div>':"")+
      (n.fix?'<div class="fix">fix: '+esc(n.fix)+'</div>':"")+
      '<div class="fix">'+new Date(n.at).toLocaleTimeString()+' · '+esc(n.kind)+'</div>'+
    '</div>').join("");
}

async function poll(){
  if (!key){ show(false); return; }
  try {
    const res = await fetch("api/status", {headers:{"X-Icgd-Key":key}});
    if (res.status === 401){
      show(false);
      $("err").textContent = "That key was rejected.";
      return;
    }
    if (!res.ok) throw new Error("HTTP "+res.status);
    const d = await res.json();
    show(true);
    renderTop(d);
    renderSessions(d.sessions||[]);
    renderNotices(d.notices||[]);
    $("tick").textContent = "updated "+new Date().toLocaleTimeString();
  } catch (e) {
    $("tick").textContent = "unreachable: "+e.message;
  }
}
poll();
setInterval(poll, 2000);
</script>
</body>
</html>
`
