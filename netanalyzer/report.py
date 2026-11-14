"""Báo cáo HTML (plotly + jinja2)."""
import datetime as dt

import plotly.express as px
from jinja2 import Template

from . import stats

TPL = Template("""<!doctype html><html lang="vi"><head><meta charset="utf-8"><title>{{ title }}</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1100px;color:#222;padding:0 1rem}
.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:#f4f6f8;border-radius:8px;padding:.8rem 1.2rem}
.card b{display:block;font-size:1.4rem}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}th{background:#eef1f4}
.high{background:#fde2e2}.medium{background:#fff1d6}.low{background:#e7f3e7}
h2{margin-top:2rem}
</style></head><body>
<h1>{{ title }}</h1><p>Nguồn: <code>{{ source }}</code> · tạo lúc {{ now }}</p>
<div class="cards">{% for k,v in summary %}<div class="card">{{ k }}<b>{{ v }}</b></div>{% endfor %}
<div class="card">Cảnh báo<b>{{ alerts|length }}</b></div>
<div class="card">TCP retransmission<b>{{ retrans }}</b></div>
<div class="card">RTT handshake TB<b>{{ rtt }}</b></div></div>
<h2>Cảnh báo</h2>
{% if alerts %}<table><tr><th>Thời điểm (UTC)</th><th>Loại</th><th>Mức</th><th>Đối tượng</th><th>Chi tiết</th></tr>
{% for a in alerts %}<tr class="{{ a.severity }}"><td>{{ a.when }}</td><td>{{ a.type }}</td><td>{{ a.severity }}</td>
<td>{{ a.who }}</td><td>{{ a.detail }}</td></tr>{% endfor %}</table>
{% else %}<p>Không phát hiện bất thường.</p>{% endif %}
<h2>Biểu đồ</h2>{% for d in divs %}{{ d|safe }}{% endfor %}
</body></html>""", autoescape=True)


def _who(a):
    for k in ("src_ip", "ip"):
        if a.get(k):
            return a[k]
    if a.get("servers"):
        return ", ".join(a["servers"])
    return a.get("top_src_mac", "")


def build_report(df, alerts, policy=None, out="report.html", title="Báo cáo phân tích traffic",
                 source="", offline_js=False):
    policy = policy or {}
    d = stats.add_vlan_eff(df, policy.get("vlan_subnets", {}))
    figs = []
    pr = stats.proto_dist(d).rename_axis("proto").reset_index(name="packets")
    figs.append(px.pie(pr, names="proto", values="packets", title="Phân bố giao thức"))
    tl = stats.traffic_timeline(d).reset_index()
    f = px.line(tl, x="time", y="packets", title="Gói / giây")
    pts = [(dt.datetime.fromtimestamp(a["ts"], dt.timezone.utc).replace(tzinfo=None), a["type"])
           for a in alerts if a.get("ts")]
    if pts:
        f.add_scatter(x=[p[0] for p in pts], y=[tl["packets"].max()] * len(pts), mode="markers+text",
                      text=[p[1] for p in pts], textposition="top center", name="cảnh báo",
                      marker=dict(symbol="x", size=11, color="red"))
    figs.append(f)
    figs.append(px.bar(stats.top_talkers(d).reset_index(), x="src_ip", y="bytes", title="Top talkers (bytes)"))
    v = stats.vlan_traffic(d).reset_index()
    v["vlan_eff"] = v["vlan_eff"].map(lambda x: "untagged/unknown" if x == 0 else f"VLAN {x}")
    figs.append(px.bar(v, x="vlan_eff", y="bytes", title="Lưu lượng theo VLAN", labels={"vlan_eff": "VLAN"}))
    h = stats.pkt_size_hist(d).rename_axis("khoảng").reset_index(name="packets")
    h["khoảng"] = h["khoảng"].astype(str)
    figs.append(px.bar(h, x="khoảng", y="packets", title="Phân bố kích thước gói (byte)"))
    rtt = stats.tcp_handshake_rtt(d)
    if not rtt.empty:
        figs.append(px.histogram(rtt, x="rtt_ms", nbins=30, title="TCP handshake RTT (ms)"))
    divs = [x.to_html(full_html=False, include_plotlyjs=(True if offline_js else "cdn") if i == 0 else False)
            for i, x in enumerate(figs)]
    rows = [{**a, "who": _who(a),
             "when": dt.datetime.fromtimestamp(a["ts"], dt.timezone.utc).strftime("%H:%M:%S") if a.get("ts") else ""}
            for a in alerts]
    s = stats.summary(d)
    html = TPL.render(title=title, source=source, now=dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
                      summary=[("Gói", s["packets"]), ("Byte", s["bytes"]), ("Thời lượng (s)", s["duration_s"]),
                               ("Gói/s TB", s["avg_pps"])],
                      alerts=rows, divs=divs, retrans=f"{stats.retransmission_rate(d) * 100:.2f}%",
                      rtt=f"{rtt['rtt_ms'].mean():.2f} ms" if not rtt.empty else "n/a")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out
