import sys, time, socket, threading, queue, json, ctypes, ipaddress, urllib.request, psutil
from pathlib import Path
from collections import defaultdict
from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP
from PySide6.QtWidgets import (QApplication, QWidget, QDialog, QVBoxLayout, QHBoxLayout,
                               QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
                               QCheckBox, QLabel, QFileIconProvider)
from PySide6.QtCore import (QTimer, QFileInfo, QSize, Qt, QModelIndex,
                            QItemSelection, QItemSelectionModel)
from PySide6.QtGui import QIcon, QColor, QBrush, QKeySequence

app = QApplication(sys.argv)
provider = QFileIconProvider()

RECENT_TTL = 15
GRACE = 1.5
GEO_URL = "http://ip-api.com/batch?fields=status,country,countryCode"
HIST_FILE = Path(__file__).with_name("known_countries.json")
LOCAL_NET = "Local network"
UNKNOWN_COUNTRY = "Unknown"
PLACEHOLDERS = (LOCAL_NET, "…", "—", UNKNOWN_COUNTRY)
FLAG_COLOR = QColor(255, 224, 178)

UNKNOWN = (-1, 0)
ICMP_KEY = (-2, 0)


def norm(addr):
    try:
        return str(ipaddress.ip_address(addr.split("%")[0]))
    except ValueError:
        return addr


def get_local_ips():
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(norm(a.address))
    return ips


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def load_hist():
    try:
        data = json.loads(HIST_FILE.read_text(encoding="utf-8"))
        return {k: set(v) for k, v in data.items()}
    except Exception:
        return {}


def save_hist():
    try:
        HIST_FILE.write_text(
            json.dumps({k: sorted(v) for k, v in KNOWN.items()}, ensure_ascii=False, indent=1),
            encoding="utf-8")
    except Exception:
        pass


def new_stat():
    return {"sent": 0, "recv": 0, "ips": defaultdict(lambda: [0, 0])}


LOCAL_IPS = get_local_ips()
STATS = defaultdict(new_stat)
LOCK = threading.Lock()
PENDING = []
PORT_MAP = {}
RECENT = {}
SERVICES = {}
SETTINGS = {"geo": True}
BASELINE = load_hist()
KNOWN = {k: set(v) for k, v in BASELINE.items()}

GEO = {}
GEO_QUEUE = set()
GEO_BUSY = set()
GEO_LOCK = threading.Lock()
RDNS = {}
RDNS_SUBMITTED = set()
RDNS_Q = queue.Queue()

PROCS = {
    UNKNOWN: {"name": "Unmatched traffic",
              "icon": provider.icon(QFileIconProvider.IconType.Network), "ok": True},
    ICMP_KEY: {"name": "Ping / portless traffic (ICMP etc.)",
               "icon": provider.icon(QFileIconProvider.IconType.Network), "ok": True},
}
SPECIAL_TIPS = {
    UNKNOWN: "Packets whose owner could not be found: very short-lived connections "
             "(closed before they ever appeared in the connection list) and some system traffic.",
    ICMP_KEY: "Packets without a port (ping/ICMP etc.). Windows does not provide "
              "process information for these.",
}
COLS = ["App", "PID (App)", "Sent", "Received", "Countries",
        "IP addresses (top traffic)", "Status"]


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def fmt(b):
    if b >= 1073741824:
        return f"{b / 1073741824:.2f} GB"
    if b >= 1048576:
        return f"{b / 1048576:.2f} MB"
    return f"{b / 1024:.1f} KB"


def make_icon(path):
    pm = provider.icon(QFileInfo(path)).pixmap(QSize(64, 64))
    return None if pm.isNull() else QIcon(pm)


def resolve(pid):
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None
    try:
        ct = p.create_time()
    except psutil.Error:
        ct = 0
    key = (pid, ct)
    info = PROCS.get(key)
    if info and info["ok"]:
        return key
    name = info["name"] if info else f"PID {pid}"
    icon, ok = None, False
    try:
        name = p.name()
        icon = make_icon(p.exe())
        ok = icon is not None
    except psutil.Error:
        pass
    PROCS[key] = {"name": name,
                  "icon": icon or provider.icon(QFileIconProvider.IconType.File),
                  "ok": ok}
    return key


def refresh_ports():
    global PORT_MAP
    now = time.time()
    cur, seen = {}, {}
    for c in psutil.net_connections(kind="inet"):
        if c.pid and c.laddr:
            if c.pid not in seen:
                seen[c.pid] = resolve(c.pid)
            if seen[c.pid]:
                proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
                cur[(proto, c.laddr.port)] = seen[c.pid]

    for k, key in cur.items():
        RECENT[k] = (key, now)
    for k in [k for k, v in RECENT.items() if now - v[1] >= RECENT_TTL]:
        del RECENT[k]

    merged = {k: v[0] for k, v in RECENT.items()}
    merged.update(cur)
    PORT_MAP = merged


def refresh_services():
    global SERVICES
    m = defaultdict(list)
    try:
        for s in psutil.win_service_iter():
            try:
                pid = s.pid()
                if pid:
                    m[pid].append(s.name())
            except psutil.Error:
                pass
    except Exception:
        pass
    SERVICES = m


def refresh_local_ips():
    global LOCAL_IPS
    LOCAL_IPS = get_local_ips()


def add_stats(key, size, ip, d):
    with LOCK:
        s = STATS[key]
        s["sent" if d == 0 else "recv"] += size
        s["ips"][ip][d] += size


def on_packet(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        src, dst = norm(pkt[IPv6].src), norm(pkt[IPv6].dst)
    else:
        return
    if src.startswith("127.") or dst.startswith("127.") or src == "::1" or dst == "::1":
        return
    src_local = src in LOCAL_IPS
    dst_local = dst in LOCAL_IPS
    if src_local == dst_local:
        return

    d = 0 if src_local else 1
    remote = dst if d == 0 else src
    size = len(pkt)
    if TCP in pkt:
        proto, port = "tcp", (pkt[TCP].sport if d == 0 else pkt[TCP].dport)
    elif UDP in pkt:
        proto, port = "udp", (pkt[UDP].sport if d == 0 else pkt[UDP].dport)
    else:
        add_stats(ICMP_KEY, size, remote, d)
        return

    key = PORT_MAP.get((proto, port))
    if key:
        add_stats(key, size, remote, d)
    else:
        with LOCK:
            PENDING.append((time.time(), proto, port, size, remote, d))


def attribute_pending():
    global PENDING
    now = time.time()
    with LOCK:
        pend, PENDING = PENDING, []
    keep = []
    for item in pend:
        t, proto, port, size, remote, d = item
        key = PORT_MAP.get((proto, port))
        if key:
            add_stats(key, size, remote, d)
        elif now - t < GRACE:
            keep.append(item)
        else:
            add_stats(UNKNOWN, size, remote, d)
    if keep:
        with LOCK:
            PENDING = keep + PENDING


def rdns_worker():
    while True:
        ip = RDNS_Q.get()
        try:
            RDNS[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            RDNS[ip] = ""


def geo_worker():
    while True:
        time.sleep(5)
        if not SETTINGS["geo"]:
            continue
        with GEO_LOCK:
            batch = list(GEO_QUEUE)[:100]
            GEO_QUEUE.difference_update(batch)
            GEO_BUSY.update(batch)
        if not batch:
            continue
        ok = False
        try:
            req = urllib.request.Request(
                GEO_URL, data=json.dumps(batch).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                res = json.loads(r.read().decode("utf-8"))
            for ip, item in zip(batch, res):
                if item.get("status") == "success":
                    GEO[ip] = f"{item.get('country', '?')} ({item.get('countryCode', '?')})"
                else:
                    GEO[ip] = UNKNOWN_COUNTRY
            ok = True
        except Exception:
            pass
        with GEO_LOCK:
            GEO_BUSY.difference_update(batch)
            if not ok:
                GEO_QUEUE.update(batch)
        if not ok:
            time.sleep(60)


def request_info(ip):
    if not is_public(ip):
        return
    if ip not in RDNS and ip not in RDNS_SUBMITTED:
        RDNS_SUBMITTED.add(ip)
        RDNS_Q.put(ip)
    if SETTINGS["geo"] and ip not in GEO:
        with GEO_LOCK:
            if ip not in GEO_BUSY:
                GEO_QUEUE.add(ip)


def country_of(ip):
    if not is_public(ip):
        return LOCAL_NET
    g = GEO.get(ip)
    if g:
        return g
    return "…" if SETTINGS["geo"] else "—"


def host_of(ip):
    if not is_public(ip):
        return "—"
    if ip in RDNS:
        return RDNS[ip] or "—"
    return "…"


def label(key):
    name = PROCS[key]["name"]
    svcs = SERVICES.get(key[0])
    if svcs and name.lower() == "svchost.exe":
        name += " (" + ", ".join(svcs[:3]) + (" …" if len(svcs) > 3 else "") + ")"
    return name


def top_ips(ips, n=3):
    order = sorted(ips.items(), key=lambda x: -(x[1][0] + x[1][1]))
    text = ", ".join(ip for ip, _ in order[:n])
    if len(order) > n:
        text += f" … (+{len(order) - n})"
    return text


class CopyTable(QTableWidget):
    def __init__(self, rows, cols, parent=None):
        super().__init__(rows, cols, parent)
        self.row_keys = []
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_selection()
            return
        super().keyPressEvent(event)

    def copy_selection(self):
        idx = sorted(self.selectedIndexes(), key=lambda i: (i.row(), i.column()))
        if not idx:
            return
        rows = {}
        for i in idx:
            rows.setdefault(i.row(), []).append(str(i.data() or ""))
        QApplication.clipboard().setText("\n".join("\t".join(v) for v in rows.values()))

    def snapshot_selection(self):
        sm = self.selectionModel()
        n = self.rowCount()
        full = {c for c in range(self.columnCount())
                if n and sm.isColumnSelected(c, QModelIndex())}
        cells = {(self.row_keys[i.row()], i.column())
                 for i in sm.selectedIndexes()
                 if i.row() < len(self.row_keys) and i.column() not in full}
        return cells, full

    def restore_selection(self, snap):
        cells, full = snap
        n = self.rowCount()
        if (not cells and not full) or not n:
            return
        model = self.model()
        sel = QItemSelection()
        for c in full:
            sel.select(model.index(0, c), model.index(n - 1, c))
        pos = {k: r for r, k in enumerate(self.row_keys)}
        for k, c in cells:
            r = pos.get(k)
            if r is not None:
                idx = model.index(r, c)
                sel.select(idx, idx)
        self.selectionModel().select(sel, QItemSelectionModel.SelectionFlag.ClearAndSelect)


class DetailDialog(QDialog):
    def __init__(self, key, parent=None):
        super().__init__(parent)
        self.key = key
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"IP details - {label(key)}")
        self.resize(950, 480)
        layout = QVBoxLayout(self)
        self.info = QLabel()
        self.table = CopyTable(0, 5)
        self.table.setHorizontalHeaderLabels(["IP", "Domain", "Country", "Sent", "Received"])
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.info)
        layout.addWidget(self.table)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        self.refresh()

    def refresh(self):
        if QApplication.mouseButtons() != Qt.MouseButton.NoButton:
            return
        with LOCK:
            s = STATS.get(self.key)
            if s is None:
                return
            ips = {ip: tuple(v) for ip, v in s["ips"].items()}
            sent, recv = s["sent"], s["recv"]

        lname = PROCS[self.key]["name"].lower()
        known = BASELINE.get(lname)
        order = sorted(ips.items(), key=lambda x: -(x[1][0] + x[1][1]))
        self.info.setText(f"{label(self.key)}   |   Total sent: {fmt(sent)}   |   "
                          f"Total received: {fmt(recv)}   |   {len(ips)} unique IPs")

        snap = self.table.snapshot_selection()
        self.table.setRowCount(len(order))
        self.table.row_keys = [ip for ip, _ in order]
        for i, (ip, (s_b, r_b)) in enumerate(order):
            request_info(ip)
            country = country_of(ip)
            cells = [QTableWidgetItem(ip), QTableWidgetItem(host_of(ip)),
                     QTableWidgetItem(country), QTableWidgetItem(fmt(s_b)),
                     QTableWidgetItem(fmt(r_b))]
            if (SETTINGS["geo"] and known is not None
                    and country not in PLACEHOLDERS and country not in known):
                for c in cells:
                    c.setBackground(QBrush(FLAG_COLOR))
                    c.setForeground(QBrush(QColor(0, 0, 0)))
                cells[2].setToolTip("This app has not connected to this country before")
            for j, c in enumerate(cells):
                self.table.setItem(i, j, c)
        self.table.restore_selection(snap)


class MonitorWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.base_title = "Network Monitor"
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search: app, PID, IP, domain, country...")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.refresh)
        self.geo_box = QCheckBox("Look up country (sends IPs to ip-api.com)")
        self.geo_box.setChecked(True)
        self.geo_box.toggled.connect(lambda v: SETTINGS.update(geo=v))
        top.addWidget(self.search, 1)
        top.addWidget(self.geo_box)

        self.table = CopyTable(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        hdr = self.table.horizontalHeader()
        for c in range(len(COLS)):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.setIconSize(QSize(32, 32))
        self.table.cellDoubleClicked.connect(self.open_detail)

        footer = QLabel("Created by: BayFearless")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color: gray; padding: 4px;")

        layout.addLayout(top)
        layout.addWidget(self.table)
        layout.addWidget(footer)

        self.t1 = QTimer(self); self.t1.timeout.connect(self.tick);    self.t1.start(250)
        self.t2 = QTimer(self); self.t2.timeout.connect(self.refresh); self.t2.start(1000)
        self.t3 = QTimer(self); self.t3.timeout.connect(self.slow);    self.t3.start(5000)
        self.t4 = QTimer(self); self.t4.timeout.connect(save_hist);    self.t4.start(60000)

    def tick(self):
        refresh_ports()
        attribute_pending()

    def slow(self):
        refresh_services()
        refresh_local_ips()

    def open_detail(self, row, col):
        if 0 <= row < len(self.table.row_keys):
            DetailDialog(self.table.row_keys[row], self).show()

    def refresh(self, *_):
        if QApplication.mouseButtons() != Qt.MouseButton.NoButton:
            return
        with LOCK:
            data = {k: (s["sent"], s["recv"], {ip: tuple(v) for ip, v in s["ips"].items()})
                    for k, s in STATS.items()}
        for _, _, ips in data.values():
            for ip in ips:
                request_info(ip)

        by_pid = defaultdict(list)
        for pid, ct in data:
            by_pid[pid].append(PROCS[(pid, ct)]["name"])

        total = sum(v[0] + v[1] for v in data.values())
        unk = (data[UNKNOWN][0] + data[UNKNOWN][1]) if UNKNOWN in data else 0

        q = self.search.text().strip().lower()
        rows = []
        flagged_count = 0
        for key, (sent, recv, ips) in data.items():
            pid = key[0]
            name = PROCS[key]["name"]
            special = pid < 0
            labels = {country_of(ip) for ip in ips}
            real = sorted(l for l in labels if l not in PLACEHOLDERS)

            new = set()
            flagged = False
            if not special and SETTINGS["geo"]:
                lname = name.lower()
                KNOWN.setdefault(lname, set()).update(real)
                new = set(real) - BASELINE.get(lname, set())
                flagged = lname in BASELINE and bool(new)
            if flagged:
                flagged_count += 1

            if real:
                ctext = ", ".join(real[:3]) + (" …" if len(real) > 3 else "")
            else:
                ctext = next((l for l in (LOCAL_NET, "…") if l in labels), "—")

            pid_text = "—" if special else f"{pid} ({name})"
            shared = len(by_pid[pid]) > 1
            status = []
            if flagged:
                status.append("⚠ New country")
            if shared:
                status.append("↻ PID reused")

            ip_text = top_ips(ips)
            hay = " ".join([label(key), pid_text, ctext, ip_text, " ".join(ips),
                            " ".join(host_of(ip) for ip in ips)]).lower()
            if q and q not in hay:
                continue
            rows.append({"key": key, "label": label(key), "pid_text": pid_text,
                         "sent": sent, "recv": recv, "ctext": ctext, "ip_text": ip_text,
                         "flagged": flagged, "new": new, "shared": shared,
                         "special": special, "status": "  ".join(status),
                         "pid": pid, "total": sent + recv})

        rows.sort(key=lambda r: -r["total"])

        title = self.base_title
        if total:
            title += f"  |  unmatched: {unk * 100 / total:.0f}%"
        if flagged_count:
            title += f"  |  suspicious: {flagged_count}"
        self.setWindowTitle(title)

        snap = self.table.snapshot_selection()
        self.table.setRowCount(len(rows))
        self.table.row_keys = [r["key"] for r in rows]
        for i, r in enumerate(rows):
            cells = [QTableWidgetItem(PROCS[r["key"]]["icon"], r["label"]),
                     QTableWidgetItem(r["pid_text"]),
                     QTableWidgetItem(fmt(r["sent"])),
                     QTableWidgetItem(fmt(r["recv"])),
                     QTableWidgetItem(r["ctext"]),
                     QTableWidgetItem(r["ip_text"]),
                     QTableWidgetItem(r["status"])]
            if r["special"]:
                cells[0].setToolTip(SPECIAL_TIPS[r["key"]])
            if r["shared"]:
                cells[6].setToolTip("This PID has been used by different apps: "
                                    + ", ".join(by_pid[r["pid"]]))
            if r["flagged"]:
                cells[6].setToolTip("This app has not connected to these countries before: "
                                    + ", ".join(sorted(r["new"])))
                for c in cells:
                    c.setBackground(QBrush(FLAG_COLOR))
                    c.setForeground(QBrush(QColor(0, 0, 0)))
            for j, c in enumerate(cells):
                self.table.setItem(i, j, c)
            self.table.setRowHeight(i, 40)
        self.table.restore_selection(snap)


refresh_ports()
refresh_services()
threading.Thread(target=geo_worker, daemon=True).start()
for _ in range(6):
    threading.Thread(target=rdns_worker, daemon=True).start()

sniffer = AsyncSniffer(prn=on_packet, store=False)
sniffer.start()

w = MonitorWindow()
if not is_admin():
    w.base_title += "  -  NOT ADMIN: data may be incomplete"
w.setWindowTitle(w.base_title)
w.resize(1250, 600)
w.show()

app.aboutToQuit.connect(save_hist)
code = app.exec()
try:
    sniffer.stop()
except Exception:
    pass
sys.exit(code)