#!/usr/bin/env python3
"""
warmap.py — Plataforma SIGINT & Analizador de Capturas JSONL de Wardrive.

- Resuelve fabricantes mediante la base de datos IEEE OUI completa (40.355 prefijos,
  `oui_es_db.json.gz`), incluyendo todos los fabricantes de móviles, routers de
  operadoras españolas (Movistar, Orange, Vodafone, Digi, MásMóvil) e IoT, más
  detección de BSSIDs virtuales (bit LAA invertido sobre OUI real) y MACs aleatorias.
- Correlaciona Redes (APs / SSIDs), Dispositivos Clientes (STAs + PNL Probe Requests),
  Persistencia Multi-Sesión, GPS vinculado a la sesión y etiquetas custom (`tags.json`).
- Genera informes en terminal, CSV, WiGLE CSV v1.4 y la Consola Web SIGINT (`--html`).
"""

import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import gzip
import json
from pathlib import Path
import struct
import sys

from pcap_audit import TRACE_ORDER, inspect_pcap_files
from ui_template import render_sigint_dashboard

_OUI_DB = None


def _load_oui_db() -> dict:
    global _OUI_DB
    if _OUI_DB is not None:
        return _OUI_DB
    db_path = Path(__file__).resolve().parent / "oui_es_db.json.gz"
    if db_path.exists():
        try:
            with gzip.open(db_path, "rt", encoding="utf-8") as gz:
                _OUI_DB = json.load(gz)
                return _OUI_DB
        except Exception:
            pass
    _OUI_DB = {}
    return _OUI_DB


def is_randomized_mac(mac: str) -> bool:
    """Devuelve True si tiene el bit Locally-Administered activo y NO corresponde a un BSSID virtual de un OUI real."""
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) < 6:
        return False
    db = _load_oui_db()
    p6 = clean[:6]
    if p6 in db:
        return False
    b0 = int(p6[:2], 16)
    if (b0 & 0x02) == 0:
        return False
    # Comprobar si los 2 bytes centrales del OUI coinciden con algún OUI real cuando el router
    # crea un BSSID virtual modificando el primer octeto (Arcadyan, Sagemcom, ZTE, TP-Link, etc.)
    for mask in (0x00, 0x04, 0x08, 0x0C, 0x10, 0x20, 0x40, 0x80, 0xC0, 0xCE):
        cand_b0 = (b0 & ~0x02) ^ mask
        if f"{cand_b0:02X}{p6[2:]}" in db:
            return False
    return True


def resolve_vendor(mac: str) -> str:
    clean = mac.replace(":", "").replace("-", "").upper()
    if len(clean) < 6:
        return "Desconocido"
    db = _load_oui_db()
    p6 = clean[:6]
    if p6 in db and db[p6] != "Private":
        return db[p6]
    b0 = int(p6[:2], 16)
    if b0 & 0x02:
        # Muchos routers (Arcadyan, ZTE, Sagemcom, TP-Link, Xiaomi) crean BSSIDs virtuales
        # activando el bit 0x02 (LAA) y variando el nibble superior del primer octeto:
        for mask in (0x00, 0x04, 0x08, 0x0C, 0x10, 0x20, 0x40, 0x80, 0xC0, 0xCE):
            cand_b0 = (b0 & ~0x02) ^ mask
            cand = f"{cand_b0:02X}{p6[2:]}"
            if cand in db and db[cand] != "Private":
                return f"{db[cand]} (Virtual)"
        return "MAC Aleatoria (iOS/Android Privacy)"
    if p6 in db:
        return db[p6]
    return "OUI No Registrado"


def load_tags_file(paths) -> tuple[dict, Path]:
    """Busca `tags.json` en el directorio de los JSONL o en `./wardrive_data/tags.json`."""
    candidates = []
    if paths:
        candidates.append(paths[0].resolve().parent / "tags.json")
    candidates.extend([
        Path("./wardrive_data/tags.json"),
        Path("/home/Kta41/wardrive/wardrive_data/tags.json"),
    ])
    for c in candidates:
        if c.exists():
            try:
                data = json.loads(c.read_text(encoding="utf-8"))
                return {
                    "sessions": data.get("sessions", {}),
                    "networks": data.get("networks", {}),
                    "devices": data.get("devices", {}),
                }, c
            except Exception:
                pass
    default_path = candidates[0] if candidates else Path("./wardrive_data/tags.json")
    return {"sessions": {}, "networks": {}, "devices": {}}, default_path


TRACE_ORDER = ["EAPOL", "DEAUTH", "ASSOC", "AUTH", "PROBE_REQ", "PROBE_RESP", "ACTION", "BEACON"]


def _fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def _is_mcast_or_zero(b: bytes) -> bool:
    if not b or len(b) < 6:
        return True
    if (b[0] & 0x01) != 0:
        return True
    return b == b"\x00\x00\x00\x00\x00\x00"


def _parse_pcap_file_into(pcap_path: Path, ap_pcap_traces, ap_pcap_frames, sta_pcap_traces, sta_pcap_frames, promisc_totals):
    """Inspecciona un archivo .pcap (DLT 127 Radiotap o DLT 105 802.11) y atribuye trazas a BSSIDs y STAs."""
    try:
        data = pcap_path.read_bytes()
    except Exception:
        return 0
    if len(data) < 24:
        return 0

    magic, vmaj, vmin, tz, sigfigs, snaplen, dlt = struct.unpack_from("<IHHiIII", data, 0)
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        return 0

    pos = 24
    total_len = len(data)
    pkts = 0

    while pos + 16 <= total_len:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from("<IIII", data, pos)
        pos += 16
        if incl_len == 0 or pos + incl_len > total_len:
            break
        pkt = data[pos : pos + incl_len]
        pos += incl_len

        if dlt == 127:  # Radiotap
            if len(pkt) < 8:
                continue
            rtap_len = struct.unpack_from("<H", pkt, 2)[0]
            if rtap_len >= len(pkt):
                continue
            dot11 = pkt[rtap_len:]
        elif dlt == 105:  # IEEE 802.11
            dot11 = pkt
        else:
            continue

        if len(dot11) < 24:
            continue

        pkts += 1
        fc0 = dot11[0]
        fc1 = dot11[1]
        ftype = (fc0 >> 2) & 0x03
        subtype = (fc0 >> 4) & 0x0F
        addr1 = dot11[4:10]
        addr2 = dot11[10:16]
        addr3 = dot11[16:22]

        trace_type = None
        bssid = None
        sta = None

        if ftype == 0x00:  # MGMT
            if subtype == 0x08:
                trace_type = "BEACON"
                bssid = addr3
            elif subtype == 0x04:
                trace_type = "PROBE_REQ"
                sta = addr2
            elif subtype == 0x05:
                trace_type = "PROBE_RESP"
                bssid = addr3
                sta = addr1
            elif subtype in (0x00, 0x02):
                trace_type = "ASSOC"
                bssid = addr1
                sta = addr2
            elif subtype in (0x01, 0x03):
                trace_type = "ASSOC"
                bssid = addr3
                sta = addr1
            elif subtype == 0x0B:
                trace_type = "AUTH"
                bssid = addr3
                sta = addr2 if addr1 == addr3 else addr1
            elif subtype in (0x0A, 0x0C):
                trace_type = "DEAUTH"
                bssid = addr3
                sta = addr2 if addr1 == addr3 else addr1
            elif subtype == 0x0D:
                trace_type = "ACTION"
                bssid = addr3
                sta = addr2 if addr1 == addr3 else addr1
        elif ftype == 0x02:  # DATA
            to_ds = (fc1 & 0x01) != 0
            from_ds = (fc1 & 0x02) != 0
            if to_ds and not from_ds:
                bssid = addr1
                sta = addr2
            elif not to_ds and from_ds:
                sta = addr1
                bssid = addr2
            if b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" in dot11[24:44]:
                trace_type = "EAPOL"
            else:
                trace_type = "DATA"

        if not trace_type:
            continue

        if bssid and not _is_mcast_or_zero(bssid):
            b_str = _fmt_mac(bssid)
            ap_pcap_traces[b_str].add(trace_type)
            ap_pcap_frames[b_str] += 1

        if sta and not _is_mcast_or_zero(sta) and sta != bssid:
            s_str = _fmt_mac(sta)
            sta_pcap_traces[s_str].add(trace_type)
            sta_pcap_frames[s_str] += 1

    return pkts


def load_records(paths):
    aps = {}
    sightings = Counter()
    ap_sessions = defaultdict(set)
    sessions_meta = {}
    session_aps = defaultdict(set)
    session_clients = defaultdict(set)
    total_scans = 0
    first_seen = {}

    clients_by_bssid = defaultdict(dict)  # bssid -> {sta_mac: info}
    probes_by_sta = defaultdict(set)      # sta_mac -> {ssid, ...}
    probe_best = {}                       # (sta_mac, ssid) -> info
    devices = {}                          # sta_mac -> aggregated device dossier
    promisc_totals = Counter()
    ap_pcap_traces = defaultdict(set)     # bssid -> {"BEACON", "EAPOL", ...}
    ap_pcap_frames = Counter()            # bssid -> count
    sta_pcap_traces = defaultdict(set)    # sta_mac -> {"PROBE_REQ", "EAPOL", ...}
    sta_pcap_frames = Counter()           # sta_mac -> count
    session_assoc = defaultdict(dict)     # sid -> {(sta, bssid): {"frames": int, "rssi": int, "channel": int, "traces": set}}
    session_probes = defaultdict(dict)    # sid -> {(sta, pssid): {"count": int, "rssi": int, "channel": int}}
    session_sta_info = defaultdict(dict)  # sid -> {sta: {"rssi": int, "channel": int}}
    session_ap_info = defaultdict(dict)   # sid -> {bssid: {"rssi": int, "channel": int, "ssid": str, "hidden": bool}}
    ble_devices = {}                      # mac BLE -> censo global {"type", "rssi", "name", "count", "sessions"}
    session_ble = defaultdict(lambda: {"unique_max": 0, "adv_frames": 0, "ibeacon": 0, "eddystone": 0, "findmy_candidates": 0, "other": 0})

    def ensure_device(sta_mac: str, rssi: int, ch: int, sid: str):
        sta = sta_mac.upper()
        d = devices.get(sta)
        if d is None:
            d = {
                "sta_mac": sta,
                "vendor": resolve_vendor(sta),
                "is_randomized": is_randomized_mac(sta),
                "rssi": rssi,
                "channel": ch,
                "total_frames": 0,
                "sessions": set(),
                "associated_bssids": set(),
                "probed_ssids": set(),
                "pcap_traces": set(),
            }
            devices[sta] = d
        else:
            if rssi > d["rssi"]:
                d["rssi"] = rssi
                d["channel"] = ch
        d["sessions"].add(sid)
        session_clients[sid].add(sta)
        return d

    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                recv_at = obj.get("recv_at", "1970-01-01T00:00:00") if isinstance(obj, dict) else "1970-01-01T00:00:00"
                gps = obj.get("gps") if isinstance(obj, dict) else None
                env_sname = obj.get("session_name") if isinstance(obj, dict) else None
                payload = obj.get("payload", obj)
                if not isinstance(payload, dict) or payload.get("mode") != "scan":
                    continue

                total_scans += 1
                sid = payload.get("session_id", "unknown")
                ts_short = recv_at[:19].replace("T", " ")

                smeta = sessions_meta.get(sid)
                if smeta is None:
                    smeta = {
                        "session_id": sid,
                        "name": env_sname,
                        "file": path.name,
                        "first_seen": ts_short,
                        "last_seen": ts_short,
                        "scans": 0,
                        "gps": gps if isinstance(gps, dict) else None,
                    }
                    sessions_meta[sid] = smeta
                smeta["scans"] += 1
                smeta["last_seen"] = ts_short
                if smeta["gps"] is None and isinstance(gps, dict):
                    smeta["gps"] = gps
                if not smeta.get("name") and env_sname:
                    smeta["name"] = env_sname

                for dev in payload.get("devices", []):
                    bssid = dev.get("bssid", "").upper()
                    if not bssid:
                        continue
                    sightings[bssid] += 1
                    ap_sessions[bssid].add(sid)
                    session_aps[sid].add(bssid)
                    d_rssi = int(dev.get("rssi", -128))
                    d_ch = int(dev.get("primary_channel", 0))
                    d_ssid = dev.get("ssid", "")
                    d_hid = bool(dev.get("hidden"))
                    cur_ap_s = session_ap_info[sid].get(bssid)
                    if cur_ap_s is None or d_rssi > cur_ap_s["rssi"]:
                        session_ap_info[sid][bssid] = {
                            "rssi": d_rssi,
                            "channel": d_ch,
                            "ssid": d_ssid or (cur_ap_s["ssid"] if cur_ap_s else ""),
                            "hidden": d_hid if not d_ssid else False,
                        }
                    elif d_ssid and not cur_ap_s.get("ssid"):
                        cur_ap_s["ssid"] = d_ssid
                        cur_ap_s["hidden"] = False
                    if bssid not in first_seen:
                        first_seen[bssid] = ts_short
                    if bssid not in aps or dev.get("rssi", -128) > aps[bssid]["rssi"]:
                        entry = dict(dev)
                        entry["bssid"] = bssid
                        if isinstance(gps, dict):
                            entry["gps"] = gps
                        aps[bssid] = entry
                    elif not aps[bssid].get("ssid") and dev.get("ssid"):
                        aps[bssid]["ssid"] = dev["ssid"]
                        aps[bssid]["hidden"] = False

                # Fusión BLE (BLE-Recon integrado en el sensor): censo global de
                # dispositivos BLE + agregados por sesión para correlación WiFi↔BLE.
                ble_blk = payload.get("ble")
                if isinstance(ble_blk, dict):
                    sble = session_ble[sid]
                    sble["unique_max"] = max(sble["unique_max"], int(ble_blk.get("unique_devices", 0)))
                    sble["adv_frames"] += int(ble_blk.get("adv_frames", 0))
                    for k in ("ibeacon", "eddystone", "findmy_candidates", "other"):
                        sble[k] = max(sble[k], int(ble_blk.get(k, 0)))
                    for bd in ble_blk.get("devices", []):
                        mac = str(bd.get("mac", "")).upper()
                        if not mac:
                            continue
                        b_entry = ble_devices.get(mac)
                        rssi_b = int(bd.get("rssi", -128))
                        if b_entry is None:
                            ble_devices[mac] = {
                                "mac": mac,
                                "type": bd.get("type", "UNKNOWN"),
                                "addr_type": bd.get("addr_type", "?"),
                                "rssi": rssi_b,
                                "name": bd.get("name", ""),
                                "count": 1,
                                "sessions": {sid},
                            }
                        else:
                            b_entry["count"] += 1
                            b_entry["sessions"].add(sid)
                            if rssi_b > b_entry["rssi"]:
                                b_entry["rssi"] = rssi_b
                                if bd.get("name"):
                                    b_entry["name"] = bd["name"]

                prom = payload.get("promisc")
                if isinstance(prom, dict):
                    for k in ("mgmt_frames", "data_frames", "probe_req_frames", "deauth_frames", "eapol_frames", "pcap_frames", "pcap_bytes"):
                        promisc_totals[k] += int(prom.get(k, 0))
                    for ap_p in prom.get("ap_pcap", []):
                        bssid = ap_p.get("bssid", "").upper()
                        if not bssid:
                            continue
                        for tr in ap_p.get("pcap_traces", []):
                            ap_pcap_traces[bssid].add(str(tr).upper())
                        ap_pcap_frames[bssid] += int(ap_p.get("pcap_frames", 0))
                    for cl in prom.get("clients", []):
                        sta = cl.get("sta_mac", "").upper()
                        bssid = cl.get("bssid", "").upper()
                        if not sta or not bssid:
                            continue
                        rssi = int(cl.get("rssi", -128))
                        ch = int(cl.get("channel", 0))
                        frames = int(cl.get("frames", 1))

                        d_entry = ensure_device(sta, rssi, ch, sid)
                        d_entry["total_frames"] += frames
                        d_entry["associated_bssids"].add(bssid)
                        cur_sta_s = session_sta_info[sid].get(sta)
                        if cur_sta_s is None or rssi > cur_sta_s["rssi"]:
                            session_sta_info[sid][sta] = {"rssi": rssi, "channel": ch}

                        sa_entry = session_assoc[sid].get((sta, bssid))
                        if sa_entry is None:
                            sa_entry = {"frames": frames, "rssi": rssi, "channel": ch, "traces": set()}
                            session_assoc[sid][(sta, bssid)] = sa_entry
                        else:
                            sa_entry["frames"] += frames
                            if rssi > sa_entry["rssi"]:
                                sa_entry["rssi"] = rssi
                                sa_entry["channel"] = ch

                        for tr in cl.get("pcap_traces", []):
                            t_up = str(tr).upper()
                            d_entry["pcap_traces"].add(t_up)
                            sta_pcap_traces[sta].add(t_up)
                            sa_entry["traces"].add(t_up)
                            if t_up in ("EAPOL", "ASSOC", "AUTH", "DEAUTH"):
                                ap_pcap_traces[bssid].add(t_up)

                        prev = clients_by_bssid[bssid].get(sta)
                        if prev is None:
                            clients_by_bssid[bssid][sta] = {
                                "sta_mac": sta,
                                "bssid": bssid,
                                "rssi": rssi,
                                "channel": ch,
                                "frames": frames,
                            }
                        else:
                            prev["frames"] += frames
                            if rssi > prev["rssi"]:
                                prev["rssi"] = rssi
                                prev["channel"] = ch

                    for pr in prom.get("probes", []):
                        sta = pr.get("sta_mac", "").upper()
                        pssid = pr.get("ssid", "")
                        if not sta:
                            continue
                        rssi = int(pr.get("rssi", -128))
                        ch = int(pr.get("channel", 0))
                        cnt = int(pr.get("count", 1))

                        d_entry = ensure_device(sta, rssi, ch, sid)
                        d_entry["total_frames"] += cnt
                        cur_sta_s = session_sta_info[sid].get(sta)
                        if cur_sta_s is None or rssi > cur_sta_s["rssi"]:
                            session_sta_info[sid][sta] = {"rssi": rssi, "channel": ch}
                        if pssid:
                            d_entry["probed_ssids"].add(pssid)
                            probes_by_sta[sta].add(pssid)
                            sp_entry = session_probes[sid].get((sta, pssid))
                            if sp_entry is None:
                                session_probes[sid][(sta, pssid)] = {"count": cnt, "rssi": rssi, "channel": ch}
                            else:
                                sp_entry["count"] += cnt
                                if rssi > sp_entry["rssi"]:
                                    sp_entry["rssi"] = rssi
                        for tr in pr.get("pcap_traces", []):
                            t_up = str(tr).upper()
                            d_entry["pcap_traces"].add(t_up)
                            sta_pcap_traces[sta].add(t_up)

                        key = (sta, pssid)
                        prev = probe_best.get(key)
                        if prev is None:
                            probe_best[key] = {
                                "sta_mac": sta,
                                "ssid": pssid,
                                "rssi": rssi,
                                "channel": ch,
                                "count": cnt,
                            }
                        else:
                            prev["count"] += cnt
                            if rssi > prev["rssi"]:
                                prev["rssi"] = rssi

    # Inspeccionar también cualquier fichero .pcap en los mismos directorios o en
    # las subcarpetas pcap/ adyacentes para enriquecer las trazas PCAP por BSSID y STA,
    # metadatos WPS, códigos Deauth, IE-Fingerprints y handshakes EAPOL/PMKID.
    base_dirs = {p.resolve().parent for p in paths if p.exists()}
    scanned_dirs = set()
    for b_dir in base_dirs:
        scanned_dirs.add(b_dir)
        scanned_dirs.add(b_dir / "pcap")
        if b_dir.name == "jsonl":
            scanned_dirs.add(b_dir.parent)
            scanned_dirs.add(b_dir.parent / "pcap")
    pcap_files_seen = []
    seen_rp = set()
    for d_dir in sorted(scanned_dirs):
        if not d_dir.is_dir():
            continue
        for pcap_f in sorted(d_dir.glob("*.pcap")):
            rp = pcap_f.resolve()
            if rp in seen_rp:
                continue
            seen_rp.add(rp)
            pcap_files_seen.append(rp)

    deep_pcap = inspect_pcap_files(pcap_files_seen)
    for b_str, tr_set in deep_pcap["ap_pcap_traces"].items():
        ap_pcap_traces[b_str].update(tr_set)
    for b_str, cnt in deep_pcap["ap_pcap_frames"].items():
        ap_pcap_frames[b_str] = max(ap_pcap_frames[b_str], cnt)
    for s_str, tr_set in deep_pcap["sta_pcap_traces"].items():
        sta_pcap_traces[s_str].update(tr_set)
    for s_str, cnt in deep_pcap["sta_pcap_frames"].items():
        sta_pcap_frames[s_str] = max(sta_pcap_frames[s_str], cnt)

    for sta, tr_set in sta_pcap_traces.items():
        if sta in devices:
            devices[sta]["pcap_traces"].update(tr_set)

    for sid, smeta in sessions_meta.items():
        smeta["unique_aps"] = len(session_aps[sid])
        smeta["unique_clients"] = len(session_clients[sid])

    promisc_data = {
        "totals": promisc_totals,
        "clients_by_bssid": clients_by_bssid,
        "probes_by_sta": probes_by_sta,
        "probe_best": probe_best,
        "first_seen": first_seen,
        "ap_sessions": ap_sessions,
        "sessions_meta": sessions_meta,
        "devices": devices,
        "ap_pcap_traces": ap_pcap_traces,
        "ap_pcap_frames": ap_pcap_frames,
        "sta_pcap_traces": sta_pcap_traces,
        "sta_pcap_frames": sta_pcap_frames,
        "ap_wps_info": deep_pcap["ap_wps_info"],
        "ap_deauth_reasons": deep_pcap["ap_deauth_reasons"],
        "ap_eapol_msgs": deep_pcap["ap_eapol_msgs"],
        "sta_eapol_msgs": deep_pcap["sta_eapol_msgs"],
        "sta_ie_fp": deep_pcap["sta_ie_fp"],
        "handshakes": deep_pcap["handshakes"],
        "hc22000_lines": deep_pcap["hc22000_lines"],
        "ble_devices": {m: {**v, "sessions": sorted(v["sessions"])} for m, v in ble_devices.items()},
        "session_ble": dict(session_ble),
        "pcap_files": [f.name for f in pcap_files_seen],
        "session_assoc": session_assoc,
        "session_probes": session_probes,
        "session_sta_info": session_sta_info,
        "session_ap_info": session_ap_info,
    }
    return aps, sightings, set(sessions_meta.keys()), total_scans, promisc_data


def build_intelligence_dataset(aps, sightings, sessions, total_scans, promisc_data, tags_data) -> dict:
    clients_by_bssid = promisc_data["clients_by_bssid"]
    ap_sessions = promisc_data["ap_sessions"]
    sessions_meta = promisc_data["sessions_meta"]
    devices_map = promisc_data["devices"]
    ap_pcap_traces = promisc_data.get("ap_pcap_traces", {})
    ap_pcap_frames = promisc_data.get("ap_pcap_frames", {})
    sta_pcap_traces = promisc_data.get("sta_pcap_traces", {})
    sta_pcap_frames = promisc_data.get("sta_pcap_frames", {})
    ap_wps_info = promisc_data.get("ap_wps_info", {})
    ap_deauth_reasons = promisc_data.get("ap_deauth_reasons", {})
    ap_eapol_msgs = promisc_data.get("ap_eapol_msgs", {})
    sta_eapol_msgs = promisc_data.get("sta_eapol_msgs", {})
    sta_ie_fp = promisc_data.get("sta_ie_fp", {})

    def _sort_traces(tr_set):
        return sorted(tr_set, key=lambda x: TRACE_ORDER.index(x) if x in TRACE_ORDER else 99)

    # Mapear SSID -> lista de BSSIDs
    ssid_to_bssids = defaultdict(list)
    for bssid, ap in aps.items():
        if ap.get("ssid"):
            ssid_to_bssids[ap["ssid"]].append(bssid)

    # Mapear SSID -> STAs que lo buscan
    ssid_probing_stas = defaultdict(set)
    for sta, dev in devices_map.items():
        for pssid in dev["probed_ssids"]:
            ssid_probing_stas[pssid].add(sta)

    known_local_ssids = set(ssid_to_bssids.keys())

    ap_list = []
    ap_by_bssid = {}
    for bssid, d in sorted(aps.items(), key=lambda kv: kv[1]["rssi"], reverse=True):
        ssid = d.get("ssid", "")
        is_weak = (
            d["auth_mode"] in ("OPEN", "WEP", "WPA_PSK", "WPA_WPA2_PSK")
            or "TKIP" in d["pairwise_cipher"]
        )
        item = {
            "bssid": bssid,
            "ssid": ssid,
            "hidden": bool(d.get("hidden")),
            "rssi": int(d["rssi"]),
            "primary_channel": int(d["primary_channel"]),
            "band_mhz": int(d.get("band_mhz", 20)),
            "proto": d.get("proto", "bgn"),
            "auth_mode": d["auth_mode"],
            "pairwise_cipher": d["pairwise_cipher"],
            "group_cipher": d.get("group_cipher", ""),
            "wps": bool(d.get("wps")),
            "is_weak": is_weak,
            "sightings": int(sightings[bssid]),
            "vendor": resolve_vendor(bssid),
            "sessions": sorted(ap_sessions[bssid]),
            "clients": sorted(clients_by_bssid.get(bssid, {}).keys()),
            "probing_stas": sorted(ssid_probing_stas.get(ssid, set())) if ssid else [],
            "cluster_size": len(ssid_to_bssids.get(ssid, [])) if ssid else 1,
            "pcap_traces": _sort_traces(ap_pcap_traces.get(bssid, set())),
            "pcap_frames": int(ap_pcap_frames.get(bssid, 0)),
            "wps_info": ap_wps_info.get(bssid, {}),
            "deauth_reasons": ap_deauth_reasons.get(bssid, []),
            "eapol_msgs": ap_eapol_msgs.get(bssid, []),
        }
        ap_list.append(item)
        ap_by_bssid[bssid] = item

    dev_list = []
    device_by_mac = {}
    all_probed_ssids = set()
    matched_probed_ssids = set()

    for sta, d in sorted(devices_map.items(), key=lambda kv: kv[1]["rssi"], reverse=True):
        assoc_bssids = sorted(d["associated_bssids"])
        assoc_ssids = sorted({aps[b]["ssid"] for b in assoc_bssids if b in aps and aps[b].get("ssid")})
        probed = sorted(d["probed_ssids"])
        matched_local = [s for s in probed if s in known_local_ssids]
        all_probed_ssids.update(probed)
        matched_probed_ssids.update(matched_local)

        item = {
            "sta_mac": sta,
            "vendor": d["vendor"],
            "is_randomized": d["is_randomized"],
            "rssi": int(d["rssi"]),
            "channel": int(d["channel"]),
            "total_frames": int(d["total_frames"]),
            "sessions": sorted(d["sessions"]),
            "associated_bssids": assoc_bssids,
            "associated_ssids": assoc_ssids,
            "probed_ssids": probed,
            "matched_local_ssids": matched_local,
            "pcap_traces": _sort_traces(d.get("pcap_traces", set()) | sta_pcap_traces.get(sta, set())),
            "pcap_frames": int(sta_pcap_frames.get(sta, 0)),
            "ie_fingerprint": sta_ie_fp.get(sta, ""),
            "eapol_msgs": sta_eapol_msgs.get(sta, []),
        }
        dev_list.append(item)
        device_by_mac[sta] = item

    ch_counts = Counter(a["primary_channel"] for a in ap_list)
    auth_counts = Counter(a["auth_mode"] for a in ap_list)

    ssid_collisions = []
    evil_twin_alerts = []
    for ssid, bssids in sorted(ssid_to_bssids.items(), key=lambda kv: len(kv[1]), reverse=True):
        if len(bssids) < 2:
            continue
        b_sorted = sorted(bssids)
        auth_set = {aps[b]["auth_mode"] for b in b_sorted if b in aps}
        vendors_set = {resolve_vendor(b).split("(")[0].strip() for b in b_sorted}
        has_deauth = any("DEAUTH" in ap_pcap_traces.get(b, set()) for b in b_sorted)
        reasons = []
        severity = "INFO"
        if len(auth_set) > 1:
            if "OPEN" in auth_set:
                severity = "CRITICAL"
                reasons.append(f"Downgrade a red ABIERTA detectado ({', '.join(sorted(auth_set))}) — patrón clásico Evil Twin / airbase-ng")
            else:
                severity = "HIGH"
                reasons.append(f"Discrepancia de seguridad entre BSSIDs ({', '.join(sorted(auth_set))})")
        if len(vendors_set) > 1:
            if severity == "INFO":
                severity = "MEDIUM"
            reasons.append(f"Fabricantes OUI heterogéneos en el mismo SSID ({', '.join(sorted(vendors_set))})")
        if has_deauth:
            severity = "CRITICAL" if severity in ("CRITICAL", "HIGH") else "HIGH"
            reasons.append("Tramas DEAUTH observadas sobre este cluster SSID")

        col_entry = {
            "ssid": ssid,
            "bssids": b_sorted,
            "auth_modes": sorted(auth_set),
            "vendors": sorted(vendors_set),
            "has_deauth": has_deauth,
            "severity": severity,
            "anomaly_reasons": reasons,
        }
        ssid_collisions.append(col_entry)
        if reasons:
            evil_twin_alerts.append(col_entry)

    # Construir relaciones de grafo por sesión y globales (Confirmadas vs Sospechas reales)
    session_assoc = promisc_data.get("session_assoc", {})
    session_probes = promisc_data.get("session_probes", {})
    session_sta_info = promisc_data.get("session_sta_info", {})
    session_ap_info = promisc_data.get("session_ap_info", {})
    hs_pairs = {(h["bssid"].upper(), h["sta_mac"].upper()): h["type"] for h in promisc_data.get("handshakes", [])}

    graph_edges_by_session = {}
    global_edge_map = {}  # (sta, bssid) -> edge dict consolidado

    def _register_global_edge(edge: dict):
        key = (edge["sta_mac"], edge["bssid"])
        cur = global_edge_map.get(key)
        if cur is None:
            cp = dict(edge)
            cp["sessions"] = [edge["session_id"]] if edge.get("session_id") else []
            global_edge_map[key] = cp
        else:
            if edge.get("session_id") and edge["session_id"] not in cur["sessions"]:
                cur["sessions"].append(edge["session_id"])
            # Si pasa de sospecha a confirmada en alguna sesión, prevalece confirmada
            if cur["type"] != "confirmed" and edge["type"] == "confirmed":
                cur["type"] = "confirmed"
                cur["subtype"] = edge.get("subtype", "DIRECT_80211")
                cur["confidence"] = edge["confidence"]
                cur["reason"] = edge["reason"]
                cur["frames"] = edge["frames"]
            elif cur["type"] == edge["type"]:
                cur["frames"] = max(cur.get("frames", 0), edge.get("frames", 0))
            cur["rssi"] = max(cur.get("rssi", -128), edge.get("rssi", -128))
            merged_tr = set(cur.get("traces", [])) | set(edge.get("traces", []))
            cur["traces"] = _sort_traces(merged_tr)
            if edge.get("has_handshake"):
                cur["has_handshake"] = True
                cur["handshake_type"] = edge.get("handshake_type", "")

    for sid in sorted(sessions_meta.keys()):
        s_aps = session_ap_info.get(sid, {})
        s_stas = session_sta_info.get(sid, {})
        s_assoc = session_assoc.get(sid, {})
        s_probes = session_probes.get(sid, {})

        s_ssid_to_bssids = defaultdict(list)
        for bssid in s_aps:
            ssid_val = s_aps[bssid].get("ssid") or aps.get(bssid, {}).get("ssid", "")
            if ssid_val:
                s_ssid_to_bssids[ssid_val].append(bssid)

        edges_this_session = []
        seen_pairs_session = set()

        # 1. Relaciones Reales Confirmadas en esta sesión (ToDS/FromDS/Assoc/EAPOL)
        for (sta, bssid), a_meta in sorted(s_assoc.items()):
            seen_pairs_session.add((sta, bssid))
            ap_obj = aps.get(bssid, {})
            ssid_val = ap_obj.get("ssid", "")
            tr_set = set(a_meta.get("traces", set()))
            hs_type = hs_pairs.get((bssid, sta), "")
            if hs_type:
                tr_set.add("HANDSHAKE")
            tr_sorted = _sort_traces(tr_set)
            reason_parts = [f"Tráfico directo 802.11 ({a_meta['frames']} tramas)"]
            if hs_type:
                reason_parts.append(f"Material criptográfico: {hs_type}")
            elif tr_sorted:
                reason_parts.append("Trazas: " + "+".join(tr_sorted))

            edge = {
                "session_id": sid,
                "sta_mac": sta,
                "bssid": bssid,
                "ssid": ssid_val,
                "type": "confirmed",
                "subtype": "DIRECT_80211",
                "confidence": "CONFIRMADA (100%)",
                "frames": int(a_meta["frames"]),
                "rssi": int(a_meta["rssi"]),
                "channel": int(a_meta["channel"]),
                "traces": tr_sorted,
                "has_handshake": bool(hs_type or "EAPOL" in tr_set or "HANDSHAKE" in tr_set or "PMKID" in tr_set),
                "handshake_type": hs_type,
                "reason": " · ".join(reason_parts),
            }
            edges_this_session.append(edge)
            _register_global_edge(edge)

        # 2a. Sospecha Tipo 1: STA busca por Probe Request un SSID que SÍ está presente en esta sesión
        for (sta, pssid), p_meta in sorted(s_probes.items()):
            if not pssid or pssid not in s_ssid_to_bssids:
                # Si la red buscada no se ve en el entorno, se descarta (cero ruido)
                continue
            for cand_bssid in sorted(s_ssid_to_bssids[pssid]):
                if (sta, cand_bssid) in seen_pairs_session:
                    continue
                seen_pairs_session.add((sta, cand_bssid))
                edge = {
                    "session_id": sid,
                    "sta_mac": sta,
                    "bssid": cand_bssid,
                    "ssid": pssid,
                    "type": "suspected",
                    "subtype": "PNL_PRESENT",
                    "confidence": "ALTA (85%)",
                    "frames": int(p_meta["count"]),
                    "rssi": int(p_meta["rssi"]),
                    "channel": int(p_meta["channel"]),
                    "traces": ["PROBE_REQ"],
                    "has_handshake": False,
                    "handshake_type": "",
                    "reason": f"Sospecha PNL: busca activamente '{pssid}' ({p_meta['count']} probes) y el AP está presente en la sesión",
                }
                edges_this_session.append(edge)
                _register_global_edge(edge)

        # 2b. Sospecha Tipo 2: STA y BSSID coinciden en esta sesión y estuvieron asociados en otra sesión
        for sta, st_info in sorted(s_stas.items()):
            dev_obj = devices_map.get(sta, {})
            for hist_bssid in sorted(dev_obj.get("associated_bssids", set())):
                if hist_bssid in s_aps and (sta, hist_bssid) not in seen_pairs_session:
                    seen_pairs_session.add((sta, hist_bssid))
                    ssid_val = aps.get(hist_bssid, {}).get("ssid", "")
                    edge = {
                        "session_id": sid,
                        "sta_mac": sta,
                        "bssid": hist_bssid,
                        "ssid": ssid_val,
                        "type": "suspected",
                        "subtype": "CROSS_SESSION_ASSOC",
                        "confidence": "ALTA (80%)",
                        "frames": 1,
                        "rssi": int(st_info["rssi"]),
                        "channel": int(st_info["channel"]),
                        "traces": [],
                        "has_handshake": False,
                        "handshake_type": "",
                        "reason": "Sospecha Multi-Sesión: dispositivo y AP presentes a la vez (conexión directa confirmada en otra sesión)",
                    }
                    edges_this_session.append(edge)
                    _register_global_edge(edge)

        # 2c. Sospecha Tipo 3: Roaming / BSSID hermano del mismo SSID en la misma sesión
        for (sta, assoc_bssid) in list(s_assoc.keys()):
            ap_ssid = aps.get(assoc_bssid, {}).get("ssid", "")
            if not ap_ssid or len(s_ssid_to_bssids.get(ap_ssid, [])) < 2:
                continue
            for sib_bssid in sorted(s_ssid_to_bssids[ap_ssid]):
                if sib_bssid == assoc_bssid or (sta, sib_bssid) in seen_pairs_session:
                    continue
                seen_pairs_session.add((sta, sib_bssid))
                edge = {
                    "session_id": sid,
                    "sta_mac": sta,
                    "bssid": sib_bssid,
                    "ssid": ap_ssid,
                    "type": "suspected",
                    "subtype": "ROAMING_CLUSTER",
                    "confidence": "MEDIA (65%)",
                    "frames": 1,
                    "rssi": int(s_aps[sib_bssid]["rssi"]),
                    "channel": int(s_aps[sib_bssid]["channel"]),
                    "traces": [],
                    "has_handshake": False,
                    "handshake_type": "",
                    "reason": f"Sospecha Roaming/Mesh: conectado al cluster '{ap_ssid}' ({assoc_bssid}) con segundo BSSID activo en sesión",
                }
                edges_this_session.append(edge)
                _register_global_edge(edge)

        # 2d. Sospecha Tipo 4: AP con SSID oculto y STA no asociado operando en el mismo canal con RSSI parejo
        hidden_bssids = [b for b, inf in s_aps.items() if inf.get("hidden") or aps.get(b, {}).get("hidden")]
        for hb in sorted(hidden_bssids):
            h_ch = s_aps[hb]["channel"] or aps.get(hb, {}).get("primary_channel", 0)
            h_rssi = s_aps[hb]["rssi"]
            if not h_ch:
                continue
            for sta, st_info in sorted(s_stas.items()):
                if (sta, hb) in seen_pairs_session:
                    continue
                if st_info["channel"] == h_ch and abs(st_info["rssi"] - h_rssi) <= 10:
                    seen_pairs_session.add((sta, hb))
                    edge = {
                        "session_id": sid,
                        "sta_mac": sta,
                        "bssid": hb,
                        "ssid": aps.get(hb, {}).get("ssid", ""),
                        "type": "suspected",
                        "subtype": "HIDDEN_CHANNEL_PROXIMITY",
                        "confidence": "MEDIA-BAJA (55%)",
                        "frames": 1,
                        "rssi": int(st_info["rssi"]),
                        "channel": int(h_ch),
                        "traces": [],
                        "has_handshake": False,
                        "handshake_type": "",
                        "reason": f"Sospecha Red Oculta: coincidencia de canal (ch {h_ch}) y proximidad RSSI ({st_info['rssi']} vs {h_rssi} dBm)",
                    }
                    edges_this_session.append(edge)
                    _register_global_edge(edge)

        graph_edges_by_session[sid] = edges_this_session

    # 2e. En la vista global, si un STA buscó en una sesión un SSID que fue visto físicamente en OTRA sesión
    for sta, d_obj in sorted(devices_map.items()):
        for pssid in sorted(d_obj.get("probed_ssids", set())):
            if not pssid or pssid not in ssid_to_bssids:
                continue
            for cand_bssid in sorted(ssid_to_bssids[pssid]):
                if (sta, cand_bssid) in global_edge_map:
                    continue
                p_info = promisc_data["probe_best"].get((sta, pssid), {"count": 1, "rssi": d_obj["rssi"], "channel": d_obj["channel"]})
                merged_sessions = sorted(set(d_obj["sessions"]) | set(ap_sessions.get(cand_bssid, set())))
                global_edge_map[(sta, cand_bssid)] = {
                    "session_id": "",
                    "sessions": merged_sessions,
                    "sta_mac": sta,
                    "bssid": cand_bssid,
                    "ssid": pssid,
                    "type": "suspected",
                    "subtype": "PNL_CROSS_SESSION",
                    "confidence": "MEDIA-ALTA (75%)",
                    "frames": int(p_info["count"]),
                    "rssi": int(p_info["rssi"]),
                    "channel": int(p_info["channel"]),
                    "traces": ["PROBE_REQ"],
                    "has_handshake": False,
                    "handshake_type": "",
                    "reason": f"Sospecha PNL Cruzada: STA busca '{pssid}' y el AP existe en el catálogo general",
                }

    graph_global_edges = sorted(
        global_edge_map.values(),
        key=lambda e: (0 if e["type"] == "confirmed" else 1, -int(e.get("frames", 0)), -int(e.get("rssi", -128))),
    )

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_scans": total_scans,
        "unique_ssids": len(ssid_to_bssids),
        "probed_ssids_count": len(all_probed_ssids),
        "matched_probes_count": len(matched_probed_ssids),
        "matched_ssids_set": sorted(matched_probed_ssids),
        "totals": {
            "mgmt_frames": int(promisc_data["totals"]["mgmt_frames"]),
            "data_frames": int(promisc_data["totals"]["data_frames"]),
            "probe_req_frames": int(promisc_data["totals"]["probe_req_frames"]),
            "deauth_frames": int(promisc_data["totals"]["deauth_frames"]),
            "eapol_frames": int(promisc_data["totals"]["eapol_frames"]),
            "pcap_frames": int(promisc_data["totals"]["pcap_frames"]),
            "pcap_bytes": int(promisc_data["totals"]["pcap_bytes"]),
        },
        "pcap_files": promisc_data.get("pcap_files", []),
        "handshakes": promisc_data.get("handshakes", []),
        "hc22000_lines": promisc_data.get("hc22000_lines", []),
        "ble_intel": {
            "devices": sorted(
                promisc_data.get("ble_devices", {}).values(),
                key=lambda d: d.get("rssi", -128),
                reverse=True,
            ),
            "sessions": promisc_data.get("session_ble", {}),
        },
        "channel_counts": {str(k): v for k, v in ch_counts.items()},
        "auth_counts": dict(auth_counts.most_common()),
        "ssid_collisions": ssid_collisions,
        "evil_twin_alerts": evil_twin_alerts,
        "sessions": [sessions_meta[k] for k in sorted(sessions_meta.keys())],
        "aps": ap_list,
        "ap_by_bssid": ap_by_bssid,
        "devices": dev_list,
        "device_by_mac": device_by_mac,
        "graph": {
            "global_edges": graph_global_edges,
            "by_session": graph_edges_by_session,
        },
    }


def print_report(aps, sightings, sessions, total_scans, promisc_data, tags_data=None):
    tags_data = tags_data or {"sessions": {}, "networks": {}, "devices": {}}
    print(f"\n\033[1;36m================ WARMAP — RESUMEN DE INTELIGENCIA SIGINT ================\033[0m")
    print(f"Sesiones analizadas : {len(sessions)} ({', '.join(sorted(sessions))})")
    print(f"Escaneos totales    : {total_scans}")
    print(f"Puntos de acceso    : {len(aps)} BSSIDs únicos")
    totals = promisc_data["totals"]
    clients_by_bssid = promisc_data["clients_by_bssid"]
    devices_map = promisc_data["devices"]
    directed_probes = [v for v in promisc_data["probe_best"].values() if v["ssid"]]
    if totals:
        print(
            f"Tráfico promiscuo   : {totals['mgmt_frames']} MGMT, {totals['data_frames']} DATA, "
            f"{len(devices_map)} dispositivos (STAs), {len(directed_probes)} SSIDs buscados, "
            f"{totals['deauth_frames']} tramas deauth\n"
        )
    else:
        print()

    if not aps:
        print("No hay puntos de acceso registrados.")
        return

    ch_cnt = Counter(d["primary_channel"] for d in aps.values())
    auth_cnt = Counter(d["auth_mode"] for d in aps.values())
    cipher_cnt = Counter(d["pairwise_cipher"] for d in aps.values())

    print("\033[1;33m[Distribución por Canal 2.4 GHz]\033[0m")
    for ch in sorted(ch_cnt):
        bar = "█" * min(40, ch_cnt[ch])
        print(f"  Canal {ch:>2}: {ch_cnt[ch]:>3} APs  {bar}")

    print("\n\033[1;33m[Autenticación y Cifrado]\033[0m")
    for k, v in auth_cnt.most_common():
        print(f"  Auth   {k:<18}: {v:>3} APs")
    for k, v in cipher_cnt.most_common():
        print(f"  Cipher {k:<18}: {v:>3} APs")

    weak = [
        d for d in aps.values()
        if d["auth_mode"] in ("OPEN", "WEP", "WPA_PSK", "WPA_WPA2_PSK")
        or "TKIP" in d["pairwise_cipher"]
    ]
    wps_list = [d for d in aps.values() if d.get("wps")]
    hidden_list = [d for d in aps.values() if d.get("hidden")]

    print(f"\n\033[1;31m[Puntos de Interés de Auditoría]\033[0m")
    print(f"  • Redes abiertas / WEP / WPA1-TKIP : {len(weak)}")
    for d in sorted(weak, key=lambda x: x["rssi"], reverse=True)[:10]:
        ssid = "<OCULTA>" if d["hidden"] else d["ssid"]
        print(f"      {d['rssi']:>4}dBm | ch {d['primary_channel']:>2} | {d['auth_mode']}/{d['pairwise_cipher']} | {d['bssid']} | {ssid}")

    print(f"  • Redes con WPS expuesto           : {len(wps_list)}")
    print(f"  • Redes con SSID oculto            : {len(hidden_list)}")
    for d in sorted(hidden_list, key=lambda x: x["rssi"], reverse=True):
        print(f"      {d['rssi']:>4}dBm | ch {d['primary_channel']:>2} | {d['auth_mode']:<14} | {d['bssid']} ({resolve_vendor(d['bssid'])})")

    if devices_map:
        print(f"\n\033[1;35m[Modo Promiscuo — Dispositivos Clientes ({len(devices_map)} STAs)]\033[0m")
        sta_pcap_traces = promisc_data.get("sta_pcap_traces", {})
        for sta, d in sorted(devices_map.items(), key=lambda kv: kv[1]["rssi"], reverse=True)[:16]:
            tag_info = tags_data.get("devices", {}).get(sta, {})
            tag_str = f" [{tag_info['label']}]" if tag_info.get("label") else ""
            assoc_str = ", ".join(
                f"{b} ({aps.get(b, {}).get('ssid') or 'AP ext'})" for b in sorted(d["associated_bssids"])
            ) or "Sin asociar"
            probes_str = ", ".join(sorted(d["probed_ssids"])) or "—"
            traces_set = d.get("pcap_traces", set()) | sta_pcap_traces.get(sta, set())
            pcap_str = f" | PCAP:[{','.join(sorted(traces_set))}]" if traces_set else ""
            ses_cnt = len(d["sessions"])
            print(
                f"  {d['rssi']:>4}dBm | {sta}{tag_str} | {d['vendor']:<32.32} | "
                f"{ses_cnt} ses | AP: {assoc_str} | Busca: {probes_str}{pcap_str}"
            )

    print(f"\n\033[1;32m[Catálogo Completo de Redes ({len(aps)} BSSIDs por potencia RSSI)]\033[0m")
    print(f"  {'RSSI':>5}  {'CH':>2}  {'SES':>3}  {'STAs':>4}  {'WPS':<3}  {'AUTH':<15}  {'CIPHER':<9}  {'BSSID':<17}  {'SSID':<24}  {'PCAP':<18}  FABRICANTE")
    ap_sessions = promisc_data["ap_sessions"]
    ap_pcap_traces = promisc_data.get("ap_pcap_traces", {})
    for d in sorted(aps.values(), key=lambda x: x["rssi"], reverse=True):
        bssid = d["bssid"]
        ssid = "<OCULTA>" if d["hidden"] else d["ssid"]
        wps = "SI" if d.get("wps") else "no"
        vendor = resolve_vendor(bssid)
        n_ses = len(ap_sessions[bssid])
        n_stas = len(clients_by_bssid.get(bssid, {}))
        tr_str = ",".join(sorted(ap_pcap_traces.get(bssid, set()))) or "—"
        print(
            f"  {d['rssi']:>4}dBm  {d['primary_channel']:>2}  {n_ses:>2}s  {n_stas:>4}  {wps:<3}  "
            f"{d['auth_mode']:<15}  {d['pairwise_cipher']:<9}  {bssid}  {ssid:<24.24}  {tr_str:<18.18}  {vendor}"
        )


def export_csv(aps, sightings, promisc_data, csv_path: Path, tags_data=None):
    tags_data = tags_data or {"networks": {}}
    clients_by_bssid = promisc_data["clients_by_bssid"]
    ap_sessions = promisc_data["ap_sessions"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "bssid", "ssid", "tag", "hidden", "rssi_max", "channel", "band_mhz",
            "proto", "auth_mode", "pairwise_cipher", "group_cipher", "wps",
            "sightings", "sessions_count", "clients_count", "vendor",
        ])
        for d in sorted(aps.values(), key=lambda x: x["rssi"], reverse=True):
            bssid = d["bssid"]
            net_tags = tags_data.get("networks", {})
            tag_obj = net_tags.get(bssid) or net_tags.get(f"SSID:{d.get('ssid', '')}") or {}
            writer.writerow([
                bssid,
                d["ssid"],
                tag_obj.get("label", ""),
                d["hidden"],
                d["rssi"],
                d["primary_channel"],
                d["band_mhz"],
                d["proto"],
                d["auth_mode"],
                d["pairwise_cipher"],
                d["group_cipher"],
                d["wps"],
                sightings[bssid],
                len(ap_sessions[bssid]),
                len(clients_by_bssid.get(bssid, {})),
                resolve_vendor(bssid),
            ])
    print(f"\nCSV exportado en: {csv_path}")


def export_wigle(aps, promisc_data, wigle_path: Path, tags_data=None):
    tags_data = tags_data or {"sessions": {}}
    first_seen = promisc_data["first_seen"]
    ap_sessions = promisc_data["ap_sessions"]
    sessions_meta = promisc_data["sessions_meta"]
    with wigle_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "WigleWifi-1.4",
            "appRelease=1.0",
            "model=ESP32-S3",
            "release=IDF-6.1",
            "device=Wardrive-S3",
            "display=CLI",
            "board=ESP32S3",
            "brand=Espressif",
        ])
        writer.writerow([
            "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
            "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type",
        ])
        for d in sorted(aps.values(), key=lambda x: x["rssi"], reverse=True):
            bssid = d["bssid"]
            gps = d.get("gps") or {}
            if not gps:
                for sid in ap_sessions.get(bssid, []):
                    st_gps = tags_data.get("sessions", {}).get(sid, {}).get("gps")
                    if st_gps:
                        gps = st_gps
                        break
                    sm_gps = sessions_meta.get(sid, {}).get("gps")
                    if sm_gps:
                        gps = sm_gps
                        break
            caps = f"[{d['auth_mode']}-{d['pairwise_cipher']}]"
            if d.get("wps"):
                caps += "[WPS]"
            caps += "[ESS]"
            writer.writerow([
                bssid,
                d["ssid"],
                caps,
                first_seen.get(bssid, "1970-01-01 00:00:00"),
                d["primary_channel"],
                d["rssi"],
                gps.get("lat", 0.0),
                gps.get("lon", 0.0),
                0.0,
                gps.get("acc_m", 0.0) or 0.0,
                "WIFI",
            ])
    print(f"\nWiGLE CSV v1.4 exportado en: {wigle_path}")


def export_airodump(aps, sightings, promisc_data, airodump_path: Path, tags_data=None):
    """Exporta en el formato estándar de dos bloques de airodump-ng CSV (compatible con airgraph-ng)."""
    tags_data = tags_data or {"networks": {}}
    first_seen = promisc_data["first_seen"]
    devices_map = promisc_data["devices"]
    net_tags = tags_data.get("networks", {})

    with airodump_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "BSSID", " First time seen", " Last time seen", " channel", " Speed",
            " Privacy", " Cipher", " Authentication", " Power", " # beacons",
            " # IV", " LAN IP", " ID-length", " ESSID", " Key",
        ])
        for d in sorted(aps.values(), key=lambda x: x["rssi"], reverse=True):
            bssid = d["bssid"]
            ssid = d.get("ssid", "")
            f_ts = first_seen.get(bssid, "2026-01-01 00:00:00")
            auth_raw = d.get("auth_mode", "OPEN")
            priv = "OPN" if auth_raw == "OPEN" else ("WEP" if "WEP" in auth_raw else ("WPA3" if "WPA3" in auth_raw else "WPA2"))
            ciph = d.get("pairwise_cipher", "CCMP")
            authn = "SAE" if "WPA3" in auth_raw else ("PSK" if "PSK" in auth_raw else ("MGT" if "ENT" in auth_raw else ""))
            tag_obj = net_tags.get(bssid) or net_tags.get(f"SSID:{ssid}") or {}
            psk_val = tag_obj.get("psk", "")
            writer.writerow([
                bssid,
                f" {f_ts}",
                f" {f_ts}",
                f" {d.get('primary_channel', 1):>2}",
                " 54",
                f" {priv}",
                f" {ciph}",
                f" {authn}",
                f" {d.get('rssi', -80)}",
                f" {sightings.get(bssid, 1)}",
                " 0",
                "   0.  0.  0.  0",
                f" {len(ssid)}",
                f" {ssid}",
                f" {psk_val}",
            ])

        fh.write("\n")
        writer.writerow([
            "Station MAC", " First time seen", " Last time seen", " Power",
            " # packets", " BSSID", " Probed ESSIDs",
        ])
        for sta, dev in sorted(devices_map.items(), key=lambda kv: kv[1]["rssi"], reverse=True):
            assoc_list = sorted(dev.get("associated_bssids", set()))
            bssid_col = assoc_list[0] if assoc_list else "(not associated)"
            probed_col = ",".join(sorted(dev.get("probed_ssids", set())))
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                sta,
                f" {now_str}",
                f" {now_str}",
                f" {dev.get('rssi', -80)}",
                f" {dev.get('total_frames', 1)}",
                f" {bssid_col}",
                f" {probed_col}" if probed_col else "",
            ])
    print(f"\nAirodump-ng CSV exportado en: {airodump_path}")


def parse_airodump_csv_to_jsonl_lines(csv_text: str, session_name_hint: str = "airodump") -> list[dict]:
    """Convierte un CSV de airodump-ng (*-01.csv) en un sobre JSONL v1 listo para SIGINT-Console."""
    import hashlib

    sid = hashlib.sha256((session_name_hint + csv_text[:256]).encode("utf-8")).hexdigest()[:8]
    lines = [ln.strip("\r") for ln in csv_text.splitlines()]
    mode = None
    devices = []
    clients = []
    probes = []
    bssid_ch = {}

    for raw in lines:
        s = raw.strip()
        if not s:
            continue
        if s.startswith("BSSID,") and "ESSID" in s:
            mode = "ap"
            continue
        if s.startswith("Station MAC,") and "Probed ESSIDs" in s:
            mode = "sta"
            continue

        parts = [p.strip() for p in raw.split(",")]
        if mode == "ap" and len(parts) >= 14:
            bssid = parts[0].upper()
            if len(bssid) != 17 or bssid.count(":") != 5:
                continue
            try:
                ch = max(1, min(14, int(parts[3])))
            except Exception:
                ch = 1
            try:
                pwr = int(parts[8])
                if pwr >= 0 or pwr < -120:
                    pwr = -75
            except Exception:
                pwr = -75
            priv = parts[5].upper()
            ciph = parts[6].upper() or "CCMP"
            ssid = parts[13]
            auth_mode = "OPEN"
            if "WPA3" in priv and "WPA2" in priv:
                auth_mode = "WPA2_WPA3_PSK"
            elif "WPA3" in priv:
                auth_mode = "WPA3_PSK"
            elif "WPA2" in priv and "WPA" in priv:
                auth_mode = "WPA_WPA2_PSK"
            elif "WPA2" in priv:
                auth_mode = "WPA2_PSK"
            elif "WPA" in priv:
                auth_mode = "WPA_PSK"
            elif "WEP" in priv:
                auth_mode = "WEP"
            bssid_ch[bssid] = ch
            devices.append({
                "ssid": ssid,
                "bssid": bssid,
                "rssi": pwr,
                "primary_channel": ch,
                "secondary_channel": 0,
                "auth_mode": auth_mode,
                "pairwise_cipher": "NONE" if auth_mode == "OPEN" else ciph,
                "group_cipher": "NONE" if auth_mode == "OPEN" else ciph,
                "proto": "bgn",
                "band_mhz": 20,
                "wps": False,
                "hidden": len(ssid) == 0,
            })
        elif mode == "sta" and len(parts) >= 6:
            sta = parts[0].upper()
            if len(sta) != 17 or sta.count(":") != 5:
                continue
            try:
                pwr = int(parts[3])
                if pwr >= 0 or pwr < -120:
                    pwr = -75
            except Exception:
                pwr = -75
            try:
                pkts = max(1, int(parts[4]))
            except Exception:
                pkts = 1
            assoc_bssid = parts[5].upper()
            ch = bssid_ch.get(assoc_bssid, 6)
            if len(assoc_bssid) == 17 and assoc_bssid.count(":") == 5:
                clients.append({
                    "sta_mac": sta,
                    "bssid": assoc_bssid,
                    "rssi": pwr,
                    "channel": ch,
                    "frames": pkts,
                })
            if len(parts) >= 7:
                for pssid in parts[6:]:
                    ps = pssid.strip()
                    if ps:
                        probes.append({
                            "sta_mac": sta,
                            "ssid": ps,
                            "rssi": pwr,
                            "channel": ch,
                            "count": 1,
                        })

    if not devices and not clients and not probes:
        return []

    envelope = {
        "recv_at": datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "session_name": session_name_hint,
        "gps": None,
        "payload": {
            "v": 1,
            "mode": "scan",
            "scan_type": "passive",
            "session_id": sid,
            "scan_id": 1,
            "device_ts_us": 1000000,
            "scan_duration_ms": 4200,
            "total_detected": len(devices),
            "stored": len(devices),
            "dropped": 0,
            "lost_before": 0,
            "buffered": False,
            "devices": devices,
            "promisc": {
                "mgmt_frames": len(devices) + len(probes),
                "data_frames": sum(c["frames"] for c in clients),
                "probe_req_frames": len(probes),
                "deauth_frames": 0,
                "probes": probes,
                "clients": clients,
            },
        },
    }
    return [envelope]


def export_html(aps, sightings, sessions, total_scans, promisc_data, html_path: Path, tags_data=None):
    tags_data = tags_data or {"sessions": {}, "networks": {}, "devices": {}}
    dataset = build_intelligence_dataset(aps, sightings, sessions, total_scans, promisc_data, tags_data)
    render_sigint_dashboard(dataset, tags_data, html_path)
    print(f"\nConsola SIGINT HTML exportada en: {html_path}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Plataforma SIGINT y Analizador de capturas JSONL de Wardrive (warmap)")
    parser.add_argument("files", nargs="*", type=Path, help="Ficheros .jsonl (por defecto busca en ./wardrive_data)")
    parser.add_argument("--csv", type=Path, help="Exportar tabla única de BSSIDs a CSV")
    parser.add_argument("--wigle", type=Path, help="Exportar en formato oficial WiGLE CSV v1.4")
    parser.add_argument("--airodump", type=Path, help="Exportar en formato oficial airodump-ng CSV (compatible con airgraph-ng)")
    parser.add_argument("--html", type=Path, help="Exportar Consola SIGINT interactiva en HTML")
    parser.add_argument("--tag-session", nargs=2, metavar=("SESSION_ID", "NOMBRE"), help="Asignar nombre a una sesión en tags.json")
    parser.add_argument("--tag-device", nargs=2, metavar=("STA_MAC", "ALIAS"), help="Asignar alias a un dispositivo cliente en tags.json")
    parser.add_argument("--tag-net", nargs=2, metavar=("BSSID_O_SSID", "ALIAS"), help="Asignar alias a un BSSID o SSID:Nombre en tags.json")
    parser.add_argument("--evidence", nargs=3, metavar=("BSSID_O_SSID", "PSK", "EVIDENCIA"), help="Registrar PSK recuperada y evidencia de auditoría en tags.json")
    args = parser.parse_args(argv)

    files = list(args.files)
    if not files:
        default_dirs = [Path("/home/Kta41/wardrive/wardrive_data"), Path("./wardrive_data")]
        for d in default_dirs:
            if d.is_dir():
                files.extend(sorted(d.glob("wardrive_*.jsonl")))
                if files:
                    break

    tags_data, tags_path = load_tags_file(files)
    tags_modified = False

    if args.tag_session:
        sid, name = args.tag_session
        tags_data["sessions"].setdefault(sid, {})["name"] = name
        tags_modified = True
    if args.tag_device:
        mac, label = args.tag_device
        cur = tags_data["devices"].get(mac.upper(), {})
        cur.update({"label": label, "category": cur.get("category", "CONOCIDO")})
        tags_data["devices"][mac.upper()] = cur
        tags_modified = True
    if args.tag_net:
        key, label = args.tag_net
        norm = key if key.startswith("SSID:") else key.upper()
        cur = tags_data["networks"].get(norm, {})
        cur.update({"label": label, "category": cur.get("category", "CONOCIDO")})
        tags_data["networks"][norm] = cur
        tags_modified = True
    if args.evidence:
        key, psk, ev_text = args.evidence
        norm = key if key.startswith("SSID:") else key.upper()
        cur = tags_data["networks"].get(norm, {})
        cur.update({
            "label": cur.get("label") or f"Auditada ({norm})",
            "category": "OBJETIVO",
            "audit_status": "CRACKEADA" if psk and psk != "-" else "VULNERABLE",
            "psk": "" if psk == "-" else psk,
            "evidence": ev_text,
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        tags_data["networks"][norm] = cur
        tags_modified = True

    if tags_modified:
        tags_path.parent.mkdir(parents=True, exist_ok=True)
        tags_path.write_text(json.dumps(tags_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Etiquetas / Evidencias guardadas en: {tags_path}")

    if not files:
        print("No se encontraron ficheros wardrive_*.jsonl.", file=sys.stderr)
        return 1 if not tags_modified else 0

    aps, sightings, sessions, total_scans, promisc_data = load_records(files)
    print_report(aps, sightings, sessions, total_scans, promisc_data, tags_data)
    if args.csv:
        export_csv(aps, sightings, promisc_data, args.csv, tags_data)
    if args.wigle:
        export_wigle(aps, promisc_data, args.wigle, tags_data)
    if args.airodump:
        export_airodump(aps, sightings, promisc_data, args.airodump, tags_data)
    if args.html:
        export_html(aps, sightings, sessions, total_scans, promisc_data, args.html, tags_data)
    return 0


def build_handshake_center(dataset: dict, tags_data: dict) -> dict:
    """Handshake Center: material criptográfico capturado por red + estado de bóveda.

    Cruza dataset.handshakes (EAPOL M1-M4 / PMKID extraídos de los .pcap) con las
    etiquetas de la bóveda (tags.json: audit_status / psk) para dar el veredicto
    por BSSID: crackeable (handshake o PMKID) y ya-comprometida (PSK recuperada).
    Consumido por `GET /api/handshakes` y por warcrack en el lado cliente.
    """
    ap_by_bssid = dataset.get("ap_by_bssid", {})
    networks_tags = tags_data.get("networks", {}) if isinstance(tags_data, dict) else {}

    by_bssid: dict = {}
    for h in dataset.get("handshakes", []):
        bssid = str(h.get("bssid", "")).upper()
        if not bssid:
            continue
        entry = by_bssid.setdefault(
            bssid,
            {
                "bssid": bssid,
                "ssid": h.get("ssid", "") or (ap_by_bssid.get(bssid, {}) or {}).get("ssid", ""),
                "vectors": [],
                "stations": [],
            },
        )
        vec = h.get("type", "")
        if vec and vec not in entry["vectors"]:
            entry["vectors"].append(vec)
        sta = str(h.get("sta_mac", "")).upper()
        if sta and sta not in entry["stations"]:
            entry["stations"].append(sta)

    hc_bssids = set()
    for line in dataset.get("hc22000_lines", []):
        parts = str(line).split("*")
        if len(parts) >= 4 and len(parts[3]) == 12:
            try:
                bssid = ":".join(parts[3].lower()[i : i + 2] for i in range(0, 12, 2)).upper()
                hc_bssids.add(bssid)
            except Exception:
                continue

    cracked = 0
    material = []
    for bssid in sorted(set(by_bssid) | hc_bssids):
        info = by_bssid.get(bssid, {"bssid": bssid, "ssid": "", "vectors": [], "stations": []})
        tag = networks_tags.get(bssid, {}) if isinstance(networks_tags, dict) else {}
        audit_status = tag.get("audit_status", "")
        psk = tag.get("psk", "")
        if psk:
            cracked += 1
        material.append(
            {
                **info,
                "hc22000_available": bssid in hc_bssids,
                "audit_status": audit_status or ("CRACKEADA" if psk else ""),
                "psk": psk,
                "label": tag.get("label", ""),
                "severity": tag.get("cvss_severity", ""),
                "crackable": bool(info["vectors"]) or bssid in hc_bssids,
            }
        )

    return {
        "totals": {
            "networks_with_material": len(material),
            "cracked": cracked,
            "handshake_vectors": sum(len(m["vectors"]) for m in material),
            "hc22000_hashes": len(dataset.get("hc22000_lines", [])),
        },
        "networks": material,
        "raw_handshakes": dataset.get("handshakes", []),
    }


if __name__ == "__main__":
    raise SystemExit(main())
