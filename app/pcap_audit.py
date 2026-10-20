#!/usr/bin/env python3
"""
pcap_audit.py (waraudit) — Inspector profundo de capturas PCAP 802.11 y suite de
                           auditoría Red Team (EAPOL M1-M4, PMKID, hc22000, WPS,
                           Deauth Reason Codes e IE-Fingerprinting de clientes).

Funciones principales:
1. Triaje profundo de `.pcap` (`DLT_IEEE802_11_RADIO = 127` o `DLT_IEEE802_11 = 105`):
   - Clasifica mensajes EAPOL en M1, M2, M3 y M4 e identifica pares M1+M2 / M2+M3.
   - Detecta presencia de RSN PMKID en el Key Data de EAPOL M1.
   - Extrae metadatos internos WPS (Fabricante, Modelo, Nombre de Dispositivo,
     Número de Serie, Estado WPS Locked) desde Beacons y Probe Responses.
   - Extrae códigos de razón IEEE 802.11 en tramas Deauthentication / Disassociation.
   - Calcula la huella `IE-Fingerprint` de estaciones clientes a partir de la
     secuencia ordenada de tags en `Probe Requests` + capacidades HT/VHT/HE + OUIs.
2. Exportación nativa a formato Hashcat **`hc22000`** (`WPA*01` PMKID y `WPA*02`
   EAPOL 4-Way Handshake) sin depender de binarios externos, además de integración
   opcional con `hcxpcapngtool`.
3. Ejecución opcional de auditoría rápida por diccionario en el móvil/PC mediante
   `aircrack-ng` o `hashcat` cuando el usuario pasa `--wordlist <fichero>`.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

TRACE_ORDER = [
    "HANDSHAKE",
    "PMKID",
    "EAPOL",
    "DEAUTH",
    "ASSOC",
    "AUTH",
    "PROBE_REQ",
    "PROBE_RESP",
    "ACTION",
    "BEACON",
    "DATA",
]

DEAUTH_REASONS = {
    1: "Unspecified (1)",
    2: "Prev auth no longer valid (2)",
    3: "STA leaving BSS (3)",
    4: "Inactivity timer expired (4)",
    5: "AP overloaded (5)",
    6: "Class 2 frame from non-auth STA (6)",
    7: "Class 3 frame from non-assoc STA (7)",
    8: "STA leaving BSS / Disassoc (8)",
    14: "MIC failure (14)",
    15: "4-Way Handshake timeout (15)",
}


def fmt_mac(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def is_mcast_or_zero(b: bytes) -> bool:
    if not b or len(b) < 6:
        return True
    if (b[0] & 0x01) != 0:
        return True
    return b == b"\x00\x00\x00\x00\x00\x00"


def _parse_wps_tlvs(data: bytes) -> dict:
    """Extrae atributos WPS (2 bytes type BE, 2 bytes len BE) de un Vendor IE 00:50:F2:04."""
    info = {}
    pos = 0
    n = len(data)
    while pos + 4 <= n:
        attr_type, attr_len = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + attr_len > n:
            break
        val = data[pos : pos + attr_len]
        pos += attr_len
        if attr_type == 0x1021:  # Manufacturer
            s = val.decode("utf-8", errors="ignore").strip("\x00 ").strip()
            if s:
                info["manufacturer"] = s
        elif attr_type == 0x1023:  # Model Name
            s = val.decode("utf-8", errors="ignore").strip("\x00 ").strip()
            if s:
                info["model_name"] = s
        elif attr_type == 0x1024:  # Model Number
            s = val.decode("utf-8", errors="ignore").strip("\x00 ").strip()
            if s:
                info["model_number"] = s
        elif attr_type == 0x1011:  # Device Name
            s = val.decode("utf-8", errors="ignore").strip("\x00 ").strip()
            if s:
                info["device_name"] = s
        elif attr_type == 0x1042:  # Serial Number
            s = val.decode("utf-8", errors="ignore").strip("\x00 ").strip()
            if s:
                info["serial"] = s
        elif attr_type == 0x1057 and attr_len >= 1:  # AP Setup Locked
            info["ap_setup_locked"] = bool(val[0])
    return info


def _parse_ies(ies_bytes: bytes) -> tuple[str | None, dict, str]:
    """
    Recorre los Information Elements (IEs) de una trama de gestión 802.11.
    Devuelve: (ssid_str | None, wps_info_dict, ie_fingerprint_str)
    """
    pos = 0
    n = len(ies_bytes)
    ssid = None
    wps_info = {}
    fp_tokens = []

    while pos + 2 <= n:
        tag = ies_bytes[pos]
        tlen = ies_bytes[pos + 1]
        pos += 2
        if pos + tlen > n:
            break
        val = ies_bytes[pos : pos + tlen]
        pos += tlen

        if tag == 0:  # SSID
            if tlen > 0 and any(b != 0 for b in val):
                ssid = val.decode("utf-8", errors="replace")
            fp_tokens.append("0")
        elif tag == 45 and tlen >= 2:  # HT Capabilities
            ht_cap = struct.unpack_from("<H", val, 0)[0]
            fp_tokens.append(f"45:{ht_cap:04X}")
        elif tag == 127 and tlen >= 1:  # Extended Capabilities
            fp_tokens.append(f"127:{val[:min(4, tlen)].hex().upper()}")
        elif tag == 221 and tlen >= 4:  # Vendor Specific
            oui = val[:3].hex().upper()
            vtype = val[3]
            fp_tokens.append(f"221:{oui}:{vtype:02X}")
            # Microsoft WPS OUI: 00:50:F2, type 0x04
            if val[:4] == b"\x00\x50\xf2\x04":
                wps_info.update(_parse_wps_tlvs(val[4:]))
        else:
            fp_tokens.append(str(tag))

    fp_str = ""
    if fp_tokens:
        raw_sig = ",".join(fp_tokens)
        short_hash = hashlib.sha1(raw_sig.encode("utf-8")).hexdigest()[:8].upper()
        fp_str = f"IE-{short_hash}"
    return ssid, wps_info, fp_str


def _extract_pmkid_from_key_data(key_data: bytes) -> bytes | None:
    """Busca el KDE de PMKID (0xDD + len + 00:0F:AC:04 + 16B PMKID) en EAPOL M1."""
    pos = 0
    n = len(key_data)
    while pos + 2 <= n:
        tag = key_data[pos]
        tlen = key_data[pos + 1]
        pos += 2
        if pos + tlen > n:
            break
        val = key_data[pos : pos + tlen]
        pos += tlen
        if tag == 0xDD and tlen >= 20 and val[:4] == b"\x00\x0f\xac\x04":
            pmkid = val[4:20]
            if any(b != 0 for b in pmkid):
                return pmkid
    return None


def _parse_eapol_key(eapol_frame: bytes) -> dict | None:
    """
    Analiza un paquete EAPOL-Key (a partir de la cabecera EAPOL de 4 bytes:
    version[1], type[1]=3, body_len[2]).
    """
    if len(eapol_frame) < 4 + 95:
        return None
    ver, pkt_type, body_len = struct.unpack_from(">BBH", eapol_frame, 0)
    if pkt_type != 3:  # 3 = EAPOL-Key
        return None
    total_eapol_len = 4 + body_len
    if len(eapol_frame) < total_eapol_len:
        total_eapol_len = len(eapol_frame)
    eapol_clean = eapol_frame[:total_eapol_len]

    desc_type = eapol_clean[4]
    if desc_type not in (2, 254):  # RSN (2) o WPA1 (254)
        return None

    key_info, key_len, replay_counter = struct.unpack_from(">HHQ", eapol_clean, 5)
    key_nonce = eapol_clean[17:49]
    key_mic = eapol_clean[81:97]
    key_data_len = struct.unpack_from(">H", eapol_clean, 97)[0]
    key_data = eapol_clean[99 : min(len(eapol_clean), 99 + key_data_len)]

    ack = (key_info & (1 << 7)) != 0
    mic = (key_info & (1 << 8)) != 0
    secure = (key_info & (1 << 9)) != 0
    install = (key_info & (1 << 6)) != 0

    msg_num = 0
    if ack and not mic:
        msg_num = 1
    elif not ack and mic:
        if not secure and key_data_len > 0 and any(b != 0 for b in key_nonce):
            msg_num = 2
        else:
            msg_num = 4
    elif ack and mic:
        msg_num = 3

    pmkid = _extract_pmkid_from_key_data(key_data) if msg_num == 1 else None

    # Copia de la trama EAPOL con el campo MIC puesto a cero (para si se requiere validar)
    return {
        "ver": ver,
        "key_ver": key_info & 0x07,
        "msg_num": msg_num,
        "replay": replay_counter,
        "nonce": key_nonce,
        "mic": key_mic,
        "key_data": key_data,
        "pmkid": pmkid,
        "raw": eapol_clean,
    }


def inspect_pcap_files(pcap_paths: list[Path]) -> dict:
    """
    Inspecciona una lista de ficheros .pcap y devuelve un diccionario enriquecido:
    - ap_pcap_traces: bssid -> set de etiquetas ("BEACON", "EAPOL", "PMKID", "HANDSHAKE", ...)
    - ap_pcap_frames: bssid -> int
    - sta_pcap_traces: sta -> set de etiquetas
    - sta_pcap_frames: sta -> int
    - ap_wps_info: bssid -> dict (manufacturer, model_name, device_name, ap_setup_locked...)
    - ap_deauth_reasons: bssid -> list de strings con las razones de deauth observadas
    - sta_ie_fp: sta -> string "IE-XXXXXXXX"
    - ap_ssids: bssid -> bytes (SSID crudo capturado en Beacon/ProbeResp/AssocReq)
    - handshakes: lista de dicts con los handshakes/PMKIDs listos para exportar a hc22000
    """
    ap_pcap_traces = defaultdict(set)
    ap_pcap_frames = Counter()
    sta_pcap_traces = defaultdict(set)
    sta_pcap_frames = Counter()
    ap_wps_info = defaultdict(dict)
    ap_deauth_reasons = defaultdict(set)
    sta_ie_fp = {}
    ap_ssids = {}

    # Almacenamiento temporal de mensajes EAPOL por (bssid_bytes, sta_bytes)
    eapol_m1_by_pair = defaultdict(list)
    eapol_m2_by_pair = defaultdict(list)
    eapol_msgs_seen = defaultdict(set)  # bssid_str -> {"M1", "M2", ...}
    sta_eapol_msgs = defaultdict(set)   # sta_str -> {"M1", "M2", ...}
    pmkids_found = {}                   # (bssid_bytes, sta_bytes) -> pmkid_bytes

    total_packets = 0

    for pcap_path in pcap_paths:
        try:
            data = pcap_path.read_bytes()
        except Exception:
            continue
        if len(data) < 24:
            continue

        magic, vmaj, vmin, tz, sigfigs, snaplen, dlt = struct.unpack_from("<IHHiIII", data, 0)
        if magic not in (0xA1B2C3D4, 0xA1B23C4D):
            continue

        pos = 24
        total_len = len(data)

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
            elif dlt == 105:
                dot11 = pkt
            else:
                continue

            if len(dot11) < 24:
                continue

            total_packets += 1
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
                if subtype == 0x08:  # Beacon
                    trace_type = "BEACON"
                    bssid = addr3
                    if len(dot11) > 36:
                        ssid_s, wps, _ = _parse_ies(dot11[36:])
                        if ssid_s and bssid not in ap_ssids:
                            ap_ssids[bssid] = ssid_s.encode("utf-8", errors="ignore")
                        if wps and not is_mcast_or_zero(bssid):
                            ap_wps_info[fmt_mac(bssid)].update(wps)
                elif subtype == 0x04:  # Probe Req
                    trace_type = "PROBE_REQ"
                    sta = addr2
                    if len(dot11) > 24 and not is_mcast_or_zero(sta):
                        _, _, fp = _parse_ies(dot11[24:])
                        if fp:
                            sta_ie_fp[fmt_mac(sta)] = fp
                elif subtype == 0x05:  # Probe Resp
                    trace_type = "PROBE_RESP"
                    bssid = addr3
                    sta = addr1
                    if len(dot11) > 36:
                        ssid_s, wps, _ = _parse_ies(dot11[36:])
                        if ssid_s and bssid not in ap_ssids:
                            ap_ssids[bssid] = ssid_s.encode("utf-8", errors="ignore")
                        if wps and not is_mcast_or_zero(bssid):
                            ap_wps_info[fmt_mac(bssid)].update(wps)
                elif subtype in (0x00, 0x02):  # Assoc / Reassoc Req
                    trace_type = "ASSOC"
                    bssid = addr1
                    sta = addr2
                    ie_off = 28 if subtype == 0x00 else 34
                    if len(dot11) > ie_off:
                        ssid_s, _, fp = _parse_ies(dot11[ie_off:])
                        if ssid_s and bssid not in ap_ssids:
                            ap_ssids[bssid] = ssid_s.encode("utf-8", errors="ignore")
                        if fp and not is_mcast_or_zero(sta):
                            sta_ie_fp[fmt_mac(sta)] = fp
                elif subtype in (0x01, 0x03):  # Assoc / Reassoc Resp
                    trace_type = "ASSOC"
                    bssid = addr3
                    sta = addr1
                elif subtype == 0x0B:  # Auth
                    trace_type = "AUTH"
                    bssid = addr3
                    sta = addr2 if addr1 == addr3 else addr1
                elif subtype in (0x0A, 0x0C):  # Disassoc / Deauth
                    trace_type = "DEAUTH"
                    bssid = addr3
                    sta = addr2 if addr1 == addr3 else addr1
                    if len(dot11) >= 26 and not is_mcast_or_zero(bssid):
                        rc = struct.unpack_from("<H", dot11, 24)[0]
                        ap_deauth_reasons[fmt_mac(bssid)].add(DEAUTH_REASONS.get(rc, f"Code {rc}"))
                elif subtype == 0x0D:  # Action
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

                mac_hdr_len = 24
                if to_ds and from_ds:
                    mac_hdr_len += 6
                if (subtype & 0x08) != 0:
                    mac_hdr_len += 2
                    if (fc1 & 0x80) != 0:
                        mac_hdr_len += 4

                llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
                if len(dot11) >= mac_hdr_len + 8 and dot11[mac_hdr_len : mac_hdr_len + 8] == llc_snap:
                    trace_type = "EAPOL"
                    eapol_payload = dot11[mac_hdr_len + 8 :]
                    ep = _parse_eapol_key(eapol_payload)
                    if ep and bssid and sta and not is_mcast_or_zero(bssid) and not is_mcast_or_zero(sta):
                        b_str = fmt_mac(bssid)
                        s_str = fmt_mac(sta)
                        mnum = ep["msg_num"]
                        if mnum > 0:
                            eapol_msgs_seen[b_str].add(f"M{mnum}")
                            sta_eapol_msgs[s_str].add(f"M{mnum}")
                        if mnum == 1:
                            eapol_m1_by_pair[(bssid, sta)].append(ep)
                            if ep["pmkid"]:
                                pmkids_found[(bssid, sta)] = ep["pmkid"]
                                ap_pcap_traces[b_str].add("PMKID")
                                sta_pcap_traces[s_str].add("PMKID")
                        elif mnum == 2:
                            eapol_m2_by_pair[(bssid, sta)].append(ep)
                else:
                    trace_type = "DATA"

            if not trace_type:
                continue

            if bssid and not is_mcast_or_zero(bssid):
                b_str = fmt_mac(bssid)
                ap_pcap_traces[b_str].add(trace_type)
                ap_pcap_frames[b_str] += 1

            if sta and not is_mcast_or_zero(sta) and sta != bssid:
                s_str = fmt_mac(sta)
                sta_pcap_traces[s_str].add(trace_type)
                sta_pcap_frames[s_str] += 1

    # Construir líneas hc22000 (WPA*01 para PMKID y WPA*02 para 4-Way Handshake M1+M2)
    handshakes = []
    hc22000_lines = []

    for (bssid_b, sta_b), pmkid_b in pmkids_found.items():
        b_str = fmt_mac(bssid_b)
        s_str = fmt_mac(sta_b)
        essid_b = ap_ssids.get(bssid_b, b"")
        line = (
            f"WPA*01*{pmkid_b.hex()}*{bssid_b.hex()}*{sta_b.hex()}*"
            f"{essid_b.hex()}***01"
        )
        hc22000_lines.append(line)
        handshakes.append({
            "type": "PMKID (WPA*01)",
            "bssid": b_str,
            "sta_mac": s_str,
            "ssid": essid_b.decode("utf-8", errors="replace"),
            "hc22000": line,
        })

    for (bssid_b, sta_b), m2_list in eapol_m2_by_pair.items():
        m1_list = eapol_m1_by_pair.get((bssid_b, sta_b), [])
        if not m1_list or not m2_list:
            continue
        b_str = fmt_mac(bssid_b)
        s_str = fmt_mac(sta_b)
        ap_pcap_traces[b_str].add("HANDSHAKE")
        sta_pcap_traces[s_str].add("HANDSHAKE")

        m1 = m1_list[-1]
        m2 = m2_list[-1]
        essid_b = ap_ssids.get(bssid_b, b"")
        line = (
            f"WPA*02*{m2['mic'].hex()}*{bssid_b.hex()}*{sta_b.hex()}*"
            f"{essid_b.hex()}*{m1['nonce'].hex()}*{m2['raw'].hex()}*02"
        )
        hc22000_lines.append(line)
        handshakes.append({
            "type": "4-Way Handshake (WPA*02)",
            "bssid": b_str,
            "sta_mac": s_str,
            "ssid": essid_b.decode("utf-8", errors="replace"),
            "hc22000": line,
        })

    return {
        "total_packets": total_packets,
        "ap_pcap_traces": ap_pcap_traces,
        "ap_pcap_frames": ap_pcap_frames,
        "sta_pcap_traces": sta_pcap_traces,
        "sta_pcap_frames": sta_pcap_frames,
        "ap_wps_info": dict(ap_wps_info),
        "ap_deauth_reasons": {k: sorted(v) for k, v in ap_deauth_reasons.items()},
        "ap_eapol_msgs": {k: sorted(v) for k, v in eapol_msgs_seen.items()},
        "sta_eapol_msgs": {k: sorted(v) for k, v in sta_eapol_msgs.items()},
        "sta_ie_fp": sta_ie_fp,
        "handshakes": handshakes,
        "hc22000_lines": hc22000_lines,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="waraudit — Triaje Red Team de capturas PCAP (EAPOL Handshakes, PMKID, WPS, IE-Fingerprints)"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Archivos .pcap o directorios (por defecto busca en wardrive_data/pcap)",
    )
    parser.add_argument(
        "--hc22000",
        type=Path,
        default=None,
        help="Exportar hashes WPA*01/WPA*02 a archivo .hc22000 (para hashcat -m 22000)",
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        default=None,
        help="Ejecutar auditoría de diccionario con aircrack-ng / hashcat sobre los handshakes capturados",
    )
    args = parser.parse_args(argv)

    pcap_files = []
    if args.paths:
        for p in args.paths:
            if p.is_dir():
                pcap_files.extend(sorted(p.rglob("*.pcap")))
            elif p.is_file() and p.suffix.lower() == ".pcap":
                pcap_files.append(p)
    else:
        for cand in (
            Path("/home/Kta41/wardrive/wardrive_data"),
            Path("./wardrive_data"),
            Path("./captures"),
            Path("/data"),
        ):
            if cand.is_dir():
                found = sorted(cand.rglob("*.pcap"))
                if found:
                    pcap_files.extend(found)
                    break

    if not pcap_files:
        print("[waraudit] No se encontraron archivos .pcap para auditar.")
        return 0

    res = inspect_pcap_files(pcap_files)
    print(f"\n\033[1;36m================ WARAUDIT — TRIAJE PCAP & RED TEAM ================\033[0m")
    print(f"Archivos PCAP analizados : {len(pcap_files)}")
    print(f"Paquetes 802.11 totales  : {res['total_packets']}")
    print(f"BSSIDs con trazas PCAP   : {len(res['ap_pcap_traces'])}")
    print(f"Clientes con IE-Hash     : {len(res['sta_ie_fp'])}")
    print(f"Material WPA extraíble   : {len(res['handshakes'])} (PMKID / 4-Way Handshakes)\n")

    if res["ap_wps_info"]:
        print("\033[1;33m[Hardware / Modelo Real Extraído de Balizas WPS]\033[0m")
        for bssid, winfo in sorted(res["ap_wps_info"].items()):
            desc = " · ".join(f"{k}={v}" for k, v in winfo.items())
            print(f"  {bssid} -> {desc}")
        print()

    if res["ap_deauth_reasons"]:
        print("\033[1;31m[Tramas Deauth / Disassoc y Códigos de Razón IEEE 802.11]\033[0m")
        for bssid, reasons in sorted(res["ap_deauth_reasons"].items()):
            print(f"  {bssid} -> {', '.join(reasons)}")
        print()

    if res["handshakes"]:
        print("\033[1;32m[Material Criptográfico Capturado (Listo para Hashcat -m 22000)]\033[0m")
        for h in res["handshakes"]:
            print(f"  • [{h['type']}] BSSID={h['bssid']} <-> STA={h['sta_mac']} (SSID='{h['ssid']}')")
        out_hc = args.hc22000
        if out_hc is None:
            out_hc = pcap_files[0].resolve().parent / "handshakes.hc22000"
        out_hc.write_text("\n".join(res["hc22000_lines"]) + "\n", encoding="utf-8")
        print(f"\n  -> Hashes exportados en: \033[1;32m{out_hc}\033[0m")
        print(f"     Comando en PC: hashcat -m 22000 {out_hc} wordlist.txt")
    else:
        print("\033[0;37m[Material Criptográfico WPA]\033[0m Ningún handshake EAPOL completo o PMKID en los PCAP actuales.")

    # Si hcxpcapngtool está instalado en el sistema (Kali NetHunter), ofrecer/ejecutar conversión adicional
    hcx_bin = shutil.which("hcxpcapngtool")
    if hcx_bin and pcap_files:
        hcx_out = pcap_files[0].resolve().parent / "hcx_dump.hc22000"
        subprocess.run(
            [hcx_bin, "-o", str(hcx_out), *[str(f) for f in pcap_files]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if hcx_out.exists() and hcx_out.stat().st_size > 0:
            print(f"  -> hcxpcapngtool verificó y exportó: {hcx_out}")

    if args.wordlist and args.wordlist.exists() and res["handshakes"]:
        aircrack_bin = shutil.which("aircrack-ng")
        if aircrack_bin:
            print(f"\n[waraudit] Ejecutando aircrack-ng con diccionario {args.wordlist} ...")
            subprocess.run([aircrack_bin, "-w", str(args.wordlist), *[str(f) for f in pcap_files]], check=False)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
