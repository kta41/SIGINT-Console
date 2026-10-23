#!/usr/bin/env python3
"""
wps_vulndb.py — Heurística de vulnerabilidad WPS (Pixie-Dust / PIN por defecto).

Evalúa los metadatos WPS extraídos de Beacons/ProbeResp (pcap_audit:
manufacturer 0x1021, model 0x1023, device name 0x1011) contra una base
EMBEBIDA de patrones públicos (documentación de reaver/pixiewps e
investigación de C. Heffner / 2011-2015). Sin red, sin dependencias.

⚠️ Es una HEURÍSTICA: un veredicto positivo NO garantiza que el ataque
funcione (los fabricantes parchearon firmwares), y un negativo no garantiza
inmunidad. Úsala para priorizar objetivos en auditorías AUTORIZADAS.
"""

import re

# Coincidencias por subcadena case-insensitive sobre manufacturer/model/name.
# severity CRITICAL = pixie-dust documentado de serie · HIGH = históricamente
# vulnerable o PIN estático de fábrica.
_DB = [
    {
        "match": ["realtek", "rtl8196", "rtl8188", "rtl8192", "rtl8881", "rtl8812"],
        "vector": "PIXIE_DUST",
        "severity": "CRITICAL",
        "why": "SoC Realtek con PRNG débil en E-Hash1/2 (arquitectura EAP clásica): pixiewps documentado",
    },
    {
        "match": ["ralink", "rt5350", "rt3052", "rt3062", "rt3070", "rt3370", "rt5370", "rt5390", "mt7620", "mt7628"],
        "vector": "PIXIE_DUST",
        "severity": "CRITICAL",
        "why": "Ralink/MediaTek (RT/MT76xx) con nonce/PIN predecibles: pixie-dust de serie en muchos firmwares",
    },
    {
        "match": ["broadcom", "bcm47", "bcm43", "bcm53"],
        "vector": "PIXIE_DUST",
        "severity": "HIGH",
        "why": "Broadcom históricamente vulnerable a pixie-dust en firmwares antiguos (verificar versión)",
    },
    {
        "match": ["tenda", "netcore", "hame", "netis", "wavlink", "totolink"],
        "vector": "DEFAULT_PIN",
        "severity": "HIGH",
        "why": "Marcas con historial de PIN de fábrica estático/reconstructor por BSSID (ataque offline inmediato)",
    },
    {
        "match": ["d-link", "dlink", "dir-6", "dir-3", "dir-8"],
        "vector": "PIXIE_DUST",
        "severity": "MEDIUM",
        "why": "D-Link DIR clásicos (Ralink/Realtek OEM): pixie-dust frecuente en HW antiguo",
    },
    {
        "match": ["tplink", "tp-link", "tl-wr", "tl-wa", "tl-wd"],
        "vector": "PIXIE_DUST",
        "severity": "MEDIUM",
        "why": "TP-Link antiguos con SoC Ralink/Qualcomm: pixie-dust frecuente; modernos parcheados",
    },
]

_DEF_CONTRIB = re.compile(r"^(?:\d{7}\d|00000000)$", re.IGNORECASE)


def assess_wps(wps_info: dict, vendor_oui: str = "") -> dict:
    """Devuelve un veredicto de vulnerabilidad para un AP con WPS activo.

    wps_info: dict de pcap_audit (manufacturer, model_name, model_number,
    device_name, wps_locked). vendor_oui: texto de fabricante resuelto por OUI
    (opcional, se une al matching).

    Retorna {"vulnerable": bool, "confidence", "vector", "severity", "why",
    "matched", "locked"} o {"vulnerable": False, ...} si no hay coincidencia.
    """
    info = wps_info if isinstance(wps_info, dict) else {}
    haystack = " ".join(
        str(info.get(k, "")) for k in ("manufacturer", "model_name", "model_number", "device_name")
    )
    if vendor_oui:
        haystack += f" {vendor_oui}"
    haystack_l = haystack.lower()

    best = None
    for entry in _DB:
        for token in entry["match"]:
            if token in haystack_l:
                cand = {
                    "vulnerable": True,
                    "confidence": "ALTA" if entry["severity"] == "CRITICAL" else "MEDIA",
                    "vector": entry["vector"],
                    "severity": entry["severity"],
                    "why": entry["why"],
                    "matched": token,
                }
                if best is None or (cand["severity"] == "CRITICAL" and best["severity"] != "CRITICAL"):
                    best = cand
                break

    if best is None:
        best = {
            "vulnerable": False,
            "confidence": "—",
            "vector": "",
            "severity": "INFO",
            "why": "Sin coincidencia en la base heurística: prueba reaver -K 1 igualmente (5 min)",
            "matched": "",
        }
    best["locked"] = bool(info.get("wps_locked"))
    return best


def summarize(wps_aps: list) -> dict:
    """Resumen agregado: {'pixiedust_probable': N, 'criticos': [bssid, ...]}."""
    criticos = [a.get("bssid", "?") for a in wps_aps if (a.get("wps_verdict") or {}).get("vulnerable")]
    return {"pixiedust_probable": len(criticos), "criticos": criticos}
