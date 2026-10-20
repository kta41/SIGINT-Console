#!/usr/bin/env python3
"""
server.py — Servidor Central de Inteligencia SIGINT-Console.

Capacidades:
- `GET /`               : Renderiza en vivo la Consola Web SIGINT sobre todos los `.jsonl` de `/data`.
- `GET /api/dataset`    : Devuelve el dataset de inteligencia correlacionado en JSON.
- `GET /api/tags`       : Lee las etiquetas persistentes de `/data/tags.json`.
- `POST /api/tags`      : Guarda automáticamente las etiquetas/nombres de sesiones, redes y dispositivos en `/data/tags.json`.
- `POST /api/import`    : Importa ficheros `.jsonl` subidos desde el navegador o vía `curl`.
- `POST /scans`         : Endpoint compatible con el sensor ESP32-S3 (`Wifi-Wardriving`) para ingesta directa.
- `GET /export/csv`     : Descarga el catálogo único de BSSIDs en CSV.
- `GET /export/wigle`   : Descarga en formato oficial WiGLE CSV v1.4.
- `GET /health`         : Estado del servicio y recuento de sesiones/archivos.
"""

import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import struct
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs, urlparse

from dual_socket import DualModeServerMixin
import engine
from validator import now_iso_ms, validate_scan_payload


class DualThreadingHTTPServer(DualModeServerMixin, ThreadingHTTPServer):
    pass

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
SIGINT_MAGIC = "SIGINT-CONSOLE-V1"


class HubState:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.jsonl_dir = self.data_dir / "jsonl"
        self.pcap_dir = self.data_dir / "pcap"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_dir.mkdir(parents=True, exist_ok=True)
        self.pcap_dir.mkdir(parents=True, exist_ok=True)
        self.tags_path = self.data_dir / "tags.json"
        self.lock = threading.Lock()
        self.seen = set()  # (session_id, scan_id)
        self.session_files = {}  # session_id -> Path
        self._rebuild_seen_index()

    def _rebuild_seen_index(self):
        self.seen.clear()
        self.session_files.clear()
        for f in self.list_jsonl_files():
            try:
                with f.open("r", encoding="utf-8") as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line:
                            continue
                        obj = json.loads(line)
                        payload = obj.get("payload", obj) if isinstance(obj, dict) else {}
                        sid = payload.get("session_id")
                        scan_id = payload.get("scan_id")
                        if isinstance(sid, str) and isinstance(scan_id, int):
                            self.seen.add((sid, scan_id))
                            self.session_files[sid] = f
            except Exception:
                continue

    def list_jsonl_files(self):
        root_files = list(self.data_dir.glob("*.jsonl"))
        sub_files = list(self.jsonl_dir.glob("*.jsonl"))
        seen_names = set()
        result = []
        for f in sorted(sub_files + root_files, key=lambda p: p.name):
            if f.name not in seen_names:
                seen_names.add(f.name)
                result.append(f)
        return result

    def list_pcap_files(self):
        root_files = list(self.data_dir.glob("*.pcap"))
        sub_files = list(self.pcap_dir.glob("*.pcap"))
        seen_names = set()
        result = []
        for f in sorted(sub_files + root_files, key=lambda p: p.name):
            if f.name not in seen_names:
                seen_names.add(f.name)
                result.append(f)
        return result

    def sync_status(self) -> dict:
        with self.lock:
            self._rebuild_seen_index()
            sessions_info = defaultdict(lambda: {"max_scan_id": 0, "scan_count": 0, "scan_ids": []})
            for sid, scan_id in sorted(self.seen):
                entry = sessions_info[sid]
                entry["scan_count"] += 1
                if scan_id > entry["max_scan_id"]:
                    entry["max_scan_id"] = scan_id
                entry["scan_ids"].append(scan_id)

            pcaps_info = {}
            for pf in self.list_pcap_files():
                try:
                    raw = pf.read_bytes()
                    pcaps_info[pf.name] = {
                        "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                except Exception:
                    continue

            return {
                "magic": SIGINT_MAGIC,
                "status": "ready",
                "sessions": dict(sessions_info),
                "pcap_files": pcaps_info,
                "total_jsonl_files": len(self.list_jsonl_files()),
                "total_pcap_files": len(pcaps_info),
            }

    def load_tags(self) -> dict:
        if self.tags_path.exists():
            try:
                raw = json.loads(self.tags_path.read_text(encoding="utf-8"))
                return {
                    "sessions": raw.get("sessions", {}),
                    "networks": raw.get("networks", {}),
                    "devices": raw.get("devices", {}),
                }
            except Exception:
                pass
        return {"sessions": {}, "networks": {}, "devices": {}}

    def save_tags(self, new_tags: dict) -> dict:
        clean = {
            "sessions": new_tags.get("sessions", {}) if isinstance(new_tags, dict) else {},
            "networks": new_tags.get("networks", {}) if isinstance(new_tags, dict) else {},
            "devices": new_tags.get("devices", {}) if isinstance(new_tags, dict) else {},
        }
        with self.lock:
            self.tags_path.write_text(
                json.dumps(clean, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        return clean

    def merge_tags(self, incoming_tags: dict) -> dict:
        if not isinstance(incoming_tags, dict):
            return self.load_tags()
        with self.lock:
            current = self.load_tags()
            for grp in ("sessions", "networks", "devices"):
                inc_grp = incoming_tags.get(grp, {})
                if isinstance(inc_grp, dict):
                    for k, v in inc_grp.items():
                        if isinstance(v, dict):
                            cur_entry = current[grp].setdefault(k, {})
                            for fk, fv in v.items():
                                if fv not in (None, "") or fk not in cur_entry:
                                    cur_entry[fk] = fv
            self.tags_path.write_text(
                json.dumps(current, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return current

    def build_current_dataset(self):
        files = self.list_jsonl_files()
        tags = self.load_tags()
        aps, sightings, sessions, total_scans, promisc_data = engine.load_records(files)
        dataset = engine.build_intelligence_dataset(
            aps, sightings, sessions, total_scans, promisc_data, tags
        )
        return dataset, tags, aps, sightings, promisc_data

    def render_dashboard_bytes(self) -> bytes:
        dataset, tags, _, _, _ = self.build_current_dataset()
        with tempfile.NamedTemporaryFile("w+", suffix=".html", delete=False, encoding="utf-8") as tmp:
            tmp_path = Path(tmp.name)
        try:
            engine.render_sigint_dashboard(dataset, tags, tmp_path)
            return tmp_path.read_bytes()
        finally:
            tmp_path.unlink(missing_ok=True)

    def _resolve_target_jsonl(self, session_id: str, filename_hint: str = None) -> Path:
        if session_id and session_id in self.session_files:
            return self.session_files[session_id]
        if filename_hint:
            safe = "".join(c for c in Path(filename_hint).name if c.isalnum() or c in ("_", "-", "."))
            if safe.endswith(".jsonl"):
                root_cand = self.data_dir / safe
                if root_cand.exists():
                    return root_cand
                return self.jsonl_dir / safe
        if session_id:
            return self.jsonl_dir / f"wardrive_{datetime.now().strftime('%Y%m%d_%H%M')}_{session_id}.jsonl"
        return self.jsonl_dir / f"wardrive_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"

    def import_jsonl_content(self, raw_text: str, filename_hint: str = None) -> dict:
        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        if not lines:
            raise ValueError("El archivo está vacío")

        imported = 0
        skipped_duplicates = 0
        grouped_writes = defaultdict(list)

        with self.lock:
            for idx, line in enumerate(lines, start=1):
                obj = json.loads(line)
                if isinstance(obj, dict) and "payload" in obj:
                    payload = obj["payload"]
                    envelope = obj
                    if "recv_at" not in envelope:
                        envelope["recv_at"] = now_iso_ms()
                else:
                    payload = obj
                    envelope = {
                        "recv_at": now_iso_ms(),
                        "gps": None,
                        "payload": payload,
                    }
                validate_scan_payload(payload)
                key = (payload["session_id"], payload["scan_id"])
                if key in self.seen:
                    skipped_duplicates += 1
                    continue

                self.seen.add(key)
                target_path = self._resolve_target_jsonl(payload["session_id"], filename_hint)
                self.session_files[payload["session_id"]] = target_path
                grouped_writes[target_path].append(
                    json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
                imported += 1

            written_files = []
            for path, out_lines in grouped_writes.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as fh:
                    fh.writelines(out_lines)
                    fh.flush()
                written_files.append(path.name)

        return {
            "imported": imported,
            "skipped_duplicates": skipped_duplicates,
            "file": written_files[0] if written_files else (filename_hint or ""),
            "files": written_files,
        }

    def ingest_pcap_bytes(self, raw_bytes: bytes, filename_hint: str = None, session_id: str = "pcap", offset: int = 0) -> dict:
        if not raw_bytes:
            return {"accepted": True, "bytes_written": 0, "file": filename_hint or ""}
        safe = ""
        if filename_hint:
            safe = "".join(c for c in Path(filename_hint).name if c.isalnum() or c in ("_", "-", "."))
        if not safe.endswith(".pcap"):
            safe = f"wardrive_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{session_id}.pcap"

        # Preferir archivo existente en root o en pcap_dir; los nuevos van a pcap_dir
        root_cand = self.data_dir / safe
        target_pcap = root_cand if root_cand.exists() else (self.pcap_dir / safe)

        with self.lock:
            has_global_hdr = len(raw_bytes) >= 4 and raw_bytes[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
            if offset > 0 and target_pcap.exists():
                cur_size = target_pcap.stat().st_size
                if cur_size == offset:
                    with target_pcap.open("ab") as fh:
                        fh.write(raw_bytes)
                        fh.flush()
                    return {"accepted": True, "bytes_written": len(raw_bytes), "file": target_pcap.name, "mode": "delta_append"}
                elif cur_size > offset and cur_size >= offset + len(raw_bytes):
                    return {"accepted": True, "bytes_written": 0, "file": target_pcap.name, "mode": "already_synced"}

            if has_global_hdr:
                if target_pcap.exists() and target_pcap.stat().st_size >= len(raw_bytes):
                    # Si el fichero en servidor ya es igual o mayor con el mismo prefijo, evitar sobrescribir con menos datos
                    existing_prefix = target_pcap.read_bytes()[: min(64, len(raw_bytes))]
                    if existing_prefix == raw_bytes[: len(existing_prefix)]:
                        if len(raw_bytes) > target_pcap.stat().st_size:
                            target_pcap.write_bytes(raw_bytes)
                        return {"accepted": True, "bytes_written": 0, "file": target_pcap.name, "mode": "idempotent_skip"}
                target_pcap.write_bytes(raw_bytes)
                return {"accepted": True, "bytes_written": len(raw_bytes), "file": target_pcap.name, "mode": "full_write"}
            else:
                if not target_pcap.exists() or target_pcap.stat().st_size == 0:
                    target_pcap.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
                with target_pcap.open("ab") as fh:
                    fh.write(raw_bytes)
                    fh.flush()
                return {"accepted": True, "bytes_written": len(raw_bytes), "file": target_pcap.name, "mode": "record_append"}


def make_handler(hub: HubState):
    class Handler(BaseHTTPRequestHandler):
        def _send_bytes(self, status: int, content_type: str, data: bytes, extra_headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            # Limpiar cualquier caché HSTS previa en el navegador para este origen
            self.send_header("Strict-Transport-Security", "max-age=0")
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _send_json(self, status: int, obj: dict):
            raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self._send_bytes(status, "application/json; charset=utf-8", raw)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path

            if path in ("/", "/index.html", "/dashboard.html"):
                body = hub.render_dashboard_bytes()
                self._send_bytes(200, "text/html; charset=utf-8", body)
                return

            if path == "/health":
                files = hub.list_jsonl_files()
                pcaps = hub.list_pcap_files()
                self._send_json(200, {
                    "status": "ok",
                    "magic": SIGINT_MAGIC,
                    "service": "SIGINT-Console",
                    "files": [f.name for f in files],
                    "pcap_files": [f.name for f in pcaps],
                    "count": len(files),
                    "pcap_count": len(pcaps),
                })
                return

            if path == "/api/sync/status":
                self._send_json(200, hub.sync_status())
                return

            if path.startswith("/export/pcap/"):
                req_name = Path(path[len("/export/pcap/"):]).name
                for pf in hub.list_pcap_files():
                    if pf.name == req_name:
                        self._send_bytes(
                            200,
                            "application/vnd.tcpdump.pcap",
                            pf.read_bytes(),
                            {"Content-Disposition": f'attachment; filename="{pf.name}"'},
                        )
                        return
                self._send_json(404, {"error": "pcap not found"})
                return

            if path == "/api/dataset":
                dataset, tags, _, _, _ = hub.build_current_dataset()
                self._send_json(200, {"dataset": dataset, "tags": tags})
                return

            if path == "/api/tags":
                self._send_json(200, hub.load_tags())
                return

            if path == "/export/csv":
                _, tags, aps, sightings, promisc_data = hub.build_current_dataset()
                with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False, encoding="utf-8") as tmp:
                    tmp_path = Path(tmp.name)
                try:
                    engine.export_csv(aps, sightings, promisc_data, tmp_path, tags)
                    self._send_bytes(
                        200,
                        "text/csv; charset=utf-8",
                        tmp_path.read_bytes(),
                        {"Content-Disposition": 'attachment; filename="redes.csv"'},
                    )
                finally:
                    tmp_path.unlink(missing_ok=True)
                return

            if path == "/export/wigle":
                _, tags, aps, _, promisc_data = hub.build_current_dataset()
                with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False, encoding="utf-8") as tmp:
                    tmp_path = Path(tmp.name)
                try:
                    engine.export_wigle(aps, promisc_data, tmp_path, tags)
                    self._send_bytes(
                        200,
                        "text/csv; charset=utf-8",
                        tmp_path.read_bytes(),
                        {"Content-Disposition": 'attachment; filename="wigle.csv"'},
                    )
                finally:
                    tmp_path.unlink(missing_ok=True)
                return

            if path == "/export/hc22000":
                dataset, _, _, _, _ = hub.build_current_dataset()
                lines = dataset.get("hc22000_lines", [])
                content = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
                self._send_bytes(
                    200,
                    "text/plain; charset=utf-8",
                    content,
                    {"Content-Disposition": 'attachment; filename="handshakes.hc22000"'},
                )
                return

            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path

            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_UPLOAD_BYTES:
                    self._send_json(400, {"error": "Content-Length fuera de rango"})
                    return
                raw_bytes = self.rfile.read(length)
            except Exception as exc:
                self._send_json(400, {"error": f"Error leyendo body: {exc}"})
                return

            if path in ("/api/import_pcap", "/pcap", "/api/sync/pcap"):
                qs = parse_qs(parsed.query)
                fname = qs.get("filename", [None])[0]
                try:
                    offset = int(qs.get("offset", ["0"])[0])
                except ValueError:
                    offset = 0
                sid = (self.headers.get("X-Session-Id") or qs.get("session_id", ["pcap"])[0]).strip()
                res = hub.ingest_pcap_bytes(raw_bytes, filename_hint=fname, session_id=sid, offset=offset)
                self._send_json(200, res)
                return

            try:
                raw_body = raw_bytes.decode("utf-8")
            except Exception as exc:
                self._send_json(400, {"error": f"UTF-8 inválido: {exc}"})
                return

            if path == "/api/tags":
                try:
                    payload = json.loads(raw_body)
                    saved = hub.save_tags(payload)
                    self._send_json(200, {"saved": True, "tags": saved})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path == "/api/sync/tags":
                try:
                    payload = json.loads(raw_body)
                    merged = hub.merge_tags(payload)
                    self._send_json(200, {"merged": True, "tags": merged})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path in ("/api/import", "/scans", "/api/sync/push"):
                qs = parse_qs(parsed.query)
                fname = qs.get("filename", [None])[0]
                try:
                    res = hub.import_jsonl_content(raw_body, filename_hint=fname)
                    self._send_json(200, {"accepted": res["imported"] + res["skipped_duplicates"], **res})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc), "first_bad_scan_id": 0})
                return

            self._send_json(404, {"error": "not found"})

        def log_message(self, fmt, *args):
            print(f"[{now_iso_ms()}] {self.client_address[0]} - {fmt % args}", flush=True)

    return Handler


def _ensure_self_signed_cert(cert_dir: Path) -> tuple[Path, Path]:
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_file = cert_dir / "localhost.crt"
    key_file = cert_dir / "localhost.key"
    if not cert_file.exists() or not key_file.exists():
        subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", str(key_file),
                "-out", str(cert_file),
                "-days", "3650",
                "-subj", "/CN=localhost",
                "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:192.168.1.142",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return cert_file, key_file


def main():
    parser = argparse.ArgumentParser(description="SIGINT-Console — Servidor de Inteligencia Inalámbrica")
    parser.add_argument("--host", default=os.environ.get("SIGINT_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SIGINT_PORT", "47891")))
    parser.add_argument("--https-port", type=int, default=int(os.environ.get("SIGINT_HTTPS_PORT", "47892")))
    parser.add_argument("--data", type=Path, default=Path(os.environ.get("SIGINT_DATA_DIR", "/data")))
    args = parser.parse_args()

    hub = HubState(data_dir=args.data)
    handler_cls = make_handler(hub)

    tls_ctx = None
    try:
        cert_file, key_file = _ensure_self_signed_cert(args.data / ".certs")
        if cert_file.exists() and key_file.exists():
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    except Exception as exc:
        print(f"[warn] No se pudo preparar contexto TLS: {exc}")

    server = DualThreadingHTTPServer((args.host, args.port), handler_cls)
    server.tls_context = tls_ctx
    print(f"📡 SIGINT-Console Dual HTTP/HTTPS activo en http://127.0.0.1:{server.server_address[1]} y https://localhost:{server.server_address[1]} (data={args.data})")

    # Levantar también listener HTTPS opcional en 8443 por si el navegador fuerza HTTPS
    if args.https_port > 0:
        try:
            cert_file, key_file = _ensure_self_signed_cert(args.data / ".certs")
            if cert_file.exists() and key_file.exists():
                https_srv = ThreadingHTTPServer((args.host, args.https_port), handler_cls)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
                https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)
                threading.Thread(target=https_srv.serve_forever, daemon=True).start()
                print(f"🔒 SIGINT-Console HTTPS activo en https://localhost:{args.https_port}")
        except Exception as exc:
            print(f"[warn] HTTPS opcional no iniciado: {exc}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCerrando SIGINT-Console...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
