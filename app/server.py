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
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
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


class HubState:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.tags_path = self.data_dir / "tags.json"
        self.lock = threading.Lock()
        self.seen = set()

    def list_jsonl_files(self):
        return sorted(self.data_dir.glob("*.jsonl"))

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

    def import_jsonl_content(self, raw_text: str, filename_hint: str = None) -> dict:
        lines = [ln.strip() for ln in raw_text.splitlines() if ln.strip()]
        if not lines:
            raise ValueError("El archivo está vacío")

        imported = 0
        target_name = None
        if filename_hint:
            safe = "".join(c for c in Path(filename_hint).name if c.isalnum() or c in ("_", "-", "."))
            if safe.endswith(".jsonl"):
                target_name = safe
        if not target_name:
            target_name = f"wardrive_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"

        target_path = self.data_dir / target_name
        out_lines = []

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
            out_lines.append(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n")
            imported += 1

        with self.lock:
            with target_path.open("a", encoding="utf-8") as fh:
                fh.writelines(out_lines)
                fh.flush()

        return {"imported": imported, "file": target_path.name}


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
                self._send_json(200, {
                    "status": "ok",
                    "service": "SIGINT-Console",
                    "files": [f.name for f in files],
                    "count": len(files),
                })
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

            self._send_json(404, {"error": "not found"})

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path

            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_UPLOAD_BYTES:
                    self._send_json(400, {"error": "Content-Length fuera de rango"})
                    return
                raw_body = self.rfile.read(length).decode("utf-8")
            except Exception as exc:
                self._send_json(400, {"error": f"Error leyendo body: {exc}"})
                return

            if path == "/api/tags":
                try:
                    payload = json.loads(raw_body)
                    saved = hub.save_tags(payload)
                    self._send_json(200, {"saved": True, "tags": saved})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path in ("/api/import", "/scans"):
                qs = parse_qs(parsed.query)
                fname = qs.get("filename", [None])[0]
                try:
                    res = hub.import_jsonl_content(raw_body, filename_hint=fname)
                    self._send_json(200, {"accepted": res["imported"], **res})
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
    parser.add_argument("--port", type=int, default=int(os.environ.get("SIGINT_PORT", "8080")))
    parser.add_argument("--https-port", type=int, default=int(os.environ.get("SIGINT_HTTPS_PORT", "8443")))
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
