import os
import socket
import ssl
import struct
import threading


class DualModeServerMixin:
    """Detecta automáticamente en cada conexión entrante si el cliente habla TLS (0x16)
    o HTTP plano ('G','P','H','O','D') en el MISMO puerto TCP (ej. 8080)."""

    tls_context: ssl.SSLContext | None = None

    def process_request(self, request, client_address):
        if self.tls_context is not None:
            try:
                request.settimeout(2.0)
                first = request.recv(1, socket.MSG_PEEK)
                if first == b"\x16":  # TLS ClientHello record
                    request = self.tls_context.wrap_socket(request, server_side=True)
            except Exception:
                self.close_request(request)
                return
        return super().process_request(request, client_address)
