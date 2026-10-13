#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Panel de Administración Interno - SSRFNest

Servicio Flask que simula un panel de administración interno.
En el laboratorio SSRFNest este servicio es accesible únicamente
desde la red interna Docker, pero la VulnApp permite alcanzarlo
mediante SSRF, demostrando el riesgo de confiar en la segmentación
por red sin autenticación adicional.

Autor: Javier Garrido Ortiz
Licencia: MIT
"""

import os
import socket
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, Response

# DATOS COMPLETAMENTE FICTICIOS - Laboratorio educativo SSRFNest

app = Flask(__name__)

# Marca de arranque para calcular uptime del proceso
_START_TIME = time.time()

# Hostname visible del contenedor (útil para el analista)
_HOSTNAME = socket.gethostname()

# Versión ficticia del panel
_VERSION = "1.4.2-internal"

# Configuración ficticia de base de datos (nunca usar valores reales aquí)
_DB_CONFIG = {
    "db_host": "172.20.0.20",
    "db_port": 5432,
    "db_user": "admin",
    "db_pass": "FICTICIO_DEMO",
    "secret_key": "FICTICIO_DEMO_KEY",
}

# Lista de usuarios ficticios expuestos por el panel
_USERS = [
    {"id": 1, "username": "jgarrido", "role": "admin"},
    {"id": 2, "username": "analista_blue", "role": "analyst"},
    {"id": 3, "username": "operador_red", "role": "operator"},
    {"id": 4, "username": "auditor", "role": "readonly"},
]


def _uptime_human() -> str:
    """Devuelve el uptime del proceso en formato legible."""
    delta = int(time.time() - _START_TIME)
    hours, remainder = divmod(delta, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"


@app.route("/", methods=["GET"])
def index() -> Response:
    """Página principal del panel con datos ficticios del sistema."""
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Panel de Administración Interno</title>
    <style>
        body {{ font-family: monospace; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        h1 {{ color: #38bdf8; }}
        .card {{ background: #1e293b; padding: 1rem 1.5rem; border-radius: 8px; margin-top: 1rem; }}
        dt {{ color: #94a3b8; }}
        dd {{ margin: 0 0 0.5rem 0; color: #f1f5f9; }}
    </style>
</head>
<body>
    <h1>Panel de Administración Interno</h1>
    <p>Bienvenido al panel interno de SSRFNest. Este servicio no debería ser
       accesible desde fuera de la red interna.</p>
    <div class="card">
        <dl>
            <dt>Versión</dt><dd>{_VERSION}</dd>
            <dt>Hostname</dt><dd>{_HOSTNAME}</dd>
            <dt>Uptime</dt><dd>{_uptime_human()}</dd>
            <dt>Fecha UTC</dt><dd>{datetime.now(timezone.utc).isoformat()}</dd>
        </dl>
    </div>
</body>
</html>"""
    return Response(html, mimetype="text/html")


@app.route("/admin", methods=["GET"])
def admin_config() -> Response:
    """Devuelve la configuración ficticia del sistema en JSON."""
    return jsonify(_DB_CONFIG)


@app.route("/users", methods=["GET"])
def list_users() -> Response:
    """Devuelve la lista de usuarios ficticios registrados."""
    return jsonify({"users": _USERS, "count": len(_USERS)})


@app.route("/health", methods=["GET"])
def health() -> Response:
    """Endpoint de salud mínimo para el orquestador."""
    return jsonify({"status": "ok", "service": "adminpanel"})


if __name__ == "__main__":
    # El puerto se puede sobrescribir por variable de entorno
    port = int(os.environ.get("ADMINPANEL_PORT", "9001"))
    # Escucha en todas las interfaces del contenedor (red interna Docker)
    app.run(host="0.0.0.0", port=port, debug=False)
