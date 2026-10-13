#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# DATOS FICTICIOS - Solo para uso en laboratorio educativo
#
# Servicio de metadatos simulado estilo AWS IMDSv1 (SSRFNest).
# Autor: Javier Garrido Ortiz
#
# Este servicio NO debe desplegarse en producción. Todas las credenciales
# devueltas son ficticias y llevan el sufijo EXAMPLE para que sean
# inequívocamente identificables como señuelo.

import os
from datetime import datetime, timedelta, timezone

from flask import Flask, Response, jsonify

app = Flask(__name__)

# Puerto configurable por entorno, por defecto 9000.
PORT = int(os.environ.get("METADATA_PORT", "9000"))

# Rol IAM simulado que expondrá el endpoint.
ROLE_NAME = "ssrfnest-demo-role"

# Valores ficticios asociados a cada clave de metadatos.
META_VALUES = {
    "ami-id": "ami-0abcdef1234567890",
    "instance-id": "i-0abcd1234efgh5678",
    "instance-type": "t3.micro",
    "local-ipv4": "10.10.0.42",
}

# Lista de claves disponibles en la raíz de meta-data.
META_KEYS = [
    "ami-id",
    "instance-id",
    "instance-type",
    "local-ipv4",
    "iam/security-credentials/",
]


def _plain(text: str) -> Response:
    """Devuelve texto plano con el estilo de IMDSv1."""
    return Response(text, mimetype="text/plain")


def _fake_credentials() -> dict:
    """Genera el JSON de credenciales ficticias con expiración dinámica."""
    expiration = datetime.now(timezone.utc) + timedelta(hours=6)
    return {
        "Code": "Success",
        "LastUpdated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Type": "AWS-HMAC",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEExampleTokenFicticioParaSSRFNestLab",
        "Expiration": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@app.get("/latest/meta-data/")
def list_meta_keys() -> Response:
    """Lista de claves disponibles, una por línea (formato IMDSv1)."""
    return _plain("\n".join(META_KEYS) + "\n")


@app.get("/latest/meta-data/iam/security-credentials/")
def list_roles() -> Response:
    """Devuelve el nombre del rol IAM simulado."""
    return _plain(ROLE_NAME + "\n")


@app.get("/latest/meta-data/iam/security-credentials/<role>")
def role_credentials(role: str):
    """Credenciales ficticias del rol solicitado."""
    if role != ROLE_NAME:
        return _plain("Role not found\n"), 404
    return jsonify(_fake_credentials())


@app.get("/latest/meta-data/<path:key>")
def meta_value(key: str):
    """Devuelve el valor ficticio de una clave concreta."""
    value = META_VALUES.get(key)
    if value is None:
        return _plain("Not found\n"), 404
    return _plain(value + "\n")


@app.get("/healthz")
def healthz() -> Response:
    """Endpoint de salud para comprobaciones del orquestador."""
    return _plain("ok\n")


if __name__ == "__main__":
    # Escucha en todas las interfaces para ser alcanzable desde la red interna Docker.
    app.run(host="0.0.0.0", port=PORT, debug=False)
