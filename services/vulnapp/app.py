import logging
import sys
from datetime import datetime

import requests
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# Configuración de logging a stdout con timestamp, método, URL y resultado.
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("vulnapp")

# Timeout por defecto para las peticiones salientes del endpoint vulnerable.
REQUEST_TIMEOUT = 3


INDEX_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>SSRFNest - VulnApp</title>
</head>
<body>
  <h1>SSRFNest - Aplicación vulnerable</h1>
  <p>Esta aplicación forma parte de un laboratorio educativo de Red/Blue Team.
     Contiene un endpoint deliberadamente vulnerable a Server-Side Request Forgery (SSRF).</p>

  <h2>Endpoints disponibles</h2>
  <ul>
    <li><code>GET /</code> — esta página.</li>
    <li><code>GET /fetch?url=&lt;URL&gt;</code> — recupera el contenido de una URL remota (SSRF).</li>
    <li><code>GET /fetch_advanced?url=&lt;URL&gt;&amp;method=GET|POST</code> — variante que permite elegir el método HTTP.</li>
    <li><code>GET /health</code> — comprobación de salud del servicio.</li>
  </ul>

  <h2>Aviso</h2>
  <p>No expongas este servicio en redes no controladas. Su propósito es exclusivamente formativo.</p>
</body>
</html>
"""


@app.route("/", methods=["GET"])
def index() -> Response:
    """Página de bienvenida con descripción del laboratorio y endpoints."""
    logger.info("GET / - sirviendo página de bienvenida")
    return Response(INDEX_HTML, mimetype="text/html; charset=utf-8")


@app.route("/health", methods=["GET"])
def health() -> Response:
    """Endpoint de salud simple."""
    logger.info("GET /health - estado ok")
    return jsonify({"status": "ok"})


@app.route("/fetch", methods=["GET"])
def fetch() -> Response:
    """
    Endpoint SSRF principal.

    Toma el parámetro `url` sin ningún tipo de validación (ni whitelist ni blacklist)
    y realiza una petición HTTP GET con `requests`. Devuelve el cuerpo de la respuesta
    como texto plano. Este comportamiento es intencionadamente inseguro y forma parte
    del laboratorio.
    """
    target_url = request.args.get("url", "")
    if not target_url:
        logger.warning("GET /fetch - petición sin parámetro url")
        return Response("Falta el parámetro 'url'\n", status=400, mimetype="text/plain; charset=utf-8")

    logger.info("GET /fetch - url=%s", target_url)

    try:
        response = requests.get(target_url, timeout=REQUEST_TIMEOUT)
        logger.info(
            "GET /fetch - url=%s status=%s bytes=%d",
            target_url,
            response.status_code,
            len(response.content),
        )
        return Response(
            response.text,
            status=200,
            mimetype="text/plain; charset=utf-8",
        )
    except requests.RequestException as exc:
        logger.error("GET /fetch - url=%s error=%s", target_url, exc)
        return Response(
            f"Error al recuperar la URL: {exc}\n",
            status=500,
            mimetype="text/plain; charset=utf-8",
        )


@app.route("/fetch_advanced", methods=["GET"])
def fetch_advanced() -> Response:
    """
    Variante SSRF que permite seleccionar el método HTTP (GET o POST).

    Igual que /fetch, no aplica ninguna validación sobre la URL destino. El parámetro
    `method` se usa tal cual para decidir el verbo HTTP de la petición saliente.
    """
    target_url = request.args.get("url", "")
    method = request.args.get("method", "GET").upper()

    if not target_url:
        logger.warning("GET /fetch_advanced - petición sin parámetro url")
        return Response("Falta el parámetro 'url'\n", status=400, mimetype="text/plain; charset=utf-8")

    if method not in ("GET", "POST"):
        logger.warning("GET /fetch_advanced - método no soportado: %s", method)
        return Response("Método no soportado (usa GET o POST)\n", status=400, mimetype="text/plain; charset=utf-8")

    logger.info("GET /fetch_advanced - url=%s method=%s", target_url, method)

    try:
        if method == "POST":
            response = requests.post(target_url, timeout=REQUEST_TIMEOUT)
        else:
            response = requests.get(target_url, timeout=REQUEST_TIMEOUT)

        logger.info(
            "GET /fetch_advanced - url=%s method=%s status=%s bytes=%d",
            target_url,
            method,
            response.status_code,
            len(response.content),
        )
        return Response(
            response.text,
            status=200,
            mimetype="text/plain; charset=utf-8",
        )
    except requests.RequestException as exc:
        logger.error(
            "GET /fetch_advanced - url=%s method=%s error=%s",
            target_url,
            method,
            exc,
        )
        return Response(
            f"Error al recuperar la URL: {exc}\n",
            status=500,
            mimetype="text/plain; charset=utf-8",
        )


@app.errorhandler(404)
def not_found(_error) -> Response:
    """Manejador 404 con logging para dejar traza en el laboratorio."""
    logger.info("404 - path=%s", request.path)
    return Response("Recurso no encontrado\n", status=404, mimetype="text/plain; charset=utf-8")


if __name__ == "__main__":
    # Se ejecuta en modo desarrollo dentro del contenedor. No usar en producción.
    logger.info("Arrancando VulnApp en 0.0.0.0:5000 a las %s", datetime.utcnow().isoformat())
    app.run(host="0.0.0.0", port=5000, debug=False)
