#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ssrf_detector.py — Detector y correlador de alertas SSRF para SSRFNest.

Autor: Javier Garrido Ortiz

Este script es el punto de entrada del proyecto desde la perspectiva Blue Team.
Lee el fichero eve.json generado por Suricata, filtra las alertas relacionadas
con SSRF, las enriquece, calcula un resumen y genera un informe JSON, además de
imprimir una tabla en terminal usando rich.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


# Mapeo de severidad numérica de Suricata a etiqueta legible.
SEVERITY_MAP: dict[int, str] = {
    1: "CRITICAL",
    2: "HIGH",
    3: "MEDIUM",
    4: "LOW",
}

# Orden de severidad para comparaciones (mayor número = más grave).
SEVERITY_ORDER: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# Colores rich para cada nivel de severidad.
SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "bold dark_orange",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}

console = Console()


def load_events(path: str) -> list[dict[str, Any]]:
    """
    Lee un fichero eve.json en formato NDJSON (una línea = un JSON).

    Args:
        path: Ruta al fichero eve.json.

    Returns:
        Lista de diccionarios, uno por cada línea válida.

    Raises:
        FileNotFoundError: Si el fichero no existe.
        ValueError: Si una línea no es JSON válido (se avisa y se omite).
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"No se encontró el fichero de eventos: {path}")

    events: list[dict[str, Any]] = []
    with file_path.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                console.print(
                    f"[yellow]Aviso:[/yellow] línea {lineno} no es JSON válido: {exc}"
                )
    return events


def filter_ssrf_alerts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Filtra los eventos que sean alertas de Suricata y cuya firma mencione SSRF.

    Args:
        events: Lista de eventos crudos procedentes de eve.json.

    Returns:
        Lista de eventos que cumplen los criterios de alerta SSRF.
    """
    filtered: list[dict[str, Any]] = []
    for ev in events:
        if ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert", {})
        signature = str(alert.get("signature", ""))
        if "SSRF" in signature.upper():
            filtered.append(ev)
    return filtered


def _map_severity(value: Any) -> str:
    """Traduce el campo numérico de severidad de Suricata a etiqueta legible."""
    try:
        return SEVERITY_MAP.get(int(value), "UNKNOWN")
    except (TypeError, ValueError):
        return "UNKNOWN"


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Extrae los campos relevantes de un evento de alerta Suricata.

    Args:
        alert: Evento crudo de Suricata.

    Returns:
        Diccionario con timestamp, signature, src_ip, src_port, dest_ip,
        dest_port, severity y, si existe, http_url.
    """
    alert_block = alert.get("alert", {}) or {}
    enriched: dict[str, Any] = {
        "timestamp": alert.get("timestamp"),
        "signature": alert_block.get("signature"),
        "signature_id": alert_block.get("signature_id"),
        "category": alert_block.get("category"),
        "src_ip": alert.get("src_ip"),
        "src_port": alert.get("src_port"),
        "dest_ip": alert.get("dest_ip"),
        "dest_port": alert.get("dest_port"),
        "proto": alert.get("proto"),
        "severity": _map_severity(alert_block.get("severity")),
    }

    http_block = alert.get("http") or {}
    if http_block:
        enriched["http_url"] = http_block.get("url")
        enriched["http_hostname"] = http_block.get("hostname")
        enriched["http_method"] = http_block.get("http_method")

    return enriched


def compute_summary(enriched: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Calcula métricas agregadas sobre las alertas enriquecidas.

    Args:
        enriched: Lista de alertas ya enriquecidas.

    Returns:
        Diccionario con total de alertas, hosts atacantes únicos, destinos
        únicos y severidad global máxima.
    """
    total = len(enriched)
    src_hosts = {a.get("src_ip") for a in enriched if a.get("src_ip")}
    dest_hosts = {a.get("dest_ip") for a in enriched if a.get("dest_ip")}

    max_sev = "NONE"
    max_val = 0
    for a in enriched:
        sev = a.get("severity", "UNKNOWN")
        val = SEVERITY_ORDER.get(sev, 0)
        if val > max_val:
            max_val = val
            max_sev = sev

    return {
        "total_alerts": total,
        "unique_source_hosts": len(src_hosts),
        "unique_destination_hosts": len(dest_hosts),
        "source_hosts": sorted(src_hosts),
        "destination_hosts": sorted(dest_hosts),
        "max_severity": max_sev,
    }


def generate_report(
    alerts: list[dict[str, Any]],
    summary: dict[str, Any],
    output_path: str,
    total_events_processed: int = 0,
) -> None:
    """
    Escribe el informe JSON estructurado en disco.

    Args:
        alerts: Alertas SSRF enriquecidas.
        summary: Resumen calculado.
        output_path: Ruta del fichero JSON de salida.
        total_events_processed: Número total de eventos leídos del eve.json.
    """
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_events_processed": total_events_processed,
        "ssrf_alerts": alerts,
        "summary": summary,
    }

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)


def print_rich_output(
    alerts: list[dict[str, Any]], summary: dict[str, Any]
) -> None:
    """
    Imprime en terminal una tabla con las alertas y un panel con el resumen.

    Args:
        alerts: Alertas SSRF enriquecidas.
        summary: Resumen agregado.
    """
    if not alerts:
        console.print(
            Panel(
                Text("No se han detectado alertas SSRF en el fichero analizado.",
                     style="yellow"),
                title="SSRFNest Detector",
                border_style="yellow",
            )
        )
        return

    table = Table(title="Alertas SSRF detectadas", show_lines=False)
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Severidad", no_wrap=True)
    table.add_column("Origen", no_wrap=True)
    table.add_column("Destino", no_wrap=True)
    table.add_column("Firma", overflow="fold")
    table.add_column("URL", overflow="fold")

    for a in alerts:
        sev = a.get("severity", "UNKNOWN")
        color = SEVERITY_COLORS.get(sev, "white")
        src = f"{a.get('src_ip', '-')}:{a.get('src_port', '-')}"
        dst = f"{a.get('dest_ip', '-')}:{a.get('dest_port', '-')}"
        table.add_row(
            str(a.get("timestamp", "-")),
            Text(sev, style=color),
            src,
            dst,
            str(a.get("signature", "-")),
            str(a.get("http_url", "-")),
        )

    console.print(table)

    max_sev = summary.get("max_severity", "NONE")
    sev_color = SEVERITY_COLORS.get(max_sev, "white")
    summary_text = Text()
    summary_text.append("Total de alertas SSRF: ", style="bold")
    summary_text.append(f"{summary.get('total_alerts', 0)}\n")
    summary_text.append("Hosts atacantes únicos: ", style="bold")
    summary_text.append(f"{summary.get('unique_source_hosts', 0)}\n")
    summary_text.append("Destinos únicos: ", style="bold")
    summary_text.append(f"{summary.get('unique_destination_hosts', 0)}\n")
    summary_text.append("Severidad máxima: ", style="bold")
    summary_text.append(max_sev, style=sev_color)

    console.print(
        Panel(summary_text, title="Resumen", border_style="blue")
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Configura y parsea los argumentos de línea de comandos."""
    parser = argparse.ArgumentParser(
        prog="ssrf_detector",
        description=(
            "Detector de alertas SSRF sobre el fichero eve.json de Suricata "
            "generado en el laboratorio SSRFNest."
        ),
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Ruta al fichero eve.json de Suricata (obligatorio).",
    )
    parser.add_argument(
        "--report",
        default="ssrf_report.json",
        help="Ruta del informe JSON de salida (por defecto: ssrf_report.json).",
    )
    parser.add_argument(
        "--severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Filtra las alertas por severidad mínima.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Muestra información adicional durante el procesamiento.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada principal del detector SSRF."""
    args = parse_args(argv)

    console.print(
        Panel(
            Text("SSRFNest — Detector de alertas SSRF", style="bold white"),
            border_style="green",
        )
    )

    try:
        events = load_events(args.log)
    except FileNotFoundError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    if args.verbose:
        console.print(f"[dim]Eventos leídos: {len(events)}[/dim]")

    ssrf_events = filter_ssrf_alerts(events)
    if args.verbose:
        console.print(f"[dim]Alertas SSRF tras filtrado: {len(ssrf_events)}[/dim]")

    enriched = [enrich_alert(ev) for ev in ssrf_events]

    # Aplicar filtro de severidad si se ha especificado.
    if args.severity:
        min_val = SEVERITY_ORDER[args.severity]
        enriched = [
            a for a in enriched
            if SEVERITY_ORDER.get(a.get("severity", "UNKNOWN"), 0) >= min_val
        ]
        if args.verbose:
            console.print(
                f"[dim]Alertas tras filtrar por severidad "
                f">= {args.severity}: {len(enriched)}[/dim]"
            )

    summary = compute_summary(enriched)

    try:
        generate_report(
            alerts=enriched,
            summary=summary,
            output_path=args.report,
            total_events_processed=len(events),
        )
    except OSError as exc:
        console.print(f"[bold red]Error escribiendo informe:[/bold red] {exc}")
        return 3

    print_rich_output(enriched, summary)
    console.print(f"[green]Informe guardado en:[/green] {args.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
