#  Sistema de Threat Intelligence para la evaluación de Indicadores de Compromiso (IoCs)


##  Descripción del proyecto

Este proyecto implementa un sistema de Threat Intelligence que recopila, normaliza, puntúa y visualiza indicadores de compromiso (IoCs) desde fuentes abiertas como OTX, URLhaus, ThreatFox y MalwareBazaar. Utiliza Elasticsearch para el almacenamiento, y un backend en Python que permite enriquecer los IoCs con geolocalización, metadatos contextuales y un sistema de scoring. La visualización se realiza mediante Kibana y dashboards web personalizados.

## Características principales

-  Recolección automática de IoCs desde múltiples fuentes públicas.
-  Enriquecimiento con metadatos: país, fechas, actores, TTPs, etc.
-  Sistema de scoring basado en antigüedad, procedencia y contexto.
-  Geolocalización de IPs con MaxMind GeoLite2.
-  Visualización interactiva con dashboard web.
-  Control de duplicados y recuento de avistamientos (`seen_count`).

## Estructura del proyecto

.
├── app.py # Backend Flask para recolección y API
├── dashboard.html # Dashboard principal de IoCs
├── charts.html # Dashboard con gráficos y filtros
├── templates/ # Plantillas HTML
├── static/ # Archivos JS, CSS, íconos, etc.
├── GeoLite2-Country.mmdb # Base de datos de geolocalización IP
├── requirements.txt # Dependencias Python del proyecto
└── README.md # Este archivo


## Instalación y ejecución

1. Clonar el repositorio:
```bash
git clone https://github.com/razzzer23/TFG_IOCS
Instalar dependencias:

pip install -r requirements.txt
Ejecutar la aplicación:

python app.py
Abrir la interfaz web:
http://localhost:5000

## Funcionalidades clave
Ruta /refresh: descarga los últimos IoCs desde todas las fuentes configuradas.

Guardado automático en Elasticsearch con control de duplicados.

Dashboards interactivos con filtros por tipo, país, score y etiquetas.

Gráficos de distribución por tipo, score medio y tags más comunes.

## Fuentes de datos utilizadas
AlienVault OTX

MalwareBazaar

ThreatFox

URLhaus

GeoLite2 by MaxMind

## Tecnologías empleadas
Python (Flask)

Elasticsearch

Kibana

Logstash (opcional)

HTML, CSS, JavaScript (Chart.js / D3.js)

## Ejemplo de IoC enriquecido
{
  "uuid": "f3c93e1a-...-...",
  "type": "sha256",
  "indicator": "5d41402abc4b2a76b9719d911017c592",
  "source": "OTX",
  "description": "Hash relacionado con RedLine Stealer",
  "pulse_name": "RedLine Stealer",
  "country": "RU",
  "tags": ["malware", "stealer"],
  "related_actors": ["APT28"],
  "ttp": ["T1059", "T1566"],
  "first_seen": "2025-06-30",
  "last_seen": "2025-07-01",
  "threat_score": 76,
  "seen_count": 3
}
## Créditos
Desarrollado por Victor Martin Miguel como parte del Trabajo de Fin de Grado en Universidad de Valladolid
