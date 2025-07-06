from flask import Flask, jsonify, render_template
from elasticsearch import Elasticsearch
import requests
from datetime import datetime, timedelta, timezone
from iso3166 import countries_by_name  
from feeds import (
    fetch_urlhaus_iocs,
    fetch_threatfox_iocs,
    fetch_malwarebazaar_iocs
)
from collections import Counter
from math import ceil
from iso3166 import countries
from flask import send_file
from wordcloud import WordCloud
import matplotlib.pyplot as plt
from io import BytesIO
import matplotlib
matplotlib.use('Agg')  
import matplotlib.pyplot as plt

import re

EXCLUDED_COUNTRIES = {"MLI", "NER", "BFA"}  # Mali, Níger, Burkina Faso, etc.

def detect_country_from_text(text):
    text = text.lower()
    for name, country_obj in countries_by_name.items():
        if country_obj.alpha3 in EXCLUDED_COUNTRIES:
            continue
        pattern = r'\b' + re.escape(name.lower()) + r'\b'
        if re.search(pattern, text):
            return country_obj.alpha3
    return None



import geoip2.database

try:
    geoip_reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
except FileNotFoundError:
    geoip_reader = None
    print("[WARN] GeoLite2 database not found. Geolocalización deshabilitada.")


app = Flask(__name__, template_folder='templates')

es = Elasticsearch("http://localhost:9200")
INDEX_NAME = "iocs"
#geoip_reader = geoip2.database.Reader("geoip/GeoLite2-Country.mmdb")




if not es.indices.exists(index=INDEX_NAME):
    es.indices.create(index=INDEX_NAME)

OTX_API_KEY = "6270e193430857e9ec5a2ed667b26d872618588a190178b155081e2527c0a67b"

# =========================
# NUEVO: Scoring contextual tipo YARA
# =========================
YARA_SIMULATED_RULES = {
    "ransomware": 30,
    "lockbit": 30,
    "infostealer": 20,
    "stealer": 20,
    "redline": 20,
    "phishing": 25,
    "cobaltstrike": 30,
    "dark web": 15,
    "apt": 25
}
RISK_COUNTRIES = {"RU", "CN", "IR", "KP"}



NORMALIZED_TYPES = {
    "url": "url",
    "URL": "url",
    "domain": "domain",
    "hostname": "domain",
    "ip": "ip",
    "ipv4": "ip",
    "IPv4": "ip",
    "IPV4": "ip",
    "ipv6": "ip",
    "IPV6": "ip",
    "filehash-sha256": "filehash-sha256",
    "FileHash-SHA256": "filehash-sha256",
    "FileHash-SHA1": "filehash-sha1",
    "filehash-sha1": "filehash-sha1",
    "FileHash-MD5": "filehash-md5",
    "filehash-md5": "filehash-md5",
    "cve": "cve",
    "CVE": "cve",
    "cidr": "cidr",
    "yara": "yara"
}


from datetime import datetime, timezone

def calculate_threat_score(ioc):
    score = 0
    combined_text = (
        (ioc.get("pulse_name") or "").lower() + " " +
        (ioc.get("description") or "").lower() + " " +
        " ".join([str(tag).lower() for tag in ioc.get("tags", [])])
    )

    yara_keywords = {
        "ransomware": 40,
        "lockbit": 40,
        "infostealer": 35,
        "stealer": 35,
        "info stealer": 35,
        "credential theft": 30,
        "remote access": 25,
        "rat": 30,
        "kimsuky": 25,
        "apt": 30,
        "worm": 15,
        "xworm": 15,
        "dark web": 20,
        "phishing": 25,
        "backdoor": 25,
        "cobaltstrike": 35,
        "powershell": 10,
        "redline": 30,
        "badbox": 25,
        "fraud": 15,
        "cve-2024": 20,
        "golang": 10,
        "loader": 15,
        "botnet": 25,
        "docker": 20,
        "cryptojacking": 20,
        "mining": 15,
        "dero": 10,
        "cloud": 10,
        "environments": 10,
        "linux": 10,
        "russia": 10,
        "rusia": 10,
        "russian": 10,
        "china": 10,
        "chinese": 10,
        "iran": 10,
        "iranian": 10,
        "north korea": 10,
        "nk": 10,
        "dprk": 10
    }

    for keyword, value in yara_keywords.items():
        if keyword in combined_text:
            score += value

    # Penalización por antigüedad 
    try:
        if ioc.get("date"):
            dt = datetime.fromisoformat(ioc["date"].rstrip("Z")).replace(tzinfo=timezone.utc)
            days_old = (datetime.now(timezone.utc) - dt).days
            penalty = min(days_old // 5, 10)  # Penaliza menos que antes
            score -= penalty
    except:
        pass

    # Penalización por inactividad prolongada 
    try:
        last_seen = ioc.get("modified") or ioc.get("date")
        if last_seen:
            dt = datetime.fromisoformat(last_seen.rstrip("Z")).replace(tzinfo=timezone.utc)
            days_inactive = (datetime.now(timezone.utc) - dt).days
            if days_inactive > 15:
                decay = min((days_inactive - 15) // 3, 10)
                score -= decay
    except:
        pass

    # Bonus por tipo SHA256
    if (ioc.get("type") or "").lower() == "filehash-sha256":
        score += 5

    # Bonus por país sospechoso
    if (ioc.get("country") or "").upper() in {"RU", "CN", "IR", "KP"}:
        score += 10

    # Repeticiones → +10 por cada vez visto (máx 100)
    seen_count = ioc.get("seen_count", 1)
    if seen_count > 1:
        score += min(seen_count * 10, 100)

    # Normalizar entre 0.1 y 10.0
    final_score = max(0.1, min(score / 10, 10))
    return round(final_score, 1)




# =========================

def fetch_otx_iocs(days_back=1):
    print("Descargando IoCs OTX recientes...")
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    date_limit = datetime.now(timezone.utc) - timedelta(days=days_back)
    iocs = []
    page = 1

    while True:
        try:
            url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?page={page}"
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                print(f"Error OTX, status code: {response.status_code}")
                break
            data = response.json()
            results = data.get("results", [])
            if not results:
                break

            for pulse in results:
                pulse_date_str = pulse.get("modified") or pulse.get("created")
                if not pulse_date_str:
                    continue
                pulse_date = datetime.fromisoformat(pulse_date_str.rstrip('Z')).replace(tzinfo=timezone.utc)
                if pulse_date < date_limit:
                    continue

                pulse_name = pulse.get("name", "")
                created = pulse.get("created", "")
                modified = pulse.get("modified", "")
                adversary = ""
                if "adversary" in pulse and isinstance(pulse["adversary"], dict):
                    adversary = pulse["adversary"].get("name", "")
                tags = pulse.get("tags", [])
                country = ""
                author = pulse.get("author", {})
                if isinstance(author, dict):
                    country = author.get("country", "")

                for indicator in pulse.get("indicators", []):
                    iocs.append({
                        "id": indicator.get("id") or indicator.get("indicator"),
                        "indicator": indicator.get("indicator"),
                        "type": indicator.get("type"),
                        "created": created,
                        "modified": modified,
                        "pulse_name": pulse_name,
                        "adversary": adversary,
                        "tags": tags,
                        "country": country,
                        "description": indicator.get("description", pulse_name),
                        "source": "OTX",
                        "date": indicator.get("created") or modified or created
                    })

            if not data.get("next"):
                break
            page += 1
        except Exception as e:
            print(f"Error OTX: {e}")
            break

    print(f"IoCs OTX descargados (últimos {days_back} días): {len(iocs)}")
    return iocs

def fetch_threatview_iocs():
    print("Descargando IoCs ThreatView...")
    try:
        response = requests.get("https://threatview.io/api/v1/indicator/ip")
        if response.status_code == 200:
            data = response.text.splitlines()
            iocs = []
            for line in data:
                if line.strip() and not line.startswith("#"):
                    iocs.append({
                        "id": line.strip(),
                        "indicator": line.strip(),
                        "type": "ip",
                        "created": None,
                        "modified": None,
                        "pulse_name": None,
                        "adversary": None,
                        "tags": [],
                        "country": None,
                        "description": "ThreatView feed",
                        "source": "ThreatView",
                        "date": None
                    })
            print(f"IoCs ThreatView descargados: {len(iocs)}")
            return iocs
        else:
            print(f"Error ThreatView, status code: {response.status_code}")
    except Exception as e:
        print(f"Error ThreatView: {e}")
    return []

def save_iocs_to_es(iocs):
    import geoip2.database
    geoip_reader = geoip2.database.Reader("GeoLite2-Country.mmdb")

    keyword_to_iso3 = {
        "russia": "RUS",
        "rusia": "RUS",
        "russian": "RUS",
        "china": "CHN",
        "chinese": "CHN",
        "iran": "IRN",
        "iranian": "IRN",
        "north korea": "PRK",
        "nk": "PRK",
        "dprk": "PRK"
    }

    count = 0
    for ioc in iocs:
        doc_id = ioc.get("id") or ioc.get("indicator")

        # === Enriquecer campo 'country' ===
        country = (ioc.get("country") or "").strip().upper()

        if not country:
            if (ioc.get("type") == "ip") and ioc.get("indicator"):
                try:
                    response = geoip_reader.country(ioc["indicator"])
                    country = response.country.iso_code
                except:
                    country = None

            if not country:
                combined_text = (
                    (ioc.get("pulse_name") or "") + " " +
                    (ioc.get("description") or "") + " " +
                    " ".join([str(tag) for tag in ioc.get("tags", [])])
                ).lower()
                country = detect_country_from_text(combined_text)
                if not country:
                    for keyword, iso3 in keyword_to_iso3.items():
                        if keyword in combined_text:
                            country = iso3
                            break

        # === Calcular threat_score ===
        threat_score = calculate_threat_score(ioc)

        # === Preparar nuevo documento ===
        doc = {
            "indicator": ioc.get("indicator"),
            "type": (ioc.get("type") or "unknown").lower(),
            "date": ioc.get("date"),
            "pulse_name": ioc.get("pulse_name") or ioc.get("related_campaigns"),
            "adversary": ioc.get("adversary"),
            "tags": ioc.get("tags"),
            "country": country if country else None,
            "description": ioc.get("description", ""),
            "threat_score": threat_score
        }

        # === Control de duplicados con seen_count ===
        existing = es.get(index=INDEX_NAME, id=doc_id, ignore=[404])
        if existing.get("found"):
            old_doc = existing["_source"]
            doc["seen_count"] = old_doc.get("seen_count", 1) + 1
        else:
            doc["seen_count"] = 1

        # === Guardar o actualizar ===
        es.index(index=INDEX_NAME, id=doc_id, document=doc)
        count += 1

    print(f"Guardados {count} IoCs (nuevos o actualizados) desde {ioc.get('source') if iocs else 'desconocido'}")




@app.route('/refresh')
def refresh_iocs():
    print("Iniciando actualización completa de IoCs...")

    otx_iocs = fetch_otx_iocs(days_back=3)
    #tv_iocs = fetch_threatview_iocs()
    #uh_iocs = fetch_urlhaus_iocs()
    tf_iocs = fetch_threatfox_iocs()
    #mb_iocs = fetch_malwarebazaar_iocs()

    save_iocs_to_es(otx_iocs)
    #save_iocs_to_es(tv_iocs)
    #save_iocs_to_es(uh_iocs)
    save_iocs_to_es(tf_iocs)
    #save_iocs_to_es(mb_iocs)

    print("Actualización completa.")
    return "Todos los IoCs fueron descargados e indexados en Elasticsearch."


@app.route('/iocs')
def get_iocs():
    resp = es.search(index=INDEX_NAME, size=2000)
    hits = resp["hits"]["hits"]
    results = [hit["_source"] for hit in hits]
    return jsonify(results)

@app.route('/')
def index():
    return render_template("dashboard.html")
    
@app.route("/charts")
def charts():
    return render_template("charts.html")    
     
    
@app.route("/chartdata")
def chart_data():
    query = {
        "size": 0,  # no queremos documentos, solo agregaciones
        "aggs": {
            "ioc_types": {
                "terms": {
                    "field": "type.keyword",
                    "size": 50  # suficiente para incluir todos los tipos
                }
            }
        }
    }
    res = es.search(index=INDEX_NAME, body=query)
    counts = {bucket['key']: bucket['doc_count'] for bucket in res['aggregations']['ioc_types']['buckets']}
    return jsonify(counts)




@app.route("/recalculate")
def recalculate_threat_scores():
    print("Recalculando threat_score para todos los IoCs existentes...")

    batch_size = 1000
    updated = 0

    # Iniciar scroll
    response = es.search(
        index=INDEX_NAME,
        scroll="2m",
        size=batch_size,
        body={"query": {"match_all": {}}}
    )

    scroll_id = response["_scroll_id"]
    hits = response["hits"]["hits"]

    while hits:
        for hit in hits:
            ioc = hit["_source"]
            doc_id = hit["_id"]

            ioc["threat_score"] = calculate_threat_score(ioc)
            es.index(index=INDEX_NAME, id=doc_id, document=ioc)
            updated += 1

        print(f"[INFO] Procesados {updated} IoCs...")

        # Obtener siguiente lote
        response = es.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = response["_scroll_id"]
        hits = response["hits"]["hits"]

    print(f"[RESULTADO] Actualizados {updated} IoCs con threat_score nuevo.")
    return f"Actualizados {updated} IoCs con nuevo threat_score."




@app.route("/countrydata")
def country_data():
    query = {
        "size": 0,
        "aggs": {
            "countries": {
                "terms": {
                    "field": "country.keyword",
                    "size": 100
                }
            }
        }
    }
    res = es.search(index=INDEX_NAME, body=query)
    counts = {bucket["key"]: bucket["doc_count"] for bucket in res["aggregations"]["countries"]["buckets"]}
    return jsonify(counts)




@app.route("/filters")
def filters():
    return render_template("filters.html")

@app.route("/filtered_iocs")
def filtered_iocs():
    resp = es.search(index=INDEX_NAME, size=10000)
    data = [hit["_source"] for hit in resp["hits"]["hits"]]
    return jsonify(data)

@app.route('/ioc_types')
def get_ioc_types():
    resp = es.search(index=INDEX_NAME, size=0, aggs={
        "types": {"terms": {"field": "type.keyword", "size": 20}}
    })
    buckets = resp["aggregations"]["types"]["buckets"]
    return jsonify([b["key"] for b in buckets])

@app.route('/iocs/type/<ioc_type>')
def get_iocs_by_type(ioc_type):
    query = {
        "query": {
            "wildcard": {
                "type.keyword": {
                    "value": f"*{ioc_type}*",
                    "case_insensitive": True
                }
            }
        }
    }
    resp = es.search(index=INDEX_NAME, body=query, size=10000)
    hits = resp["hits"]["hits"]
    return jsonify([hit["_source"] for hit in hits])






@app.route("/normalize_types")
def normalize_ioc_types():
    print("Iniciando normalización completa de tipos con scroll...")

    # Diccionario de normalización
    mapping = {
        "url": "url",
        "URL": "url",
        "domain": "domain",
        "hostname": "domain",
        "ip": "ip",
        "ipv4": "ip",
        "IPv4": "ip",
        "filehash-md5": "filehash-md5",
        "FileHash-MD5": "filehash-md5",
        "filehash-sha1": "filehash-sha1",
        "FileHash-SHA1": "filehash-sha1",
        "filehash-sha256": "filehash-sha256",
        "FileHash-SHA256": "filehash-sha256",
        "cve": "cve",
        "CVE": "cve"
    }

    # Iniciar scroll
    page = es.search(
        index=INDEX_NAME,
        scroll='2m',
        size=1000,
        body={"query": {"match_all": {}}}
    )
    sid = page['_scroll_id']
    scroll_size = len(page['hits']['hits'])

    updated = 0

    while scroll_size > 0:
        for hit in page['hits']['hits']:
            doc_id = hit['_id']
            ioc = hit['_source']
            raw_type = ioc.get("type", "").strip()
            cleaned = mapping.get(raw_type, raw_type.lower())

            if raw_type != cleaned:
                ioc["type"] = cleaned
                es.index(index=INDEX_NAME, id=doc_id, document=ioc)
                updated += 1

        page = es.scroll(scroll_id=sid, scroll='2m')
        sid = page['_scroll_id']
        scroll_size = len(page['hits']['hits'])

    print(f"[RESULTADO] Tipos normalizados: {updated}")
    return f"Tipos normalizados: {updated}"



@app.route("/recalculate_country")
def recalculate_country_field():
    print("Recalculando campo 'country' en todos los IoCs...")
    keyword_to_iso3 = {
        "russia": "RUS",
        "rusia": "RUS",
        "russian": "RUS",
        "china": "CHN",
        "chinese": "CHN",
        "iran": "IRN",
        "iranian": "IRN",
        "north korea": "PRK",
        "nk": "PRK",
        "dprk": "PRK"
    }

    results = es.search(index=INDEX_NAME, body={"query": {"match_all": {}}}, size=10000)["hits"]["hits"]
    updated = 0

    for hit in results:
        doc_id = hit["_id"]
        ioc = hit["_source"]

        # Recalcular país
        combined_text = (
            (ioc.get("pulse_name") or "") + " " +
            (ioc.get("description") or "") + " " +
            " ".join([str(tag) for tag in ioc.get("tags", [])])
        ).lower()

        country = None
        for keyword, iso3 in keyword_to_iso3.items():
            if keyword in combined_text:
                country = iso3
                break

        if country:
            ioc["country"] = country
            es.index(index=INDEX_NAME, id=doc_id, document=ioc)
            updated += 1

    print(f"[RESULTADO] Países recalculados: {updated}")
    return f"Países recalculados: {updated}"

@app.route("/reanalyze_iocs")
def reanalyze_existing_iocs():
    print("Reanalizando todos los IoCs con scroll para threat_score y country...")

    keyword_to_iso3 = {
        "russia": "RUS",
        "rusia": "RUS",
        "russian": "RUS",
        "china": "CHN",
        "chinese": "CHN",
        "iran": "IRN",
        "iranian": "IRN",
        "north korea": "PRK",
        "nk": "PRK",
        "dprk": "PRK"
    }

    page = es.search(
        index=INDEX_NAME,
        scroll='2m',
        size=1000,
        body={"query": {"match_all": {}}}
    )
    sid = page['_scroll_id']
    scroll_size = len(page['hits']['hits'])
    updated = 0

    while scroll_size > 0:
        for hit in page['hits']['hits']:
            doc_id = hit['_id']
            ioc = hit['_source']

            combined_text = (
                (ioc.get("pulse_name") or "") + " " +
                (ioc.get("description") or "") + " " +
                " ".join([str(tag) for tag in ioc.get("tags", [])])
            ).lower()

            country = None

            # 1. GeoIP si es IP
            if geoip_reader and ioc.get("type") == "ip" and ioc.get("indicator"):
                try:
                    geo = geoip_reader.country(ioc["indicator"])
                    country = geo.country.iso_code
                except:
                    pass

            # 2. Detección por nombre de país (tags o texto)
            if not country:
                country = detect_country_from_text(combined_text)

            # 3. Fallback por keyword manual
            if not country:
                for keyword, iso3 in keyword_to_iso3.items():
                    if keyword in combined_text:
                        country = iso3
                        break

            ioc["country"] = country
            ioc["threat_score"] = calculate_threat_score(ioc)

            es.index(index=INDEX_NAME, id=doc_id, document=ioc)
            updated += 1

        page = es.scroll(scroll_id=sid, scroll='2m')
        sid = page['_scroll_id']
        scroll_size = len(page['hits']['hits'])

    print(f"[RESULTADO] IoCs reanalizados: {updated}")
    return f"IoCs reanalizados: {updated}"



@app.route("/geoip_all")
def apply_geoip_to_all():
    if not geoip_reader:
        return "GeoLite2 database no encontrada. No se puede aplicar geolocalización."

    print("Aplicando GeoIP a todos los IoCs con tipo 'ip'...")

    scroll = es.search(
        index=INDEX_NAME,
        scroll='2m',
        size=1000,
        body={
            "query": {
                "bool": {
                    "must": [
                        {"term": {"type.keyword": "ip"}}
                    ],
                    "must_not": [
                        {"exists": {"field": "country"}}
                    ]
                }
            }
        }
    )

    sid = scroll['_scroll_id']
    scroll_size = len(scroll['hits']['hits'])
    updated = 0

    while scroll_size > 0:
        for hit in scroll['hits']['hits']:
            doc_id = hit['_id']
            ioc = hit['_source']
            ip = ioc.get("indicator")

            try:
                response = geoip_reader.country(ip)
                country = response.country.iso_code
                if country:
                    ioc["country"] = country
                    es.index(index=INDEX_NAME, id=doc_id, document=ioc)
                    updated += 1
                    print(f"[OK] {ip} → {country}")
            except Exception as e:
                print(f"[SKIP] {ip} → {e}")

        scroll = es.scroll(scroll_id=sid, scroll='2m')
        sid = scroll['_scroll_id']
        scroll_size = len(scroll['hits']['hits'])

    return f"GeoIP aplicado a {updated} IoCs."


@app.route("/score_histogram")
def score_histogram():
    print("Calculando histograma de threat_score...")

    score_counts = Counter()

    # Scroll por todos los IoCs
    page = es.search(
        index=INDEX_NAME,
        scroll='2m',
        size=1000,
        body={"query": {"exists": {"field": "threat_score"}}}
    )

    sid = page['_scroll_id']
    scroll_size = len(page['hits']['hits'])

    while scroll_size > 0:
        for hit in page['hits']['hits']:
            score = hit['_source'].get("threat_score")
            if score:
                bucket = min(ceil(score), 10)  # Agrupa en máximo 10
                score_counts[bucket] += 1

        page = es.scroll(scroll_id=sid, scroll='2m')
        sid = page['_scroll_id']
        scroll_size = len(page['hits']['hits'])

    # Asegura todos los buckets del 1 al 10 aunque estén vacíos
    full_hist = {i: score_counts.get(i, 0) for i in range(1, 11)}

    print(f"[Histograma de threat_score]: {full_hist}")
    return jsonify(full_hist)
    
    
@app.route("/avg_score_by_type")
def avg_score_by_type():
    query = {
        "size": 0,
        "aggs": {
            "types": {
                "terms": {"field": "type.keyword", "size": 20},
                "aggs": {
                    "avg_score": {"avg": {"field": "threat_score"}}
                }
            }
        }
    }
    res = es.search(index=INDEX_NAME, body=query)
    data = {
        bucket["key"]: round(bucket["avg_score"]["value"], 2)
        for bucket in res["aggregations"]["types"]["buckets"]
    }
    return jsonify(data)



@app.route("/top_iocs")
def top_iocs():
    query = {
        "size": 0,
        "aggs": {
            "top_iocs": {
                "terms": {
                    "field": "indicator.keyword",
                    "size": 10,
                    "order": {"sum_seen_count": "desc"}
                },
                "aggs": {
                    "sum_seen_count": {
                        "sum": {"field": "seen_count"}
                    }
                }
            }
        }
    }

    res = es.search(index=INDEX_NAME, body=query)
    results = res["aggregations"]["top_iocs"]["buckets"]
    data = {bucket["key"]: int(bucket["sum_seen_count"]["value"]) for bucket in results}
    return jsonify(data)




@app.route("/tag_wordcloud")
def tag_wordcloud():
    from wordcloud import WordCloud
    from io import BytesIO
    from flask import send_file
    import matplotlib.pyplot as plt

    query = {
        "size": 10000,
        "_source": ["tags"]
    }
    res = es.search(index=INDEX_NAME, body=query)

    # Tags que queremos excluir de la nube de palabras
    undesired_tags = {"urlhaus", "malwarebazaar", "threatfox", "otx", "cve", "ioc", "indicator", "source"}

    tag_freq = {}
    for hit in res["hits"]["hits"]:
        tags = hit["_source"].get("tags", [])
        for tag in tags:
            tag = tag.lower()
            if tag not in undesired_tags:
                tag_freq[tag] = tag_freq.get(tag, 0) + 1

    if not tag_freq:
        tag_freq["no_tags"] = 1

    wc = WordCloud(width=800, height=400, background_color='white').generate_from_frequencies(tag_freq)

    img = BytesIO()
    plt.figure(figsize=(10, 5))
    plt.imshow(wc, interpolation="bilinear")
    plt.axis("off")
    plt.tight_layout(pad=0)
    plt.savefig(img, format='PNG')
    plt.close()

    img.seek(0)
    return send_file(img, mimetype='image/png')


if __name__ == "__main__":
    print("Iniciando servidor Flask... (con threat_score contextual)")
    app.run(debug=True, host="0.0.0.0", port=5000)
