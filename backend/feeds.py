import requests
from datetime import datetime

def fetch_urlhaus_iocs():
    print("Descargando IoCs de URLhaus...")
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    iocs = []
    try:
        resp = requests.get(url)
        if resp.status_code != 200:
            print(f"Error URLhaus, status code: {resp.status_code}")
            return []
        lines = resp.text.splitlines()
        for line in lines:
            if not line.startswith("#"):
                parts = line.split(",")
                if len(parts) >= 3:
                    indicator = parts[2]
                    iocs.append({
                        "id": indicator,
                        "indicator": indicator,
                        "type": "url",
                        "created": None,
                        "modified": None,
                        "pulse_name": "URLhaus",
                        "adversary": None,
                        "tags": ["urlhaus", "malware"],
                        "country": None,
                        "description": "Malicious URL from URLhaus",
                        "source": "URLhaus",
                        "date": None
                    })
        print(f"IoCs URLhaus descargados: {len(iocs)}")
        return iocs
    except Exception as e:
        print(f"Error URLhaus: {e}")
        return []

def fetch_threatfox_iocs():
    print("Descargando IoCs de ThreatFox...")
    api_url = "https://threatfox.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 7}
    iocs = []

    try:
        resp = requests.post(api_url, json=payload)
        data = resp.json()
        if data.get("query_status") != "ok":
            print("Error ThreatFox: respuesta inválida")
            return []

        for item in data.get("data", []):
            indicator = item.get("ioc")
            iocs.append({
                "id": indicator,
                "indicator": indicator,
                "type": item.get("ioc_type", "unknown"),
                "created": item.get("date_added"),
                "modified": item.get("date_modified"),
                "pulse_name": "ThreatFox",
                "adversary": None,
                "tags": item.get("tags", []),
                "country": item.get("malware_alias", ""),
                "description": item.get("threat_type") or "ThreatFox IOC",
                "source": "ThreatFox",
                "date": item.get("date_added")
            })
        print(f"IoCs ThreatFox descargados: {len(iocs)}")
        return iocs
    except Exception as e:
        print(f"Error ThreatFox: {e}")
        return []

def fetch_malwarebazaar_iocs():
    print("Descargando IoCs de MalwareBazaar...")
    url = "https://bazaar.abuse.ch/export/csv/recent/"
    iocs = []
    try:
        resp = requests.get(url)
        if resp.status_code != 200:
            print(f"Error MalwareBazaar, status code: {resp.status_code}")
            return []
        lines = resp.text.splitlines()
        for line in lines:
            if not line.startswith("#"):
                parts = line.split(",")
                if len(parts) > 1:
                    sha256 = parts[1]
                    iocs.append({
                        "id": sha256,
                        "indicator": sha256,
                        "type": "filehash-sha256",
                        "created": None,
                        "modified": None,
                        "pulse_name": "MalwareBazaar",
                        "adversary": None,
                        "tags": ["malwarebazaar"],
                        "country": None,
                        "description": "Malware sample from MalwareBazaar",
                        "source": "MalwareBazaar",
                        "date": None
                    })
        print(f"IoCs MalwareBazaar descargados: {len(iocs)}")
        return iocs
    except Exception as e:
        print(f"Error MalwareBazaar: {e}")
        return []
