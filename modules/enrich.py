import requests

def enrich_event(misp, event_id, config):
    event = misp.get_event(event_id)
    if 'Event' not in event:
        print(f"[!] Event ID {event_id} not found or inaccessible.")
        return

    for attr in event['Event']['Attribute']:
        if attr['type'] in ['ip-src', 'ip-dst']:
            ip = attr['value']
            tags = []

            # AbuseIPDB enrichment
            if config.get('abuseipdb_key'):
                try:
                    response = requests.get(
                        'https://api.abuseipdb.com/api/v2/check',
                        headers={
                            'Key': config['abuseipdb_key'],
                            'Accept': 'application/json'
                        },
                        params={'ipAddress': ip, 'maxAgeInDays': 90},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json().get('data', {})
                        score = data.get('abuseConfidenceScore', 0)
                        tags.append(f"abuseipdb:score={score}")
                except Exception as e:
                    print(f"[!] AbuseIPDB error: {e}")

            # VirusTotal enrichment
            if config.get('virustotal_key'):
                try:
                    response = requests.get(
                        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={'x-apikey': config['virustotal_key']},
                        timeout=10
                    )
                    if response.status_code == 200:
                        data = response.json()
                        malicious = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                        tags.append(f"virustotal:malicious={malicious}")
                except Exception as e:
                    print(f"[!] VirusTotal error: {e}")

            # Apply all tags to the attribute
            for tag in tags:
                try:
                    misp.tag(attr['uuid'], tag)
                    print(f" [+] Tag added to {ip}: {tag}")
                except Exception as e:
                    print(f" [!] Failed to tag {ip} with {tag}: {e}")
