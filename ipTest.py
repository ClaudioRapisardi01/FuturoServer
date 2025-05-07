import requests

API_KEY = "LA_TUA_API_KEY"
URL = "https://api.abuseipdb.com/api/v2/blacklist"

params = {
    'confidenceMinimum': '90',  # Solo IP molto sospetti
    'limit': '10000'            # Massimo IP da richiedere
}

headers = {
    'Accept': 'application/json',
    'Key': '04c97c8a06500573e20b12cccb874807465ee286a37068bba9afa1d2e8c9a6d0a0d6a24a952041e7'
}

response = requests.get(URL, headers=headers, params=params)

if response.status_code == 200:
    data = response.json()
    ip_list = [record['ipAddress'] for record in data['data']]
    print(f"Totale IP trovati: {len(ip_list)}")
    print(ip_list)
else:
    print(f"Errore: {response.status_code} - {response.text}")
