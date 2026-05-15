import requests
from elasticsearch import Elasticsearch
import sys

print("="*60)
print("🚑 DIAGNÓSTICO DE CONECTIVIDAD NIDS")
print("="*60)

# Lista de direcciones a probar
test_urls = [
    {"name": "Elasticsearch (Local)", "url": "http://localhost:9200"},
    {"name": "Elasticsearch (Docker)", "url": "http://elasticsearch:9200"},
    {"name": "Elasticsearch (IP Típica)", "url": "http://127.0.0.1:9200"},
    {"name": "ML API (Local)", "url": "http://localhost:5000"},
    {"name": "ML API (Docker)", "url": "http://ml-api:5000"}
]

def check_url(target):
    print(f"\n🔍 Probando: {target['name']} -> {target['url']} ...")
    try:
        # Timeout corto para no esperar eternamente
        response = requests.get(target['url'], timeout=3)
        if response.status_code == 200:
            print(f"   ✅ ¡ÉXITO! Servicio respondio: {response.status_code}")
            return target['url']
        else:
            print(f"   ⚠️ CONECTÓ PERO CON ERROR: {response.status_code}")
            return None
    except requests.exceptions.ConnectionError:
        print("   ❌ FALLÓ: Conexión rechazada (¿El servicio está apagado o la URL es incorrecta?)")
    except requests.exceptions.NameResolutionError:
        print("   ❌ FALLÓ: No se pudo resolver el nombre (Tu PC no sabe quién es este host)")
    except Exception as e:
        print(f"   ❌ FALLÓ: {str(e)}")
    return None

# Ejecutar pruebas
valid_es = None
valid_ml = None

for test in test_urls:
    if "Elasticsearch" in test['name'] and not valid_es:
        result = check_url(test)
        if result: valid_es = result
    elif "ML API" in test['name'] and not valid_ml:
        result = check_url(test)
        if result: valid_ml = result

print("\n" + "="*60)
print("📝 RESULTADOS Y SOLUCIÓN")
print("="*60)

if valid_es:
    print(f"✅ Elasticsearch está accesible en: {valid_es}")
else:
    print("❌ Elasticsearch NO es accesible en ninguna dirección probada.")
    print("   -> Asegúrate de que el contenedor esté corriendo: 'docker ps'")
    print("   -> Asegúrate de que el puerto 9200 esté expuesto en docker-compose.yml")

if valid_ml:
    print(f"✅ ML API está accesible en: {valid_ml}")
else:
    print("❌ ML API NO es accesible.")

if valid_es or valid_ml:
    print("\n💡 PARA ARREGLAR TU APP.PY:")
    print("Cambia las líneas de configuración al inicio de tu archivo por:")
    if valid_es:
        print(f'ES_HOST = "{valid_es}"')
    if valid_ml:
        print(f'ML_API_URL = "{valid_ml}"')
