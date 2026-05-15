# 🛡️ NIDS SOC System v4.0 FINAL

## Sistema Profesional de Detección de Intrusiones con Correlación UID

Dashboard completo para equipos SOC/NOC con detección ML de 15 tipos de ataques.

## 🚀 Instalación Rápida

```bash
chmod +x install.sh
./install.sh
```

## 📊 URLs de Acceso

| Servicio | URL |
|----------|-----|
| **Dashboard SOC** | http://localhost:8050 |
| **Kibana** | http://localhost:5601 |
| **Elasticsearch** | http://localhost:9200 |
| **ML API** | http://localhost:5000 |
| **Logstash** | http://localhost:9600 |

## 🏗️ Arquitectura

```
Network → Zeek → Filebeat → Logstash → ML API → Elasticsearch → Dashboard
                                ↓
                        CORRELACIÓN UID:
                        conn.log (IPs) + flowmeter (ML)
```

## 🔑 Correlación UID - Cómo Funciona

**Problema**: `conn.log` tiene IPs/puertos, `flowmeter.log` tiene métricas ML, pero comparten el `uid`.

**Solución**: Logstash usa el `aggregate` filter:
1. `conn.log` llega primero → guarda IPs por UID en memoria
2. `flowmeter.log` llega después → obtiene IPs del UID correspondiente
3. Resultado: documento enriquecido con IPs + predicción ML

## 📁 Estructura

```
nids_production/
├── docker-compose.yml           # Orquestación
├── install.sh                   # Instalación
├── config/
│   ├── elasticsearch/
│   │   └── nids_template.json   # Template ES (previene errores de tipos)
│   ├── filebeat/
│   │   └── filebeat.yml         # Collector de logs Zeek
│   └── logstash/
│       ├── config/
│       │   ├── logstash.yml
│       │   └── pipelines.yml
│       └── pipeline/
│           └── nids.conf        # Pipeline con correlación UID
├── dashboard/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app.py                   # Dashboard SOC (6 pestañas)
└── ml_api/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py                   # API predicción
    └── models/                  # Modelos ML
```

## 🤖 Ataques Detectados

| Categoría | Ataques | Severidad |
|-----------|---------|-----------|
| **DDoS** | HOIC, LOIC-HTTP, LOIC-UDP | Critical |
| **Infiltration** | Infilteration | Critical |
| **DoS** | Hulk, GoldenEye, Slowloris, SlowHTTPTest | Medium-High |
| **Brute Force** | SSH, FTP, Web, XSS | Medium-High |
| **Injection** | SQL, XSS | High |
| **Bot** | Bot | High |

## 📊 Dashboard - 6 Pestañas

1. **📊 Resumen**: KPIs, severidad, timeline, gráficos
2. **🌐 Tráfico**: Top IPs origen/destino, puertos, protocolos
3. **🔬 Forense**: Ataques detectados, alertas críticas
4. **🤖 ML**: Estado del modelo, métricas, confianza
5. **🧠 Gemini**: Análisis AI (requiere API key)
6. **⚙️ Monitor**: Estado del sistema, índices ES

## ⚙️ Configuración

### Filebeat (en servidor Zeek)

```bash
sudo cp config/filebeat/filebeat.yml /etc/filebeat/
# Editar hosts si Logstash no está en localhost
sudo nano /etc/filebeat/filebeat.yml
sudo systemctl restart filebeat
```

### Gemini AI (opcional)

Editar `dashboard/app.py`:
```python
GEMINI_API_KEY = "tu-api-key"
```

Obtén API key: https://makersuite.google.com/

## 🔧 Comandos Útiles

```bash
# Ver logs
docker-compose logs -f

# Reiniciar
docker-compose restart

# Ver estado
docker-compose ps

# Eliminar índices
curl -X DELETE "http://localhost:9200/nids-*"

# Contar documentos
curl "http://localhost:9200/nids-*/_count"

# Ver índices
curl "http://localhost:9200/_cat/indices/nids-*?v"
```

## 🐛 Troubleshooting

### IPs no aparecen
- Verificar que `conn.log` llega antes que `flowmeter.log`
- Verificar índice conn: `curl "http://localhost:9200/nids-conn-*/_count"`

### Error de tipos en ES
- Aplicar template: ver sección instalación

### Dashboard sin datos
- Verificar Filebeat: `sudo systemctl status filebeat`
- Verificar Logstash: `curl http://localhost:9600`

## 📈 Índices de Elasticsearch

| Índice | Contenido |
|--------|-----------|
| `nids-conn-*` | Conexiones con IPs/puertos (de conn.log) |
| `nids-flows-*` | Flujos con predicción ML (de flowmeter) |
| `nids-attacks-*` | Solo ataques detectados |
| `nids-critical-*` | Ataques critical/high |

---

**NIDS SOC System v4.0 FINAL** - Producción
