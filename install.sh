#!/bin/bash
# ==============================================================================
# NIDS SOC System v4.0 - Instalación
# ==============================================================================
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           NIDS SOC System v4.0 - Instalación                ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Verificar Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}✗ Docker no instalado${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker"

if ! docker compose version &> /dev/null && ! command -v docker compose &> /dev/null; then
    echo -e "${RED}✗ Docker Compose no instalado${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker Compose"

# Crear directorios
mkdir -p ml_api/models data logs
touch ml_api/models/.gitkeep

echo ""
echo -e "${CYAN}[1/4] Iniciando servicios Docker...${NC}"

# Build e inicio
docker compose up -d --build

echo ""
echo -e "${CYAN}[2/4] Esperando Elasticsearch...${NC}"
sleep 10

for i in {1..30}; do
    if curl -s "http://localhost:9200/_cluster/health" | grep -q '"status"'; then
        echo -e "${GREEN}✓${NC} Elasticsearch listo"
        break
    fi
    echo "  Esperando... ($i/30)"
    sleep 2
done

echo ""
echo -e "${CYAN}[3/4] Aplicando template Elasticsearch...${NC}"
curl -s -X PUT "http://localhost:9200/_index_template/nids-template" \
    -H "Content-Type: application/json" \
    -d @config/elasticsearch/nids_template.json | grep -q "acknowledged" && \
    echo -e "${GREEN}✓${NC} Template aplicado" || \
    echo -e "${YELLOW}⚠${NC} Error aplicando template"

echo ""
echo -e "${CYAN}[4/4] Verificación final...${NC}"

# Estado
ES=$(curl -s "http://localhost:9200/_cluster/health" | grep -o '"status":"[^"]*"' | cut -d'"' -f4 2>/dev/null)
ML=$(curl -s "http://localhost:5000/health" | grep -o '"models_loaded":[^,]*' | cut -d':' -f2 2>/dev/null)
DASH=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8050" 2>/dev/null)

echo ""
echo "  Estado de servicios:"
[ -n "$ES" ] && echo -e "  ${GREEN}✓${NC} Elasticsearch: $ES" || echo -e "  ${RED}✗${NC} Elasticsearch"
[ "$ML" = "true" ] && echo -e "  ${GREEN}✓${NC} ML API: Activo" || echo -e "  ${YELLOW}⚠${NC} ML API: Modelo de desarrollo"
[ "$DASH" = "200" ] && echo -e "  ${GREEN}✓${NC} Dashboard: Activo" || echo -e "  ${YELLOW}⚠${NC} Dashboard: Iniciando..."

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Instalación completada${NC}"
echo ""
echo "  URLs:"
echo -e "  ${CYAN}•${NC} Dashboard:     http://localhost:8050"
echo -e "  ${CYAN}•${NC} Kibana:        http://localhost:5601"
echo -e "  ${CYAN}•${NC} Elasticsearch: http://localhost:9200"
echo -e "  ${CYAN}•${NC} ML API:        http://localhost:5000"
echo ""
echo "  Siguiente paso - Configurar Filebeat en servidor Zeek:"
echo "    sudo cp config/filebeat/filebeat.yml /etc/filebeat/"
echo "    # Editar hosts de Logstash si es necesario"
echo "    sudo systemctl restart filebeat"
echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
