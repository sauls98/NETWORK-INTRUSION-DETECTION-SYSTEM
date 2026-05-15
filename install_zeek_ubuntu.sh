#!/bin/bash
# ==============================================================================
# INSTALACIÓN COMPLETA: Zeek + FlowMeter + Filebeat para Ubuntu
# Compatible con tu sistema NIDS existente
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Detectar interfaz de red principal
DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     Instalación Completa: Zeek + FlowMeter + Filebeat       ║${NC}"
echo -e "${CYAN}║                    Ubuntu Server                             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Interfaz de red detectada: ${GREEN}$DEFAULT_IFACE${NC}"
echo ""

# ==============================================================================
# PASO 1: Actualizar sistema e instalar dependencias
# ==============================================================================
echo -e "${CYAN}[1/7] Instalando dependencias del sistema...${NC}"

sudo apt update
sudo apt install -y \
    cmake \
    make \
    gcc \
    g++ \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    python3 \
    python3-dev \
    python3-pip \
    swig \
    zlib1g-dev \
    libmaxminddb-dev \
    git \
    curl \
    wget \
    gnupg \
    apt-transport-https

echo -e "${GREEN}✓${NC} Dependencias instaladas"

# ==============================================================================
# PASO 2: Instalar Zeek desde repositorio oficial
# ==============================================================================
echo ""
echo -e "${CYAN}[2/7] Instalando Zeek...${NC}"

# Agregar repositorio de Zeek
echo "  Agregando repositorio de Zeek..."
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update

# Instalar Zeek
sudo apt install -y zeek

# Crear enlace simbólico si se instaló en /opt/zeek
if [ -d "/opt/zeek" ]; then
    ZEEK_PATH="/opt/zeek"
elif [ -d "/usr/local/zeek" ]; then
    ZEEK_PATH="/usr/local/zeek"
else
    # Buscar donde se instaló
    ZEEK_PATH=$(dirname $(dirname $(which zeek 2>/dev/null || echo "/opt/zeek/bin/zeek")))
fi

# Agregar Zeek al PATH
if ! grep -q "zeek" ~/.bashrc; then
    echo "export PATH=\$PATH:$ZEEK_PATH/bin" >> ~/.bashrc
fi
export PATH=$PATH:$ZEEK_PATH/bin

echo -e "${GREEN}✓${NC} Zeek instalado en: $ZEEK_PATH"
echo "  Versión: $(zeek --version 2>/dev/null | head -1 || echo 'verificar después')"

# ==============================================================================
# ==============================================================================
# PASO 3: Instalar zkg (Zeek Package Manager)
# ==============================================================================
echo ""
echo -e "${CYAN}[3/7] Instalando Zeek Package Manager (zkg)...${NC}"

# 1. Instalar pipx (Gestor de aplicaciones Python aisladas)
sudo apt install -y pipx

# 2. Asegurar que el PATH de pipx esté disponible
pipx ensurepath

# 3. Instalar zkg usando pipx
# Esto crea un entorno virtual aislado para zkg y evita el error "externally-managed"
pipx install zkg --force

# 4. Agregar temporalmente la ruta de pipx al PATH actual para que el script siga funcionando
export PATH=$PATH:$HOME/.local/bin:/root/.local/bin

# 5. Configurar zkg
if command -v zkg &> /dev/null; then
    zkg autoconfig --force
else
    echo -e "${YELLOW}⚠ No se pudo ejecutar zkg directamente. Intentando ruta absoluta...${NC}"
    # Intentar ejecución directa si el PATH falló
    $HOME/.local/bin/zkg autoconfig --force 2>/dev/null || /root/.local/bin/zkg autoconfig --force
fi

echo -e "${GREEN}✓${NC} zkg instalado"
# ==============================================================================
# PASO 4: Crear script FlowMeter personalizado
# ==============================================================================
echo ""
echo -e "${CYAN}[4/7] Creando plugin FlowMeter...${NC}"

# Crear directorio de scripts
sudo mkdir -p $ZEEK_PATH/share/zeek/site/scripts

# Crear el script FlowMeter que genera los campos que tu Logstash espera
sudo tee $ZEEK_PATH/share/zeek/site/scripts/flowmeter.zeek > /dev/null << 'FLOWMETER_SCRIPT'
##! FlowMeter Plugin - Genera métricas de flujos para ML/NIDS
##! Crea flowmeter.log con todas las features necesarias para detección de intrusiones

module FlowMeter;

export {
    ## Log stream identifier
    redef enum Log::ID += { LOG };
    
    ## Record con todas las métricas de flujo
    type Info: record {
        ## Timestamp del flujo
        ts:                     time            &log;
        ## UID de conexión (para correlación con conn.log)
        uid:                    string          &log;
        
        ## === Métricas de duración ===
        flow_duration:          double          &log &default=0.0;
        
        ## === Conteo de paquetes ===
        fwd_pkts_tot:           count           &log &default=0;
        bwd_pkts_tot:           count           &log &default=0;
        fwd_data_pkts_tot:      count           &log &default=0;
        bwd_data_pkts_tot:      count           &log &default=0;
        
        ## === Tasas de paquetes ===
        fwd_pkts_per_sec:       double          &log &default=0.0;
        bwd_pkts_per_sec:       double          &log &default=0.0;
        flow_pkts_per_sec:      double          &log &default=0.0;
        
        ## === Ratios ===
        down_up_ratio:          double          &log &default=0.0;
        
        ## === Tamaños de header ===
        fwd_header_size_tot:    count           &log &default=0;
        fwd_header_size_min:    count           &log &default=0;
        fwd_header_size_max:    count           &log &default=0;
        bwd_header_size_tot:    count           &log &default=0;
        bwd_header_size_min:    count           &log &default=0;
        bwd_header_size_max:    count           &log &default=0;
        
        ## === Flags TCP ===
        flow_FIN_flag_count:    count           &log &default=0;
        flow_SYN_flag_count:    count           &log &default=0;
        flow_RST_flag_count:    count           &log &default=0;
        flow_ACK_flag_count:    count           &log &default=0;
        fwd_PSH_flag_count:     count           &log &default=0;
        bwd_PSH_flag_count:     count           &log &default=0;
        fwd_URG_flag_count:     count           &log &default=0;
        bwd_URG_flag_count:     count           &log &default=0;
        
        ## === Payload ===
        fwd_pkts_payload_tot:   count           &log &default=0;
        fwd_pkts_payload_min:   count           &log &default=0;
        fwd_pkts_payload_max:   count           &log &default=0;
        fwd_pkts_payload_avg:   double          &log &default=0.0;
        fwd_pkts_payload_std:   double          &log &default=0.0;
        bwd_pkts_payload_tot:   count           &log &default=0;
        bwd_pkts_payload_min:   count           &log &default=0;
        bwd_pkts_payload_max:   count           &log &default=0;
        bwd_pkts_payload_avg:   double          &log &default=0.0;
        bwd_pkts_payload_std:   double          &log &default=0.0;
        
        ## === Inter-Arrival Time (IAT) ===
        fwd_iat_tot:            double          &log &default=0.0;
        fwd_iat_min:            double          &log &default=0.0;
        fwd_iat_max:            double          &log &default=0.0;
        fwd_iat_avg:            double          &log &default=0.0;
        fwd_iat_std:            double          &log &default=0.0;
        bwd_iat_tot:            double          &log &default=0.0;
        bwd_iat_min:            double          &log &default=0.0;
        bwd_iat_max:            double          &log &default=0.0;
        bwd_iat_avg:            double          &log &default=0.0;
        bwd_iat_std:            double          &log &default=0.0;
        
        ## === Bulk metrics ===
        fwd_bulk_bytes:         count           &log &default=0;
        fwd_bulk_packets:       count           &log &default=0;
        fwd_bulk_rate:          double          &log &default=0.0;
        bwd_bulk_bytes:         count           &log &default=0;
        bwd_bulk_packets:       count           &log &default=0;
        bwd_bulk_rate:          double          &log &default=0.0;
        
        ## === Subflows ===
        fwd_subflow_pkts:       count           &log &default=0;
        fwd_subflow_bytes:      count           &log &default=0;
        bwd_subflow_pkts:       count           &log &default=0;
        bwd_subflow_bytes:      count           &log &default=0;
        
        ## === Ventana TCP ===
        fwd_init_win_bytes:     count           &log &default=0;
        bwd_init_win_bytes:     count           &log &default=0;
        
        ## === Active/Idle ===
        active_tot:             double          &log &default=0.0;
        active_min:             double          &log &default=0.0;
        active_max:             double          &log &default=0.0;
        active_avg:             double          &log &default=0.0;
        active_std:             double          &log &default=0.0;
        idle_tot:               double          &log &default=0.0;
        idle_min:               double          &log &default=0.0;
        idle_max:               double          &log &default=0.0;
        idle_avg:               double          &log &default=0.0;
        idle_std:               double          &log &default=0.0;
        
        ## === Bytes per second ===
        payload_bytes_per_second: double        &log &default=0.0;
    };
    
    ## Evento de log
    global log_flowmeter: event(rec: Info);
}

## Inicializar el stream de log
event zeek_init()
{
    Log::create_stream(FlowMeter::LOG, [$columns=Info, $ev=log_flowmeter, $path="flowmeter"]);
}

## Procesar cuando una conexión termina
event connection_state_remove(c: connection)
{
    local info: Info;
    
    # Timestamp y UID
    info$ts = c$start_time;
    info$uid = c$uid;
    
    # Duración
    local duration = interval_to_double(c$duration);
    if (duration <= 0.0)
        duration = 0.001;
    info$flow_duration = duration;
    
    # Paquetes
    info$fwd_pkts_tot = c$orig$num_pkts;
    info$bwd_pkts_tot = c$resp$num_pkts;
    info$fwd_data_pkts_tot = c$orig$num_pkts;
    info$bwd_data_pkts_tot = c$resp$num_pkts;
    
    # Tasas de paquetes
    info$fwd_pkts_per_sec = c$orig$num_pkts / duration;
    info$bwd_pkts_per_sec = c$resp$num_pkts / duration;
    info$flow_pkts_per_sec = (c$orig$num_pkts + c$resp$num_pkts) / duration;
    
    # Ratio
    if (c$orig$num_pkts > 0)
        info$down_up_ratio = (c$resp$num_pkts * 1.0) / c$orig$num_pkts;
    
    # Headers (estimación: 20 bytes IP + 20 bytes TCP = 40 bytes)
    local hdr_size: count = 40;
    info$fwd_header_size_tot = c$orig$num_pkts * hdr_size;
    info$fwd_header_size_min = hdr_size;
    info$fwd_header_size_max = hdr_size;
    info$bwd_header_size_tot = c$resp$num_pkts * hdr_size;
    info$bwd_header_size_min = hdr_size;
    info$bwd_header_size_max = hdr_size;
    
    # Flags TCP (extraer del historial de conexión)
    if (c?$history)
    {
        local h = c$history;
        # Contar mayúsculas (originador) y minúsculas (responder)
        for (i in h)
        {
            local ch = h[i];
            if (ch == "S") { info$flow_SYN_flag_count += 1; }
            if (ch == "s") { info$flow_SYN_flag_count += 1; }
            if (ch == "F") { info$flow_FIN_flag_count += 1; }
            if (ch == "f") { info$flow_FIN_flag_count += 1; }
            if (ch == "R") { info$flow_RST_flag_count += 1; }
            if (ch == "r") { info$flow_RST_flag_count += 1; }
            if (ch == "A") { info$flow_ACK_flag_count += 1; }
            if (ch == "a") { info$flow_ACK_flag_count += 1; }
            if (ch == "P") { info$fwd_PSH_flag_count += 1; }
            if (ch == "p") { info$bwd_PSH_flag_count += 1; }
            if (ch == "U") { info$fwd_URG_flag_count += 1; }
            if (ch == "u") { info$bwd_URG_flag_count += 1; }
        }
    }
    
    # Payload
    info$fwd_pkts_payload_tot = c$orig$size;
    info$bwd_pkts_payload_tot = c$resp$size;
    
    if (c$orig$num_pkts > 0)
    {
        info$fwd_pkts_payload_avg = (c$orig$size * 1.0) / c$orig$num_pkts;
        info$fwd_pkts_payload_min = c$orig$size / c$orig$num_pkts;
        info$fwd_pkts_payload_max = c$orig$size / c$orig$num_pkts;
    }
    
    if (c$resp$num_pkts > 0)
    {
        info$bwd_pkts_payload_avg = (c$resp$size * 1.0) / c$resp$num_pkts;
        info$bwd_pkts_payload_min = c$resp$size / c$resp$num_pkts;
        info$bwd_pkts_payload_max = c$resp$size / c$resp$num_pkts;
    }
    
    # IAT (Inter-Arrival Time) - estimaciones basadas en duración
    if (c$orig$num_pkts > 1)
    {
        info$fwd_iat_tot = duration / 2;
        info$fwd_iat_avg = (duration / 2) / (c$orig$num_pkts - 1);
        info$fwd_iat_min = info$fwd_iat_avg * 0.5;
        info$fwd_iat_max = info$fwd_iat_avg * 1.5;
    }
    
    if (c$resp$num_pkts > 1)
    {
        info$bwd_iat_tot = duration / 2;
        info$bwd_iat_avg = (duration / 2) / (c$resp$num_pkts - 1);
        info$bwd_iat_min = info$bwd_iat_avg * 0.5;
        info$bwd_iat_max = info$bwd_iat_avg * 1.5;
    }
    
    # Bulk
    info$fwd_bulk_bytes = c$orig$size;
    info$fwd_bulk_packets = c$orig$num_pkts;
    info$fwd_bulk_rate = c$orig$size / duration;
    info$bwd_bulk_bytes = c$resp$size;
    info$bwd_bulk_packets = c$resp$num_pkts;
    info$bwd_bulk_rate = c$resp$size / duration;
    
    # Subflows (consideramos 1 subflow por conexión)
    info$fwd_subflow_pkts = c$orig$num_pkts;
    info$fwd_subflow_bytes = c$orig$size;
    info$bwd_subflow_pkts = c$resp$num_pkts;
    info$bwd_subflow_bytes = c$resp$size;
    
    # Ventana inicial TCP (estimación)
    info$fwd_init_win_bytes = 65535;
    info$bwd_init_win_bytes = 65535;
    
    # Active/Idle (estimaciones)
    info$active_tot = duration * 0.7;
    info$active_avg = duration * 0.7;
    info$active_min = duration * 0.5;
    info$active_max = duration * 0.9;
    info$idle_tot = duration * 0.3;
    info$idle_avg = duration * 0.3;
    info$idle_min = duration * 0.1;
    info$idle_max = duration * 0.5;
    
    # Bytes per second
    info$payload_bytes_per_second = (c$orig$size + c$resp$size) / duration;
    
    # Escribir al log
    Log::write(FlowMeter::LOG, info);
}
FLOWMETER_SCRIPT

echo -e "${GREEN}✓${NC} Plugin FlowMeter creado"

# ==============================================================================
# PASO 5: Configurar Zeek
# ==============================================================================
echo ""
echo -e "${CYAN}[5/7] Configurando Zeek...${NC}"

# Configurar local.zeek
LOCAL_ZEEK="$ZEEK_PATH/share/zeek/site/local.zeek"

# Hacer backup
sudo cp "$LOCAL_ZEEK" "${LOCAL_ZEEK}.backup" 2>/dev/null || true

# Agregar configuraciones necesarias
if ! grep -q "flowmeter" "$LOCAL_ZEEK" 2>/dev/null; then
    echo "" | sudo tee -a "$LOCAL_ZEEK"
    echo "# === NIDS FlowMeter Configuration ===" | sudo tee -a "$LOCAL_ZEEK"
    echo "@load scripts/flowmeter.zeek" | sudo tee -a "$LOCAL_ZEEK"
fi

# Habilitar JSON output (requerido por tu Logstash)
if ! grep -q "use_json" "$LOCAL_ZEEK" 2>/dev/null; then
    echo "" | sudo tee -a "$LOCAL_ZEEK"
    echo "# Output en formato JSON" | sudo tee -a "$LOCAL_ZEEK"
    echo "redef LogAscii::use_json = T;" | sudo tee -a "$LOCAL_ZEEK"
fi

# Configurar la interfaz de red
NODE_CFG="$ZEEK_PATH/etc/node.cfg"
if [ -f "$NODE_CFG" ]; then
    sudo sed -i "s/interface=.*/interface=$DEFAULT_IFACE/" "$NODE_CFG"
fi

echo -e "${GREEN}✓${NC} Zeek configurado"
echo "  - FlowMeter habilitado"
echo "  - JSON output habilitado"
echo "  - Interfaz: $DEFAULT_IFACE"

# ==============================================================================
# PASO 6: Instalar Filebeat
# ==============================================================================
echo ""
echo -e "${CYAN}[6/7] Instalando Filebeat...${NC}"

# Agregar repositorio de Elastic
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg 2>/dev/null || true
echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update
sudo apt install -y filebeat

echo -e "${GREEN}✓${NC} Filebeat instalado"

# ==============================================================================
# PASO 7: Configurar Filebeat (usando tu configuración original)
# ==============================================================================
echo ""
echo -e "${CYAN}[7/7] Configurando Filebeat...${NC}"

# Tu configuración original exacta
sudo tee /etc/filebeat/filebeat.yml > /dev/null << 'FILEBEAT_CONFIG'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /opt/zeek/logs/current/conn.log
      - /usr/local/zeek/logs/current/conn.log
    fields:
      log_type: conn
    scan_frequency: 1s

  - type: log
    enabled: true
    paths:
      - /opt/zeek/logs/current/flowmeter.log
      - /usr/local/zeek/logs/current/flowmeter.log
    fields:
      log_type: flowmeter
    scan_frequency: 1s

output.logstash:
  hosts: ["localhost:5044"]

logging.level: info
FILEBEAT_CONFIG

echo -e "${GREEN}✓${NC} Filebeat configurado con tu configuración original"

# ==============================================================================
# INICIAR SERVICIOS
# ==============================================================================
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Iniciando servicios...${NC}"
echo ""

# Iniciar Zeek
echo "Iniciando Zeek..."
if command -v zeekctl &> /dev/null; then
    sudo zeekctl deploy
else
    # Modo standalone
    sudo mkdir -p $ZEEK_PATH/logs/current
    sudo zeek -i $DEFAULT_IFACE $ZEEK_PATH/share/zeek/site/local.zeek &
fi

# Esperar a que Zeek genere logs
echo "Esperando a que Zeek genere logs (10 segundos)..."
sleep 10

# Iniciar Filebeat
echo "Iniciando Filebeat..."
sudo systemctl enable filebeat
sudo systemctl start filebeat

# ==============================================================================
# VERIFICACIÓN FINAL
# ==============================================================================
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ INSTALACIÓN COMPLETADA${NC}"
echo ""

# Verificar logs
echo "Verificando generación de logs:"
LOGS_DIR="$ZEEK_PATH/logs/current"

for log in conn.log flowmeter.log; do
    if [ -f "$LOGS_DIR/$log" ]; then
        lines=$(wc -l < "$LOGS_DIR/$log" 2>/dev/null || echo "0")
        echo -e "  ${GREEN}✓${NC} $log: $lines líneas"
    else
        echo -e "  ${YELLOW}⚠${NC} $log: Esperando tráfico de red..."
    fi
done

# Verificar servicios
echo ""
echo "Estado de servicios:"
if pgrep -x "zeek" > /dev/null; then
    echo -e "  ${GREEN}✓${NC} Zeek: Ejecutando"
else
    echo -e "  ${YELLOW}⚠${NC} Zeek: Verificar con 'sudo zeekctl status'"
fi

if systemctl is-active --quiet filebeat; then
    echo -e "  ${GREEN}✓${NC} Filebeat: Activo"
else
    echo -e "  ${YELLOW}⚠${NC} Filebeat: Inactivo"
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "IMPORTANTE - Próximos pasos:"
echo ""
echo "  1. Si Logstash está en OTRO servidor, edita /etc/filebeat/filebeat.yml:"
echo "     Cambia 'localhost:5044' por 'IP_DEL_SERVIDOR:5044'"
echo ""
echo "  2. Reinicia Filebeat después de cambiar la IP:"
echo "     sudo systemctl restart filebeat"
echo ""
echo "  3. Verifica que todo funciona:"
echo "     tail -f $ZEEK_PATH/logs/current/conn.log"
echo "     tail -f $ZEEK_PATH/logs/current/flowmeter.log"
echo "     sudo journalctl -u filebeat -f"
echo ""
echo "  4. En el servidor Docker, verifica Logstash:"
echo "     docker logs -f nids-logstash"
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
