sudo tee /opt/zeek/share/zeek/site/scripts/flowmeter.zeek > /dev/null << 'FLOWMETER_FIX'
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
        # CORRECCIÓN AQUÍ: iterar directamente sobre los caracteres
        for (ch in h)
        {
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
FLOWMETER_FIX
