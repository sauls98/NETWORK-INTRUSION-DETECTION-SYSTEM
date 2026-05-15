#!/usr/bin/env python3
"""
================================================================================
    NIDS SOC Dashboard v5.1 - CON REPORTES PDF
================================================================================
    INCLUYE:
    - Generación de reportes SOC profesionales en PDF
    - Múltiples tipos de reportes
    - Exportación con gráficos y tablas
================================================================================
"""

import dash
from dash import dcc, html, dash_table, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
import requests
import json
import warnings
from collections import Counter
import base64
import io
warnings.filterwarnings('ignore')

# Para generación de PDF
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak, HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart

# =============================================================================
# CONFIGURACIÓN
# =============================================================================

ES_HOST = "http://elasticsearch:9200"
ES_INDEX = "nids-*"
ML_API_URL = "http://ml-api:5000"
GEMINI_API_KEY = "AIzaSyC_Ie_V4xeoqLQbfZtY0UnfYk8zu5Kkr7Q"
REFRESH_INTERVAL = 10

COLORS = {
    'bg_dark': '#0a0e17',
    'bg_card': '#0d1321',
    'bg_header': '#151d2b',
    'bg_input': '#1a2332',
    'primary': '#3b82f6',
    'secondary': '#6366f1',
    'success': '#10b981',
    'warning': '#f59e0b',
    'danger': '#ef4444',
    'info': '#06b6d4',
    'purple': '#8b5cf6',
    'pink': '#ec4899',
    'text': '#e2e8f0',
    'text_muted': '#64748b',
    'border': '#1e293b',
    'grid': 'rgba(148,163,184,0.1)',
    'chart_colors': ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4', '#84cc16']
}

SEVERITY_CONFIG = {
    'critical': {'color': '#ef4444', 'bg': 'rgba(239,68,68,0.15)', 'icon': 'fa-skull-crossbones', 'label': 'CRÍTICO'},
    'high': {'color': '#f97316', 'bg': 'rgba(249,115,22,0.15)', 'icon': 'fa-exclamation-triangle', 'label': 'ALTO'},
    'medium': {'color': '#eab308', 'bg': 'rgba(234,179,8,0.15)', 'icon': 'fa-exclamation-circle', 'label': 'MEDIO'},
    'low': {'color': '#22c55e', 'bg': 'rgba(34,197,94,0.15)', 'icon': 'fa-info-circle', 'label': 'BAJO'},
    'info': {'color': '#06b6d4', 'bg': 'rgba(6,182,212,0.15)', 'icon': 'fa-shield-alt', 'label': 'INFO'},
    'unknown': {'color': '#64748b', 'bg': 'rgba(100,116,139,0.15)', 'icon': 'fa-question-circle', 'label': 'DESCONOCIDO'}
}

PORT_SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
}

# =============================================================================
# FUNCIONES DE CONEXIÓN
# =============================================================================

def get_es():
    try:
        es = Elasticsearch([ES_HOST], request_timeout=30)
        return es if es.ping() else None
    except:
        return None

def get_ml_status():
    try:
        r = requests.get(f"{ML_API_URL}/health", timeout=3)
        return r.json() if r.status_code == 200 else None
    except:
        return None

def get_ml_classes():
    try:
        r = requests.get(f"{ML_API_URL}/classes", timeout=3)
        return r.json() if r.status_code == 200 else None
    except:
        return None

# =============================================================================
# FUNCIONES DE EXTRACCIÓN DE DATOS
# =============================================================================

def extract_connection_info(doc):
    result = {
        'src_ip': None, 'src_port': None, 'dst_ip': None, 'dst_port': None,
        'proto': None, 'service': None, 'duration': None,
        'orig_bytes': None, 'resp_bytes': None, 'orig_pkts': None, 'resp_pkts': None
    }
    
    for field in result.keys():
        if field in doc and doc[field]:
            result[field] = doc[field]
    
    if not result['src_ip'] and 'event' in doc and isinstance(doc['event'], dict):
        original = doc['event'].get('original', '')
        if original and isinstance(original, str):
            try:
                parsed = json.loads(original)
                field_mapping = {
                    'id.orig_h': 'src_ip', 'id.orig_p': 'src_port',
                    'id.resp_h': 'dst_ip', 'id.resp_p': 'dst_port',
                    'proto': 'proto', 'service': 'service'
                }
                for zeek_field, our_field in field_mapping.items():
                    if zeek_field in parsed and parsed[zeek_field] is not None:
                        result[our_field] = parsed[zeek_field]
            except:
                pass
    return result

def get_all_data_with_ips(limit=2000):
    es = get_es()
    if not es:
        return pd.DataFrame()
    try:
        r = es.search(index=ES_INDEX, query={"match_all": {}}, size=limit, sort=[{"@timestamp": "desc"}])
        if not r['hits']['hits']:
            return pd.DataFrame()
        
        data = []
        for hit in r['hits']['hits']:
            doc = hit['_source'].copy()
            conn_info = extract_connection_info(doc)
            for key, value in conn_info.items():
                if value is not None:
                    doc[key] = value
            data.append(doc)
        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error getting data: {e}")
        return pd.DataFrame()

def get_aggregated_stats():
    es = get_es()
    if not es:
        return {}
    try:
        r = es.search(
            index=ES_INDEX,
            query={"match_all": {}},
            aggregations={
                "total_docs": {"value_count": {"field": "@timestamp"}},
                "attacks_count": {"filter": {"term": {"is_attack": True}}},
                "by_severity": {"terms": {"field": "severity", "size": 10}},
                "by_attack_type": {"terms": {"field": "attack_type", "size": 20}},
                "by_log_type": {"terms": {"field": "log_type", "size": 5}},
                "avg_confidence": {"avg": {"field": "ml_confidence"}},
                "total_bytes": {"sum": {"field": "total_bytes"}},
                "total_pkts": {"sum": {"field": "total_pkts"}},
                "by_hour": {"terms": {"field": "hour_of_day", "size": 24}},
                "by_day": {"terms": {"field": "day_of_week", "size": 7}},
                "by_protocol": {"terms": {"field": "proto", "size": 10}},
                "timeline": {
                    "date_histogram": {"field": "@timestamp", "fixed_interval": "5m"},
                    "aggs": {
                        "attacks": {"filter": {"term": {"is_attack": True}}},
                        "bytes": {"sum": {"field": "total_bytes"}}
                    }
                }
            },
            size=0
        )
        return r.get('aggregations', {})
    except Exception as e:
        print(f"Stats error: {e}")
        return {}

def get_attacks_with_ips(limit=1000):
    es = get_es()
    if not es:
        return pd.DataFrame()
    try:
        r = es.search(
            index=ES_INDEX,
            query={"bool": {"must": [{"term": {"is_attack": True}}]}},
            size=limit,
            sort=[{"@timestamp": "desc"}]
        )
        if not r['hits']['hits']:
            return pd.DataFrame()
        
        data = []
        for hit in r['hits']['hits']:
            doc = hit['_source'].copy()
            conn_info = extract_connection_info(doc)
            for key, value in conn_info.items():
                if value is not None:
                    doc[key] = value
            data.append(doc)
        return pd.DataFrame(data)
    except Exception as e:
        print(f"Error attacks: {e}")
        return pd.DataFrame()

def get_attack_by_uid(uid):
    es = get_es()
    if not es:
        return None
    try:
        r = es.search(index=ES_INDEX, query={"term": {"uid": uid}}, size=1)
        if r['hits']['hits']:
            return r['hits']['hits'][0]['_source']
        return None
    except:
        return None

def get_ip_statistics_from_df(df):
    stats = {'src_ips': [], 'dst_ips': [], 'dst_ports': [], 'protocols': [], 'services': []}
    if df.empty:
        return stats
    
    if 'src_ip' in df.columns:
        src_valid = df[df['src_ip'].notna() & (df['src_ip'] != '') & (df['src_ip'] != 'N/A')]
        if not src_valid.empty:
            src_counts = src_valid['src_ip'].value_counts().head(20)
            total = len(df)
            stats['src_ips'] = [{'ip': str(ip), 'count': int(count), 'pct': round(count/total*100, 2)} for ip, count in src_counts.items()]
    
    if 'dst_ip' in df.columns:
        dst_valid = df[df['dst_ip'].notna() & (df['dst_ip'] != '') & (df['dst_ip'] != 'N/A')]
        if not dst_valid.empty:
            dst_counts = dst_valid['dst_ip'].value_counts().head(20)
            total = len(df)
            stats['dst_ips'] = [{'ip': str(ip), 'count': int(count), 'pct': round(count/total*100, 2)} for ip, count in dst_counts.items()]
    
    if 'dst_port' in df.columns:
        port_valid = df[df['dst_port'].notna()]
        if not port_valid.empty:
            port_counts = port_valid['dst_port'].value_counts().head(20)
            stats['dst_ports'] = [{'port': int(port), 'count': int(count), 'service': PORT_SERVICES.get(int(port), 'Unknown')} for port, count in port_counts.items()]
    
    if 'proto' in df.columns:
        proto_valid = df[df['proto'].notna() & (df['proto'] != '')]
        if not proto_valid.empty:
            proto_counts = proto_valid['proto'].value_counts()
            stats['protocols'] = [{'proto': str(p).upper(), 'count': int(c)} for p, c in proto_counts.items()]
    
    if 'service' in df.columns:
        svc_valid = df[df['service'].notna() & (df['service'] != '') & (df['service'] != '-')]
        if not svc_valid.empty:
            svc_counts = svc_valid['service'].value_counts().head(15)
            stats['services'] = [{'service': str(s), 'count': int(c)} for s, c in svc_counts.items()]
    
    return stats

def check_system_status():
    status = {
        'elasticsearch': {'online': False, 'cluster': 'unknown', 'docs': 0, 'size': '0 MB'},
        'ml_api': {'online': False, 'predictions': 0, 'attacks': 0, 'model': 'Unknown'},
        'indices': [],
        'logstash': {'online': False},
        'zeek': {'online': False}
    }
    
    es = get_es()
    if es:
        try:
            health = es.cluster.health()
            status['elasticsearch']['online'] = True
            status['elasticsearch']['cluster'] = health['status']
            status['elasticsearch']['docs'] = es.count(index=ES_INDEX)['count']
            
            indices = list(es.indices.get_alias(index="nids-*").keys())
            total_size = 0
            for idx in indices[:10]:
                try:
                    s = es.indices.stats(index=idx)
                    docs = s['indices'][idx]['total']['docs']['count']
                    size = s['indices'][idx]['total']['store']['size_in_bytes'] / 1024 / 1024
                    total_size += size
                    status['indices'].append({'name': idx, 'docs': docs, 'size_mb': round(size, 2)})
                except:
                    pass
            status['elasticsearch']['size'] = f"{total_size:.1f} MB"
            
            r = es.search(index=ES_INDEX, query={"match_all": {}}, size=1, sort=[{"@timestamp": "desc"}])
            if r['hits']['hits']:
                last_ts = r['hits']['hits'][0]['_source'].get('@timestamp', '')
                if last_ts:
                    last_time = datetime.fromisoformat(last_ts.replace('Z', '+00:00'))
                    if (datetime.now(last_time.tzinfo) - last_time).total_seconds() < 300:
                        status['zeek']['online'] = True
                        status['logstash']['online'] = True
        except Exception as e:
            print(f"ES status error: {e}")
    
    ml = get_ml_status()
    if ml:
        status['ml_api']['online'] = ml.get('models_loaded', False)
        status['ml_api']['predictions'] = ml.get('predictions_count', 0)
        status['ml_api']['attacks'] = ml.get('attacks_detected', 0)
        status['ml_api']['model'] = ml.get('model_name', 'RandomForest')
    
    return status

# =============================================================================
# FUNCIONES DE GESTIÓN DE ÍNDICES
# =============================================================================

def get_indices_details():
    """Obtiene detalles de todos los índices NIDS"""
    es = get_es()
    if not es:
        return []
    
    try:
        indices = list(es.indices.get_alias(index="nids-*").keys())
        details = []
        
        for idx in sorted(indices, reverse=True):
            try:
                stats = es.indices.stats(index=idx)
                idx_stats = stats['indices'][idx]['total']
                
                # Obtener fecha del índice
                date_part = idx.split('-')[-1] if '-' in idx else 'unknown'
                
                # Obtener rango de timestamps
                first_doc = es.search(index=idx, query={"match_all": {}}, size=1, sort=[{"@timestamp": "asc"}])
                last_doc = es.search(index=idx, query={"match_all": {}}, size=1, sort=[{"@timestamp": "desc"}])
                
                first_ts = first_doc['hits']['hits'][0]['_source'].get('@timestamp', 'N/A')[:10] if first_doc['hits']['hits'] else 'N/A'
                last_ts = last_doc['hits']['hits'][0]['_source'].get('@timestamp', 'N/A')[:10] if last_doc['hits']['hits'] else 'N/A'
                
                # Contar ataques
                attacks = es.count(index=idx, query={"term": {"is_attack": True}})['count']
                
                details.append({
                    'name': idx,
                    'date': date_part,
                    'docs': idx_stats['docs']['count'],
                    'size_bytes': idx_stats['store']['size_in_bytes'],
                    'size_mb': round(idx_stats['store']['size_in_bytes'] / 1024 / 1024, 2),
                    'attacks': attacks,
                    'first_event': first_ts,
                    'last_event': last_ts
                })
            except Exception as e:
                print(f"Error getting stats for {idx}: {e}")
                continue
        
        return details
    except Exception as e:
        print(f"Error listing indices: {e}")
        return []

def export_index_data(index_name, format_type='json', limit=None):
    """Exporta datos de un índice en el formato especificado"""
    es = get_es()
    if not es:
        return None, "Elasticsearch no disponible"
    
    try:
        # Obtener total de documentos
        total = es.count(index=index_name)['count']
        fetch_limit = limit if limit else total
        
        # Usar scroll para obtener todos los documentos
        all_docs = []
        batch_size = 1000
        
        resp = es.search(
            index=index_name,
            query={"match_all": {}},
            size=min(batch_size, fetch_limit),
            scroll='2m',
            sort=[{"@timestamp": "desc"}]
        )
        
        scroll_id = resp['_scroll_id']
        all_docs.extend([hit['_source'] for hit in resp['hits']['hits']])
        
        while len(all_docs) < fetch_limit:
            resp = es.scroll(scroll_id=scroll_id, scroll='2m')
            if not resp['hits']['hits']:
                break
            all_docs.extend([hit['_source'] for hit in resp['hits']['hits']])
            if len(all_docs) >= fetch_limit:
                break
        
        # Limpiar scroll
        try:
            es.clear_scroll(scroll_id=scroll_id)
        except:
            pass
        
        all_docs = all_docs[:fetch_limit]
        
        # Formatear según tipo
        if format_type == 'json':
            return json.dumps(all_docs, indent=2, default=str), None
        elif format_type == 'ndjson':
            return '\n'.join([json.dumps(doc, default=str) for doc in all_docs]), None
        elif format_type == 'csv':
            if not all_docs:
                return "", None
            df = pd.DataFrame(all_docs)
            return df.to_csv(index=False), None
        else:
            return None, "Formato no soportado"
            
    except Exception as e:
        return None, str(e)

def delete_index(index_name):
    """Elimina un índice de Elasticsearch"""
    es = get_es()
    if not es:
        return False, "Elasticsearch no disponible"
    
    try:
        # Verificar que el índice existe
        if not es.indices.exists(index=index_name):
            return False, f"El índice {index_name} no existe"
        
        # Obtener info antes de eliminar
        stats = es.indices.stats(index=index_name)
        docs = stats['indices'][index_name]['total']['docs']['count']
        
        # Eliminar
        es.indices.delete(index=index_name)
        
        return True, f"Índice {index_name} eliminado ({docs:,} documentos)"
    except Exception as e:
        return False, str(e)

def delete_old_indices(days=7):
    """Elimina índices más antiguos que X días"""
    es = get_es()
    if not es:
        return False, "Elasticsearch no disponible"
    
    try:
        indices = get_indices_details()
        cutoff_date = datetime.now() - timedelta(days=days)
        deleted = []
        
        for idx in indices:
            try:
                # Parsear fecha del nombre del índice
                date_str = idx['date']
                idx_date = datetime.strptime(date_str, '%Y.%m.%d')
                
                if idx_date < cutoff_date:
                    success, msg = delete_index(idx['name'])
                    if success:
                        deleted.append(idx['name'])
            except:
                continue
        
        if deleted:
            return True, f"Eliminados {len(deleted)} índices: {', '.join(deleted)}"
        else:
            return True, "No hay índices antiguos para eliminar"
    except Exception as e:
        return False, str(e)

def call_gemini(prompt):
    if not GEMINI_API_KEY:
        return "⚠️ API Key de Gemini no configurada."
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
        r = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=60)
        if r.status_code == 200:
            text = r.json()['candidates'][0]['content']['parts'][0]['text']
            return format_gemini_response(text)
        return f"Error API: {r.status_code} - {r.text[:200]}"
    except Exception as e:
        return f"Error: {e}"

def format_gemini_response(text):
    """Convierte la respuesta de Gemini en componentes HTML con tablas formateadas"""
    lines = text.split('\n')
    elements = []
    table_lines = []
    in_table = False
    
    for line in lines:
        stripped = line.strip()
        
        # Detectar línea de tabla
        if '|' in stripped and stripped.startswith('|') and stripped.endswith('|'):
            in_table = True
            table_lines.append(stripped)
        else:
            # Si estábamos en una tabla, procesarla
            if in_table and table_lines:
                elements.append(create_html_table(table_lines))
                table_lines = []
                in_table = False
            
            # Procesar línea normal
            if stripped:
                # Títulos con emoji
                if any(stripped.startswith(e) for e in ['🚦', '📊', '⚠️', '⚡', '🔍', '📈', '🎯', '✅', '📋', '🔴', '🛡️', '🚨', '🔒', '🔥', '🌐', '⏱️', '🔗', '📝']):
                    elements.append(html.H6(stripped, style={'color': COLORS['primary'], 'marginTop': '1rem', 'marginBottom': '0.5rem', 'fontWeight': '700'}))
                # Líneas numeradas
                elif stripped[0].isdigit() and '. ' in stripped[:4]:
                    elements.append(html.P(stripped, style={'color': COLORS['text'], 'marginBottom': '0.3rem', 'paddingLeft': '0.5rem'}))
                # Líneas normales
                else:
                    elements.append(html.P(stripped, style={'color': COLORS['text'], 'marginBottom': '0.5rem'}))
    
    # Procesar última tabla si existe
    if table_lines:
        elements.append(create_html_table(table_lines))
    
    return html.Div(elements)

def create_html_table(table_lines):
    """Crea una tabla HTML desde líneas de markdown"""
    if len(table_lines) < 2:
        return html.P(' | '.join(table_lines), style={'color': COLORS['text']})
    
    # Parsear headers
    headers = [cell.strip() for cell in table_lines[0].split('|') if cell.strip()]
    
    # Ignorar línea separadora (---|---|---)
    data_start = 1
    if len(table_lines) > 1 and all(c in '-|: ' for c in table_lines[1]):
        data_start = 2
    
    # Parsear datos
    rows = []
    for line in table_lines[data_start:]:
        cells = [cell.strip() for cell in line.split('|') if cell.strip()]
        if cells:
            rows.append(cells)
    
    # Crear tabla HTML
    table_header = html.Thead(
        html.Tr([html.Th(h, style={
            'backgroundColor': COLORS['bg_header'],
            'color': COLORS['primary'],
            'padding': '0.5rem',
            'fontSize': '0.75rem',
            'fontWeight': '600',
            'borderBottom': f'2px solid {COLORS["primary"]}'
        }) for h in headers])
    )
    
    table_body = html.Tbody([
        html.Tr([
            html.Td(cell, style={
                'backgroundColor': COLORS['bg_card'] if i % 2 == 0 else COLORS['bg_header'],
                'color': COLORS['text'],
                'padding': '0.4rem',
                'fontSize': '0.8rem',
                'borderBottom': f'1px solid {COLORS["border"]}'
            }) for cell in row
        ]) for i, row in enumerate(rows)
    ])
    
    return html.Table([table_header, table_body], style={
        'width': '100%',
        'borderCollapse': 'collapse',
        'marginBottom': '1rem',
        'marginTop': '0.5rem'
    })

def format_bytes(bytes_val):
    if bytes_val is None or bytes_val == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(bytes_val) < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"

# =============================================================================
# GENERADOR DE REPORTES PDF
# =============================================================================

def generate_soc_report_pdf(report_type, author, org_name, include_recommendations=True):
    """Genera un reporte SOC profesional en PDF"""
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
    
    # Estilos
    styles = getSampleStyleSheet()
    
    # Estilos personalizados
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1e3a5f')
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#64748b')
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor('#1e3a5f'),
        borderPadding=5
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubheading',
        parent=styles['Heading3'],
        fontSize=12,
        spaceBefore=15,
        spaceAfter=8,
        textColor=colors.HexColor('#3b82f6')
    )
    
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=8,
        alignment=TA_JUSTIFY,
        leading=14
    )
    
    # Obtener datos
    stats = get_aggregated_stats()
    attacks_df = get_attacks_with_ips(500)
    df = get_all_data_with_ips(1000)
    ip_stats = get_ip_statistics_from_df(df)
    system_status = check_system_status()
    
    total = stats.get('total_docs', {}).get('value', 0) or 0
    attacks = stats.get('attacks_count', {}).get('doc_count', 0) or 0
    rate = (attacks / total * 100) if total > 0 else 0
    avg_conf = stats.get('avg_confidence', {}).get('value', 0) or 0
    total_bytes = stats.get('total_bytes', {}).get('value', 0) or 0
    
    sev_buckets = stats.get('by_severity', {}).get('buckets', [])
    severity_data = {b['key']: b['doc_count'] for b in sev_buckets}
    
    attack_buckets = stats.get('by_attack_type', {}).get('buckets', [])
    attack_types = [(b['key'], b['doc_count']) for b in attack_buckets if b['key'] != 'Benign'][:10]
    
    # Determinar nivel de riesgo
    if severity_data.get('critical', 0) > 10 or rate > 50:
        risk_level = "CRÍTICO"
        risk_color = colors.HexColor('#ef4444')
    elif severity_data.get('high', 0) > 20 or rate > 30:
        risk_level = "ALTO"
        risk_color = colors.HexColor('#f97316')
    elif rate > 10:
        risk_level = "MEDIO"
        risk_color = colors.HexColor('#eab308')
    else:
        risk_level = "BAJO"
        risk_color = colors.HexColor('#22c55e')
    
    # Construir documento
    elements = []
    
    # === PORTADA ===
    elements.append(Spacer(1, 50))
    elements.append(Paragraph("🛡️", ParagraphStyle('Icon', fontSize=60, alignment=TA_CENTER)))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("REPORTE DE SEGURIDAD", title_style))
    elements.append(Paragraph("Security Operations Center (SOC)", subtitle_style))
    elements.append(Spacer(1, 30))
    
    # Información del reporte
    report_info = [
        ["Organización:", org_name],
        ["Tipo de Reporte:", report_type],
        ["Fecha de Generación:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Período Analizado:", "Últimas 24 horas"],
        ["Elaborado por:", author],
        ["Clasificación:", "CONFIDENCIAL"]
    ]
    
    info_table = Table(report_info, colWidths=[150, 300])
    info_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#1e3a5f')),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(info_table)
    
    elements.append(Spacer(1, 40))
    
    # Nivel de riesgo
    risk_table = Table([[f"NIVEL DE RIESGO: {risk_level}"]], colWidths=[450])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 16),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('ROUNDEDCORNERS', [10, 10, 10, 10]),
    ]))
    elements.append(risk_table)
    
    elements.append(PageBreak())
    
    # === RESUMEN EJECUTIVO ===
    elements.append(Paragraph("1. RESUMEN EJECUTIVO", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3b82f6')))
    elements.append(Spacer(1, 10))
    
    exec_summary = f"""
    Durante el período analizado, el sistema NIDS ha procesado un total de <b>{total:,}</b> flujos de red, 
    detectando <b>{attacks:,}</b> eventos clasificados como ataques potenciales, lo que representa una 
    tasa de ataque del <b>{rate:.1f}%</b>. El modelo de Machine Learning ha operado con una confianza 
    promedio del <b>{avg_conf*100:.0f}%</b>.
    """
    elements.append(Paragraph(exec_summary, body_style))
    
    # KPIs principales
    elements.append(Paragraph("1.1 Indicadores Clave (KPIs)", subheading_style))
    
    kpi_data = [
        ["Métrica", "Valor", "Estado"],
        ["Total de Flujos", f"{total:,}", "✓"],
        ["Ataques Detectados", f"{attacks:,}", "⚠" if attacks > 0 else "✓"],
        ["Tasa de Ataque", f"{rate:.1f}%", "⚠" if rate > 20 else "✓"],
        ["Confianza ML", f"{avg_conf*100:.0f}%", "✓" if avg_conf > 0.7 else "⚠"],
        ["Tráfico Total", format_bytes(total_bytes), "✓"],
        ["Alertas Críticas", f"{severity_data.get('critical', 0)}", "🔴" if severity_data.get('critical', 0) > 0 else "✓"],
    ]
    
    kpi_table = Table(kpi_data, colWidths=[200, 150, 80])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 20))
    
    # === ANÁLISIS DE AMENAZAS ===
    elements.append(Paragraph("2. ANÁLISIS DE AMENAZAS", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3b82f6')))
    elements.append(Spacer(1, 10))
    
    # Distribución por severidad
    elements.append(Paragraph("2.1 Distribución por Severidad", subheading_style))
    
    sev_data = [["Severidad", "Cantidad", "Porcentaje"]]
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_data.get(sev, 0)
        pct = (count / total * 100) if total > 0 else 0
        sev_data.append([sev.upper(), f"{count:,}", f"{pct:.1f}%"])
    
    sev_table = Table(sev_data, colWidths=[150, 150, 130])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 15))
    
    # Tipos de ataque
    elements.append(Paragraph("2.2 Tipos de Ataque Detectados", subheading_style))
    
    if attack_types:
        attack_data = [["Tipo de Ataque", "Eventos", "% del Total"]]
        for attack_name, count in attack_types:
            pct = (count / total * 100) if total > 0 else 0
            attack_data.append([attack_name, f"{count:,}", f"{pct:.1f}%"])
        
        attack_table = Table(attack_data, colWidths=[200, 100, 130])
        attack_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(attack_table)
    else:
        elements.append(Paragraph("No se detectaron ataques en el período analizado.", body_style))
    
    elements.append(PageBreak())
    
    # === ANÁLISIS DE TRÁFICO ===
    elements.append(Paragraph("3. ANÁLISIS DE TRÁFICO", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3b82f6')))
    elements.append(Spacer(1, 10))
    
    # Top IPs Origen (Atacantes)
    elements.append(Paragraph("3.1 Top IPs Origen (Posibles Atacantes)", subheading_style))
    
    if ip_stats['src_ips']:
        src_data = [["IP Origen", "Conexiones", "% del Total"]]
        for ip_info in ip_stats['src_ips'][:10]:
            src_data.append([ip_info['ip'], f"{ip_info['count']:,}", f"{ip_info['pct']:.1f}%"])
        
        src_table = Table(src_data, colWidths=[200, 100, 130])
        src_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7c3aed')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f3ff')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(src_table)
    elements.append(Spacer(1, 15))
    
    # Top IPs Destino (Víctimas)
    elements.append(Paragraph("3.2 Top IPs Destino (Objetivos)", subheading_style))
    
    if ip_stats['dst_ips']:
        dst_data = [["IP Destino", "Conexiones", "% del Total"]]
        for ip_info in ip_stats['dst_ips'][:10]:
            dst_data.append([ip_info['ip'], f"{ip_info['count']:,}", f"{ip_info['pct']:.1f}%"])
        
        dst_table = Table(dst_data, colWidths=[200, 100, 130])
        dst_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0891b2')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecfeff')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(dst_table)
    elements.append(Spacer(1, 15))
    
    # Top Puertos
    elements.append(Paragraph("3.3 Puertos más Utilizados", subheading_style))
    
    if ip_stats['dst_ports']:
        port_data = [["Puerto", "Servicio", "Conexiones"]]
        for port_info in ip_stats['dst_ports'][:10]:
            port_data.append([str(port_info['port']), port_info['service'], f"{port_info['count']:,}"])
        
        port_table = Table(port_data, colWidths=[100, 180, 150])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ea580c')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff7ed')]),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(port_table)
    
    elements.append(PageBreak())
    
    # === ESTADO DEL SISTEMA ===
    elements.append(Paragraph("4. ESTADO DEL SISTEMA", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3b82f6')))
    elements.append(Spacer(1, 10))
    
    sys_data = [
        ["Componente", "Estado", "Detalles"],
        ["Elasticsearch", "✓ Online" if system_status['elasticsearch']['online'] else "✗ Offline", 
         f"Cluster: {system_status['elasticsearch']['cluster']}"],
        ["ML API", "✓ Online" if system_status['ml_api']['online'] else "✗ Offline",
         f"Modelo: RandomForest"],
        ["Logstash", "✓ Online" if system_status['logstash']['online'] else "✗ Offline",
         "Pipeline activo"],
        ["Zeek", "✓ Online" if system_status['zeek']['online'] else "✗ Offline",
         "Capturando tráfico"],
    ]
    
    sys_table = Table(sys_data, colWidths=[120, 100, 210])
    sys_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(sys_table)
    elements.append(Spacer(1, 20))
    
    # === RECOMENDACIONES ===
    if include_recommendations:
        elements.append(Paragraph("5. RECOMENDACIONES", heading_style))
        elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3b82f6')))
        elements.append(Spacer(1, 10))
        
        recommendations = []
        
        if severity_data.get('critical', 0) > 0:
            recommendations.append("🔴 <b>URGENTE:</b> Se detectaron alertas críticas. Investigar inmediatamente y considerar aislamiento de sistemas afectados.")
        
        if rate > 30:
            recommendations.append("⚠️ <b>ALTA PRIORIDAD:</b> La tasa de ataques supera el 30%. Revisar reglas de firewall y considerar bloqueo de IPs sospechosas.")
        
        for attack_name, count in attack_types[:3]:
            if 'DDoS' in attack_name:
                recommendations.append(f"🛡️ Implementar rate limiting y considerar servicios de mitigación DDoS para contrarrestar ataques tipo {attack_name}.")
            elif 'Brute' in attack_name:
                recommendations.append(f"🔐 Fortalecer políticas de contraseñas y considerar implementar 2FA debido a ataques de {attack_name}.")
            elif 'SQL' in attack_name:
                recommendations.append(f"💉 Revisar y sanitizar todas las entradas de usuario en aplicaciones web para prevenir {attack_name}.")
        
        if avg_conf < 0.7:
            recommendations.append("📊 La confianza promedio del modelo ML es baja. Considerar reentrenamiento con datos más recientes.")
        
        recommendations.append("📝 Mantener actualizados todos los sistemas y aplicar parches de seguridad pendientes.")
        recommendations.append("👥 Realizar capacitación de concientización en seguridad para el personal.")
        recommendations.append("🔄 Revisar y actualizar el plan de respuesta a incidentes.")
        
        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(f"{i}. {rec}", body_style))
            elements.append(Spacer(1, 5))
    
    elements.append(PageBreak())
    
    # === APÉNDICE: ATAQUES RECIENTES ===
    elements.append(Paragraph("APÉNDICE A: ATAQUES RECIENTES", heading_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#3b82f6')))
    elements.append(Spacer(1, 10))
    
    if not attacks_df.empty:
        recent_attacks = attacks_df.head(20)
        attack_log = [["Timestamp", "IP Origen", "IP Destino", "Tipo", "Severidad"]]
        
        for _, row in recent_attacks.iterrows():
            ts = str(row.get('@timestamp', 'N/A'))[:19]
            attack_log.append([
                ts,
                str(row.get('src_ip', 'N/A'))[:20],
                str(row.get('dst_ip', 'N/A'))[:20],
                str(row.get('attack_type', 'N/A'))[:20],
                str(row.get('severity', 'N/A'))
            ])
        
        log_table = Table(attack_log, colWidths=[90, 95, 95, 110, 60])
        log_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fef2f2')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(log_table)
    else:
        elements.append(Paragraph("No hay ataques recientes para mostrar.", body_style))
    
    elements.append(Spacer(1, 30))
    
    # === PIE DE PÁGINA ===
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1e3a5f')))
    elements.append(Spacer(1, 10))
    
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor('#64748b'),
        alignment=TA_CENTER
    )
    
    elements.append(Paragraph(
        f"Reporte generado automáticamente por NIDS SOC Dashboard v5.1 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Clasificación: CONFIDENCIAL",
        footer_style
    ))
    elements.append(Paragraph(
        f"© {datetime.now().year} {org_name} - Todos los derechos reservados",
        footer_style
    ))
    
    # Generar PDF
    doc.build(elements)
    buffer.seek(0)
    
    return buffer.getvalue()

# =============================================================================
# COMPONENTES UI
# =============================================================================

def create_kpi_card(title, value, subtitle="", icon="fa-chart-line", color=COLORS['primary']):
    return dbc.Card([
        dbc.CardBody([
            html.Div([
                html.I(className=f"fas {icon}", style={'fontSize': '1.5rem', 'color': color, 'opacity': '0.8'}),
                html.P(title, style={'color': COLORS['text_muted'], 'fontSize': '0.7rem', 'marginTop': '0.5rem', 'marginBottom': '0.25rem', 'textTransform': 'uppercase'}),
                html.H3(value, style={'color': COLORS['text'], 'fontWeight': '700', 'marginBottom': '0'}),
                html.Small(subtitle, style={'color': COLORS['text_muted'], 'fontSize': '0.7rem'}) if subtitle else None
            ], className="text-center")
        ], style={'padding': '1rem'})
    ], style={
        'backgroundColor': COLORS['bg_card'],
        'border': f'1px solid {COLORS["border"]}',
        'borderRadius': '10px',
        'borderTop': f'4px solid {color}'
    }, className="h-100")

def create_panel(title, children, icon="fa-chart-bar", footer=None):
    card_children = [
        dbc.CardHeader([
            html.I(className=f"fas {icon} me-2", style={'color': COLORS['primary']}),
            html.Span(title, style={'fontWeight': '600', 'fontSize': '0.9rem'})
        ], style={
            'backgroundColor': COLORS['bg_header'],
            'borderBottom': f'1px solid {COLORS["border"]}',
            'color': COLORS['text']
        }),
        dbc.CardBody(children, style={'padding': '1rem'})
    ]
    if footer:
        card_children.append(dbc.CardFooter(footer, style={
            'backgroundColor': COLORS['bg_header'],
            'borderTop': f'1px solid {COLORS["border"]}',
            'fontSize': '0.75rem',
            'color': COLORS['text_muted']
        }))
    
    return dbc.Card(card_children, style={
        'backgroundColor': COLORS['bg_card'],
        'border': f'1px solid {COLORS["border"]}',
        'borderRadius': '10px'
    }, className="h-100")

def create_data_table(df, columns, id_suffix, page_size=10):
    if df.empty:
        return html.Div([
            html.I(className="fas fa-inbox fa-2x mb-2", style={'color': COLORS['text_muted'], 'opacity': '0.3'}),
            html.P("Sin datos disponibles", style={'color': COLORS['text_muted']})
        ], className="text-center p-4")
    
    available_cols = [c for c in columns if c['id'] in df.columns]
    if not available_cols:
        return html.P("Columnas no disponibles", style={'color': COLORS['text_muted']})
    
    display_df = df[[c['id'] for c in available_cols]].head(200).copy()
    display_df = display_df.fillna('')
    
    return dash_table.DataTable(
        data=display_df.to_dict('records'),
        columns=available_cols,
        page_size=page_size,
        filter_action="native",
        sort_action="native",
        style_table={'overflowX': 'auto'},
        style_header={
            'backgroundColor': COLORS['bg_header'],
            'color': COLORS['text'],
            'fontWeight': '600',
            'fontSize': '0.75rem',
            'textTransform': 'uppercase',
            'border': f'1px solid {COLORS["border"]}'
        },
        style_cell={
            'backgroundColor': COLORS['bg_card'],
            'color': COLORS['text'],
            'border': f'1px solid {COLORS["border"]}',
            'textAlign': 'left',
            'padding': '8px',
            'fontSize': '0.8rem',
            'maxWidth': '180px',
            'overflow': 'hidden',
            'textOverflow': 'ellipsis'
        },
        style_data_conditional=[
            {'if': {'row_index': 'odd'}, 'backgroundColor': 'rgba(13,19,33,0.5)'},
            {'if': {'filter_query': '{severity} = "critical"'}, 'backgroundColor': 'rgba(239,68,68,0.15)'},
            {'if': {'filter_query': '{severity} = "high"'}, 'backgroundColor': 'rgba(249,115,22,0.1)'},
        ],
        style_filter={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}
    )

def create_severity_cards(severity_data, total):
    cards = []
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_data.get(sev, 0)
        pct = (count / total * 100) if total > 0 else 0
        cfg = SEVERITY_CONFIG.get(sev, SEVERITY_CONFIG['info'])
        
        cards.append(dbc.Col([
            html.Div([
                html.I(className=f"fas {cfg['icon']} fa-lg", style={'color': cfg['color']}),
                html.H4(f"{count:,}", style={'color': COLORS['text'], 'fontWeight': '700', 'marginTop': '0.5rem', 'marginBottom': '0'}),
                html.Small(cfg['label'], style={'color': cfg['color'], 'fontWeight': '600', 'fontSize': '0.7rem'}),
                html.Div([
                    html.Div(style={'width': f"{min(pct, 100)}%", 'height': '4px', 'backgroundColor': cfg['color'], 'borderRadius': '2px'})
                ], style={'width': '100%', 'height': '4px', 'backgroundColor': COLORS['border'], 'borderRadius': '2px', 'marginTop': '0.5rem'}),
                html.Small(f"{pct:.1f}%", style={'color': COLORS['text_muted'], 'fontSize': '0.65rem'})
            ], style={'backgroundColor': cfg['bg'], 'padding': '1rem', 'borderRadius': '8px', 'textAlign': 'center'})
        ], width=True))
    
    return dbc.Row(cards, className="g-2")

def base_chart_layout(height=300, show_legend=False):
    layout = {
        'paper_bgcolor': 'rgba(0,0,0,0)',
        'plot_bgcolor': 'rgba(0,0,0,0)',
        'font': {'color': COLORS['text'], 'size': 11},
        'margin': {'l': 50, 'r': 20, 't': 40, 'b': 50},
        'xaxis': {'showgrid': False, 'zeroline': False, 'color': COLORS['text_muted']},
        'yaxis': {'showgrid': True, 'gridcolor': COLORS['grid'], 'zeroline': False, 'color': COLORS['text_muted']},
        'height': height
    }
    if show_legend:
        layout['showlegend'] = True
        layout['legend'] = {'orientation': 'h', 'yanchor': 'bottom', 'y': 1.02, 'xanchor': 'right', 'x': 1, 'font': {'size': 10}}
    else:
        layout['showlegend'] = False
    return layout

def empty_chart(height=300, message="Sin datos"):
    fig = go.Figure()
    fig.add_annotation(text=message, xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font={'size': 14, 'color': COLORS['text_muted']})
    fig.update_layout(**base_chart_layout(height))
    return fig

# =============================================================================
# APLICACIÓN DASH
# =============================================================================

app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.DARKLY,
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
    ],
    title="NIDS SOC Dashboard v5.1",
    suppress_callback_exceptions=True
)

app.index_string = '''
<!DOCTYPE html>
<html>
    <head>
        {%metas%}
        <title>{%title%}</title>
        {%favicon%}
        {%css%}
        <style>
            body { background-color: #0a0e17; font-family: -apple-system, BlinkMacSystemFont, sans-serif; }
            .nav-tabs .nav-link { color: #64748b; border: none; padding: 0.75rem 1.25rem; }
            .nav-tabs .nav-link.active { color: #3b82f6; background: transparent; border-bottom: 3px solid #3b82f6; }
            .nav-tabs .nav-link:hover { color: #e2e8f0; }
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: #0d1321; }
            ::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 4px; }
        </style>
    </head>
    <body>
        {%app_entry%}
        <footer>{%config%}{%scripts%}{%renderer%}</footer>
    </body>
</html>
'''

# =============================================================================
# LAYOUT
# =============================================================================

app.layout = dbc.Container([
    # Header
    dbc.Row([
        dbc.Col([
            html.Div([
                html.I(className="fas fa-shield-virus fa-2x me-3", style={'color': COLORS['primary']}),
                html.Div([
                    html.H4("NIDS Security Operations Center", className="mb-0", style={'color': COLORS['text']}),
                    html.Small("Dashboard v5.1 - Con Reportes PDF", style={'color': COLORS['text_muted']})
                ])
            ], className="d-flex align-items-center")
        ], width=5),
        dbc.Col([
            html.Div([
                html.I(className="fas fa-circle me-1", id="status-es", style={'fontSize': '0.5rem', 'color': COLORS['warning']}),
                html.Span("ES", className="me-3", style={'fontSize': '0.75rem', 'color': COLORS['text_muted']}),
                html.I(className="fas fa-circle me-1", id="status-ml", style={'fontSize': '0.5rem', 'color': COLORS['warning']}),
                html.Span("ML", className="me-3", style={'fontSize': '0.75rem', 'color': COLORS['text_muted']}),
                html.Span(id="status-docs", style={'fontSize': '0.75rem', 'color': COLORS['text']})
            ])
        ], width=3, className="text-center"),
        dbc.Col([
            html.Div([
                dbc.Select(id="time-range", options=[
                    {"label": "1h", "value": "1"},
                    {"label": "6h", "value": "6"},
                    {"label": "24h", "value": "24"},
                    {"label": "Todo", "value": "0"},
                ], value="24", size="sm", style={'width': '100px', 'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                html.Small(id="update-time", className="ms-2", style={'color': COLORS['text_muted']})
            ], className="d-flex align-items-center justify-content-end")
        ], width=4)
    ], className="py-3 mb-3", style={'borderBottom': f'2px solid {COLORS["primary"]}'}),
    
    # Tabs
    dbc.Tabs([
        # TAB 1: RESUMEN
        dbc.Tab([
            dbc.Row([
                dbc.Col(html.Div(id="kpi-1"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-2"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-3"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-4"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-5"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-6"), lg=2, md=4, className="mb-3"),
            ], className="mt-3"),
            dbc.Row([dbc.Col([create_panel("Distribución por Severidad", html.Div(id="severity-panel"), "fa-exclamation-triangle")], width=12)], className="mb-4"),
            dbc.Row([
                dbc.Col([create_panel("Timeline de Eventos", dcc.Graph(id="chart-timeline", config={'displayModeBar': False}), "fa-chart-area")], lg=8, className="mb-4"),
                dbc.Col([create_panel("Tipos de Ataque", dcc.Graph(id="chart-attacks", config={'displayModeBar': False}), "fa-virus")], lg=4, className="mb-4"),
            ]),
            dbc.Row([
                dbc.Col([create_panel("Distribución por Protocolo", dcc.Graph(id="chart-protocols", config={'displayModeBar': False}), "fa-network-wired")], lg=4, className="mb-4"),
                dbc.Col([create_panel("Top 10 Puertos", dcc.Graph(id="chart-ports", config={'displayModeBar': False}), "fa-door-open")], lg=4, className="mb-4"),
                dbc.Col([create_panel("Servicios", dcc.Graph(id="chart-services", config={'displayModeBar': False}), "fa-server")], lg=4, className="mb-4"),
            ]),
        ], label="📊 Resumen", tab_id="tab-1"),
        
        # TAB 2: TRÁFICO
        dbc.Tab([
            dbc.Row([
                dbc.Col(html.Div(id="kpi-src"), lg=3, md=6, className="mb-3"),
                dbc.Col(html.Div(id="kpi-dst"), lg=3, md=6, className="mb-3"),
                dbc.Col(html.Div(id="kpi-ports"), lg=3, md=6, className="mb-3"),
                dbc.Col(html.Div(id="kpi-conn"), lg=3, md=6, className="mb-3"),
            ], className="mt-3"),
            dbc.Row([
                dbc.Col([create_panel("Top IPs Origen", html.Div(id="table-src-ips"), "fa-crosshairs")], lg=6, className="mb-4"),
                dbc.Col([create_panel("Top IPs Destino", html.Div(id="table-dst-ips"), "fa-bullseye")], lg=6, className="mb-4"),
            ]),
            dbc.Row([
                dbc.Col([create_panel("Puertos", dcc.Graph(id="chart-traffic-ports", config={'displayModeBar': False}), "fa-chart-bar")], lg=6, className="mb-4"),
                dbc.Col([create_panel("Protocolos", dcc.Graph(id="chart-traffic-proto", config={'displayModeBar': False}), "fa-pie-chart")], lg=6, className="mb-4"),
            ]),
            dbc.Row([dbc.Col([create_panel("Conexiones", [
                dbc.Button([html.I(className="fas fa-download me-2"), "CSV"], id="btn-export", color="success", size="sm", className="mb-3"),
                dcc.Download(id="download-csv"),
                html.Div(id="table-connections")
            ], "fa-list")], width=12)]),
        ], label="🌐 Tráfico", tab_id="tab-2"),
        
        # TAB 3: FORENSE
        dbc.Tab([
            dbc.Row([
                dbc.Col(html.Div(id="kpi-f1"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-f2"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-f3"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-f4"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-f5"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-f6"), lg=2, md=4, className="mb-3"),
            ], className="mt-3"),
            dbc.Row([
                dbc.Col([create_panel("Alertas Críticas", html.Div(id="critical-alerts"), "fa-radiation")], lg=4, className="mb-4"),
                dbc.Col([create_panel("Categorías", dcc.Graph(id="chart-categories", config={'displayModeBar': False}), "fa-layer-group")], lg=4, className="mb-4"),
                dbc.Col([create_panel("Severidad", dcc.Graph(id="chart-severity-pie", config={'displayModeBar': False}), "fa-exclamation-circle")], lg=4, className="mb-4"),
            ]),
            dbc.Row([
                dbc.Col([create_panel("Timeline Ataques", dcc.Graph(id="chart-attacks-timeline", config={'displayModeBar': False}), "fa-chart-line")], lg=6, className="mb-4"),
                dbc.Col([create_panel("Por Hora", dcc.Graph(id="chart-heatmap-hour", config={'displayModeBar': False}), "fa-clock")], lg=6, className="mb-4"),
            ]),
            dbc.Row([
                dbc.Col([create_panel("Top Atacantes", html.Div(id="table-top-attackers"), "fa-user-secret")], lg=6, className="mb-4"),
                dbc.Col([create_panel("Top Víctimas", html.Div(id="table-top-victims"), "fa-crosshairs")], lg=6, className="mb-4"),
            ]),
            dbc.Row([dbc.Col([create_panel("Ataques", [
                dbc.Button([html.I(className="fas fa-download me-2"), "CSV"], id="btn-export-attacks", color="danger", size="sm", className="mb-3"),
                dcc.Download(id="download-attacks"),
                html.Div(id="table-attacks")
            ], "fa-skull")], width=12)]),
        ], label="🔬 Forense", tab_id="tab-3"),
        
        # TAB 4: ML
        dbc.Tab([
            dbc.Row([
                dbc.Col(html.Div(id="kpi-ml1"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-ml2"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-ml3"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-ml4"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-ml5"), lg=2, md=4, className="mb-3"),
                dbc.Col(html.Div(id="kpi-ml6"), lg=2, md=4, className="mb-3"),
            ], className="mt-3"),
            dbc.Row([
                dbc.Col([create_panel("Estado ML", html.Div(id="ml-status"), "fa-microchip")], lg=4, className="mb-4"),
                dbc.Col([create_panel("Confianza", dcc.Graph(id="chart-confidence", config={'displayModeBar': False}), "fa-percentage")], lg=4, className="mb-4"),
                dbc.Col([create_panel("Clases", dcc.Graph(id="chart-attack-classes", config={'displayModeBar': False}), "fa-tags")], lg=4, className="mb-4"),
            ]),
            dbc.Row([
                dbc.Col([create_panel("Timeline ML", dcc.Graph(id="chart-ml-timeline", config={'displayModeBar': False}), "fa-wave-square")], lg=6, className="mb-4"),
                dbc.Col([create_panel("Comparación", dcc.Graph(id="chart-comparison", config={'displayModeBar': False}), "fa-balance-scale")], lg=6, className="mb-4"),
            ]),
            dbc.Row([dbc.Col([create_panel("Predicciones", html.Div(id="table-ml"), "fa-table")], width=12)]),
        ], label="🤖 ML", tab_id="tab-4"),
        
        # TAB 5: GEMINI
        dbc.Tab([
            dbc.Row([dbc.Col([create_panel("Asistente Gemini AI", [
                dbc.Row([
                    dbc.Col([
                        dbc.Label("Tipo de Análisis", style={'color': COLORS['text'], 'fontSize': '0.85rem'}),
                        dbc.Select(id="gemini-type", options=[
                            {"label": "📊 Resumen Ejecutivo", "value": "executive"},
                            {"label": "🔍 Análisis General", "value": "general"},
                            {"label": "🎯 Amenazas", "value": "threats"},
                            {"label": "🛡️ Mitigación", "value": "mitigation"},
                            {"label": "🔥 Reglas Firewall", "value": "firewall"},
                            {"label": "🔬 Forense por UID", "value": "forensic"},
                        ], value="general", className="mb-3", style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                    ], md=6),
                    dbc.Col([
                        dbc.Label("UID (opcional)", style={'color': COLORS['text'], 'fontSize': '0.85rem'}),
                        dbc.Input(id="gemini-uid", placeholder="Ej: CT5JkU...", className="mb-3", style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                    ], md=6),
                ]),
                dbc.Textarea(id="gemini-context", placeholder="Contexto adicional...", className="mb-3", style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text'], 'minHeight': '60px'}),
                dbc.Button([html.I(className="fas fa-robot me-2"), "Analizar"], id="btn-gemini", color="primary", className="w-100 mb-3"),
                dcc.Loading(html.Div(id="gemini-output", style={'backgroundColor': COLORS['bg_header'], 'padding': '1rem', 'borderRadius': '8px', 'minHeight': '300px', 'color': COLORS['text'], 'fontSize': '0.85rem', 'overflowY': 'auto', 'maxHeight': '500px'}))
            ], "fa-brain")], width=12, className="mt-3")]),
        ], label="🧠 Gemini", tab_id="tab-5"),
        
        # TAB 6: REPORTES PDF
        dbc.Tab([
            dbc.Row([
                dbc.Col([create_panel("📄 Generador de Reportes SOC", [
                    html.P("Genera reportes profesionales en PDF con toda la información del sistema NIDS.", style={'color': COLORS['text_muted'], 'marginBottom': '1.5rem'}),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Tipo de Reporte", style={'color': COLORS['text'], 'fontWeight': '600'}),
                            dbc.Select(id="report-type", options=[
                                {"label": "📊 Reporte Ejecutivo Completo", "value": "Reporte Ejecutivo Completo"},
                                {"label": "🔬 Reporte de Incidentes", "value": "Reporte de Incidentes"},
                                {"label": "📈 Reporte de Análisis de Tráfico", "value": "Reporte de Análisis de Tráfico"},
                                {"label": "🤖 Reporte de Machine Learning", "value": "Reporte de Machine Learning"},
                                {"label": "⚡ Reporte Rápido (Resumen)", "value": "Reporte Rápido"},
                            ], value="Reporte Ejecutivo Completo", className="mb-3", style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                        ], md=6),
                        dbc.Col([
                            dbc.Label("Organización", style={'color': COLORS['text'], 'fontWeight': '600'}),
                            dbc.Input(id="report-org", value="Mi Organización", className="mb-3", style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                        ], md=6),
                    ]),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Autor del Reporte", style={'color': COLORS['text'], 'fontWeight': '600'}),
                            dbc.Input(id="report-author", value="Analista SOC", className="mb-3", style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                        ], md=6),
                        dbc.Col([
                            dbc.Label("Opciones", style={'color': COLORS['text'], 'fontWeight': '600'}),
                            dbc.Checklist(
                                id="report-options",
                                options=[
                                    {"label": " Incluir recomendaciones", "value": "recommendations"},
                                ],
                                value=["recommendations"],
                                className="mb-3",
                                style={'color': COLORS['text']}
                            ),
                        ], md=6),
                    ]),
                    
                    html.Hr(style={'borderColor': COLORS['border']}),
                    
                    dbc.Button([
                        html.I(className="fas fa-file-pdf me-2"),
                        "Generar Reporte PDF"
                    ], id="btn-generate-report", color="danger", size="lg", className="w-100 mb-3"),
                    
                    dcc.Download(id="download-report"),
                    
                    html.Div(id="report-status", className="text-center mt-3"),
                    
                ], "fa-file-pdf")], lg=6, className="mt-3"),
                
                dbc.Col([create_panel("📋 Vista Previa del Contenido", [
                    html.Div(id="report-preview", style={'color': COLORS['text'], 'fontSize': '0.85rem'})
                ], "fa-eye")], lg=6, className="mt-3"),
            ]),
            
            dbc.Row([
                dbc.Col([create_panel("📊 Estadísticas Actuales (Se incluirán en el reporte)", [
                    html.Div(id="report-stats-preview")
                ], "fa-chart-bar")], width=12, className="mt-3"),
            ]),
        ], label="📄 Reportes", tab_id="tab-6"),
        
        # TAB 7: GESTIÓN DE DATOS
        dbc.Tab([
            dbc.Row([
                dbc.Col([create_panel("💾 Gestión de Índices Elasticsearch", [
                    html.P("Administra los índices del sistema NIDS. Descarga backups y elimina datos antiguos para optimizar el rendimiento.", 
                           style={'color': COLORS['text_muted'], 'marginBottom': '1rem'}),
                    
                    dbc.Button([html.I(className="fas fa-sync me-2"), "Actualizar Lista"], id="btn-refresh-indices", color="primary", size="sm", className="mb-3"),
                    
                    html.Div(id="indices-table"),
                    
                ], "fa-database")], lg=7, className="mt-3"),
                
                dbc.Col([
                    create_panel("📊 Resumen de Almacenamiento", [
                        html.Div(id="storage-summary")
                    ], "fa-hdd"),
                    html.Div(style={'height': '1rem'}),
                    create_panel("⚡ Acciones Rápidas", [
                        dbc.Button([html.I(className="fas fa-download me-2"), "Backup Todo"], id="btn-backup-all", color="success", className="w-100 mb-2"),
                        dbc.Button([html.I(className="fas fa-broom me-2"), "Limpiar Antiguos (>7 días)"], id="btn-clean-old", color="warning", className="w-100 mb-2"),
                        html.Hr(style={'borderColor': COLORS['border']}),
                        html.Small("⚠️ Las eliminaciones son permanentes", style={'color': COLORS['danger']})
                    ], "fa-bolt"),
                ], lg=5, className="mt-3"),
            ]),
            
            dbc.Row([
                dbc.Col([create_panel("🔧 Operaciones por Índice", [
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Seleccionar Índice", style={'color': COLORS['text'], 'fontWeight': '600'}),
                            dbc.Select(id="select-index", options=[], className="mb-3", 
                                       style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                        ], md=6),
                        dbc.Col([
                            dbc.Label("Formato de Backup", style={'color': COLORS['text'], 'fontWeight': '600'}),
                            dbc.Select(id="backup-format", options=[
                                {"label": "JSON (Completo)", "value": "json"},
                                {"label": "CSV (Tabular)", "value": "csv"},
                                {"label": "NDJSON (Líneas)", "value": "ndjson"},
                            ], value="json", className="mb-3",
                                       style={'backgroundColor': COLORS['bg_input'], 'color': COLORS['text']}),
                        ], md=6),
                    ]),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Button([html.I(className="fas fa-download me-2"), "Descargar Backup"], 
                                      id="btn-download-index", color="success", className="w-100"),
                        ], md=4),
                        dbc.Col([
                            dbc.Button([html.I(className="fas fa-eye me-2"), "Ver Muestra (100 docs)"], 
                                      id="btn-preview-index", color="info", className="w-100"),
                        ], md=4),
                        dbc.Col([
                            dbc.Button([html.I(className="fas fa-trash-alt me-2"), "Eliminar Índice"], 
                                      id="btn-delete-index", color="danger", className="w-100"),
                        ], md=4),
                    ]),
                    
                    dcc.Download(id="download-backup"),
                    dcc.Download(id="download-backup-all"),
                    
                    html.Div(id="index-operation-status", className="mt-3"),
                    
                ], "fa-cog")], lg=6, className="mt-3"),
                
                dbc.Col([create_panel("👁️ Vista Previa de Datos", [
                    html.Div(id="index-preview", style={'maxHeight': '400px', 'overflowY': 'auto'})
                ], "fa-table")], lg=6, className="mt-3"),
            ]),
            
            # Modal de confirmación para eliminar
            dbc.Modal([
                dbc.ModalHeader(dbc.ModalTitle("⚠️ Confirmar Eliminación"), close_button=True),
                dbc.ModalBody([
                    html.P(id="delete-confirm-text", style={'color': COLORS['text']}),
                    html.P("Esta acción es IRREVERSIBLE. Los datos serán eliminados permanentemente.", 
                           style={'color': COLORS['danger'], 'fontWeight': '600'})
                ]),
                dbc.ModalFooter([
                    dbc.Button("Cancelar", id="btn-cancel-delete", color="secondary", className="me-2"),
                    dbc.Button("Eliminar Permanentemente", id="btn-confirm-delete", color="danger"),
                ]),
            ], id="modal-delete", is_open=False),
            
        ], label="💾 Backups", tab_id="tab-7"),
        
        # TAB 8: MONITOR
        dbc.Tab([
            dbc.Row([
                dbc.Col([create_panel("Arquitectura", html.Div(id="sys-arch"), "fa-project-diagram")], lg=8, className="mb-4"),
                dbc.Col([create_panel("Servicios", html.Div(id="sys-status"), "fa-server")], lg=4, className="mb-4"),
            ], className="mt-3"),
            dbc.Row([
                dbc.Col([create_panel("Índices", html.Div(id="es-indices"), "fa-database")], lg=6, className="mb-4"),
                dbc.Col([create_panel("ML Info", html.Div(id="ml-info"), "fa-cogs")], lg=6, className="mb-4"),
            ]),
        ], label="⚙️ Monitor", tab_id="tab-8"),
        
    ], id="tabs", active_tab="tab-1"),
    
    dcc.Interval(id='interval', interval=REFRESH_INTERVAL * 1000, n_intervals=0),
], fluid=True, style={'backgroundColor': COLORS['bg_dark'], 'minHeight': '100vh'})

# =============================================================================
# CALLBACKS
# =============================================================================

# Status bar
@app.callback(
    [Output("status-es", "style"), Output("status-ml", "style"), Output("status-docs", "children"), Output("update-time", "children")],
    [Input("interval", "n_intervals")]
)
def update_status(n):
    status = check_system_status()
    es_color = COLORS['success'] if status['elasticsearch']['online'] else COLORS['danger']
    ml_color = COLORS['success'] if status['ml_api']['online'] else COLORS['danger']
    return (
        {'fontSize': '0.5rem', 'color': es_color},
        {'fontSize': '0.5rem', 'color': ml_color},
        f"{status['elasticsearch']['docs']:,} docs",
        datetime.now().strftime("%H:%M:%S")
    )

# TAB 1: RESUMEN
@app.callback(
    [Output("kpi-1", "children"), Output("kpi-2", "children"), Output("kpi-3", "children"),
     Output("kpi-4", "children"), Output("kpi-5", "children"), Output("kpi-6", "children"),
     Output("severity-panel", "children"),
     Output("chart-timeline", "figure"), Output("chart-attacks", "figure"),
     Output("chart-protocols", "figure"), Output("chart-ports", "figure"), Output("chart-services", "figure")],
    [Input("interval", "n_intervals")]
)
def update_summary(n):
    stats = get_aggregated_stats()
    df = get_all_data_with_ips(1500)
    ip_stats = get_ip_statistics_from_df(df)
    
    total = stats.get('total_docs', {}).get('value', 0) or 0
    attacks = stats.get('attacks_count', {}).get('doc_count', 0) or 0
    rate = (attacks / total * 100) if total > 0 else 0
    avg_conf = stats.get('avg_confidence', {}).get('value', 0) or 0
    total_bytes = stats.get('total_bytes', {}).get('value', 0) or 0
    
    sev_buckets = stats.get('by_severity', {}).get('buckets', [])
    severity_data = {b['key']: b['doc_count'] for b in sev_buckets}
    critical = severity_data.get('critical', 0) + severity_data.get('high', 0)
    
    kpis = [
        create_kpi_card("Total Flujos", f"{total:,}", "Conexiones", "fa-stream", COLORS['primary']),
        create_kpi_card("Ataques", f"{attacks:,}", "Detectados", "fa-bug", COLORS['danger']),
        create_kpi_card("Tasa Ataque", f"{rate:.1f}%", "Del total", "fa-percent", COLORS['warning']),
        create_kpi_card("Críticos", f"{critical:,}", "Alta prioridad", "fa-radiation", COLORS['danger']),
        create_kpi_card("Confianza ML", f"{avg_conf*100:.0f}%", "Promedio", "fa-brain", COLORS['success']),
        create_kpi_card("Tráfico", format_bytes(total_bytes), "Total", "fa-exchange-alt", COLORS['info']),
    ]
    
    severity_cards = create_severity_cards(severity_data, total)
    
    timeline_buckets = stats.get('timeline', {}).get('buckets', [])
    if timeline_buckets:
        tl_df = pd.DataFrame([{'time': b['key_as_string'], 'total': b['doc_count'], 'attacks': b.get('attacks', {}).get('doc_count', 0)} for b in timeline_buckets])
        fig_tl = go.Figure()
        fig_tl.add_trace(go.Scatter(x=tl_df['time'], y=tl_df['total'], name='Total', fill='tozeroy', line=dict(color=COLORS['primary'])))
        fig_tl.add_trace(go.Scatter(x=tl_df['time'], y=tl_df['attacks'], name='Ataques', fill='tozeroy', line=dict(color=COLORS['danger'])))
        fig_tl.update_layout(**base_chart_layout(300, show_legend=True))
    else:
        fig_tl = empty_chart(300)
    
    attack_buckets = stats.get('by_attack_type', {}).get('buckets', [])
    if attack_buckets:
        attacks_only = [b for b in attack_buckets if b['key'] != 'Benign'][:10]
        if attacks_only:
            fig_attacks = go.Figure(go.Bar(y=[b['key'] for b in attacks_only], x=[b['doc_count'] for b in attacks_only], orientation='h', marker_color=COLORS['danger']))
            fig_attacks.update_layout(**base_chart_layout(300))
        else:
            fig_attacks = empty_chart(300, "Sin ataques")
    else:
        fig_attacks = empty_chart(300)
    
    if ip_stats['protocols']:
        fig_proto = go.Figure(go.Pie(labels=[p['proto'] for p in ip_stats['protocols']], values=[p['count'] for p in ip_stats['protocols']], hole=0.5, marker_colors=COLORS['chart_colors']))
        fig_proto.update_layout(**base_chart_layout(280))
    else:
        fig_proto = empty_chart(280)
    
    if ip_stats['dst_ports']:
        ports = ip_stats['dst_ports'][:10]
        fig_ports = go.Figure(go.Bar(x=[f":{p['port']}" for p in ports], y=[p['count'] for p in ports], marker_color=COLORS['warning']))
        fig_ports.update_layout(**base_chart_layout(280))
    else:
        fig_ports = empty_chart(280)
    
    if ip_stats['services']:
        fig_svc = go.Figure(go.Pie(labels=[s['service'] for s in ip_stats['services'][:8]], values=[s['count'] for s in ip_stats['services'][:8]], hole=0.4, marker_colors=COLORS['chart_colors']))
        fig_svc.update_layout(**base_chart_layout(280))
    else:
        fig_svc = empty_chart(280)
    
    return (*kpis, severity_cards, fig_tl, fig_attacks, fig_proto, fig_ports, fig_svc)

# TAB 2: TRÁFICO
@app.callback(
    [Output("kpi-src", "children"), Output("kpi-dst", "children"), Output("kpi-ports", "children"), Output("kpi-conn", "children"),
     Output("table-src-ips", "children"), Output("table-dst-ips", "children"),
     Output("chart-traffic-ports", "figure"), Output("chart-traffic-proto", "figure"),
     Output("table-connections", "children")],
    [Input("interval", "n_intervals")]
)
def update_traffic(n):
    df = get_all_data_with_ips(2000)
    ip_stats = get_ip_statistics_from_df(df)
    
    kpis = [
        create_kpi_card("IPs Origen", f"{len(ip_stats['src_ips'])}", "Fuentes", "fa-upload", COLORS['primary']),
        create_kpi_card("IPs Destino", f"{len(ip_stats['dst_ips'])}", "Destinos", "fa-download", COLORS['info']),
        create_kpi_card("Puertos", f"{len(ip_stats['dst_ports'])}", "Únicos", "fa-door-open", COLORS['warning']),
        create_kpi_card("Conexiones", f"{len(df):,}", "Total", "fa-exchange-alt", COLORS['success']),
    ]
    
    if ip_stats['src_ips']:
        src_df = pd.DataFrame(ip_stats['src_ips'])
        src_df['pct'] = src_df['pct'].apply(lambda x: f"{x:.1f}%")
        src_table = create_data_table(src_df, [{'name': 'IP', 'id': 'ip'}, {'name': 'Conex', 'id': 'count'}, {'name': '%', 'id': 'pct'}], 'src', 10)
    else:
        src_table = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    if ip_stats['dst_ips']:
        dst_df = pd.DataFrame(ip_stats['dst_ips'])
        dst_df['pct'] = dst_df['pct'].apply(lambda x: f"{x:.1f}%")
        dst_table = create_data_table(dst_df, [{'name': 'IP', 'id': 'ip'}, {'name': 'Conex', 'id': 'count'}, {'name': '%', 'id': 'pct'}], 'dst', 10)
    else:
        dst_table = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    if ip_stats['dst_ports']:
        fig_ports = go.Figure(go.Bar(y=[f":{p['port']}" for p in ip_stats['dst_ports'][:15]], x=[p['count'] for p in ip_stats['dst_ports'][:15]], orientation='h', marker_color=COLORS['warning']))
        fig_ports.update_layout(**base_chart_layout(400))
    else:
        fig_ports = empty_chart(400)
    
    if ip_stats['protocols']:
        fig_proto = go.Figure(go.Pie(labels=[p['proto'] for p in ip_stats['protocols']], values=[p['count'] for p in ip_stats['protocols']], hole=0.5, marker_colors=COLORS['chart_colors']))
        fig_proto.update_layout(**base_chart_layout(400))
    else:
        fig_proto = empty_chart(400)
    
    if not df.empty:
        conn_table = create_data_table(df, [
            {'name': 'UID', 'id': 'uid'}, {'name': 'Origen', 'id': 'src_ip'}, {'name': 'Destino', 'id': 'dst_ip'},
            {'name': 'Puerto', 'id': 'dst_port'}, {'name': 'Tipo', 'id': 'attack_type'}, {'name': 'Sev', 'id': 'severity'}
        ], 'conn', 10)
    else:
        conn_table = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    return (*kpis, src_table, dst_table, fig_ports, fig_proto, conn_table)

@app.callback(Output("download-csv", "data"), [Input("btn-export", "n_clicks")], prevent_initial_call=True)
def export_traffic(n):
    df = get_all_data_with_ips(10000)
    if df.empty:
        return None
    return dcc.send_data_frame(df.to_csv, f"nids_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", index=False)

# TAB 3: FORENSE
@app.callback(
    [Output("kpi-f1", "children"), Output("kpi-f2", "children"), Output("kpi-f3", "children"),
     Output("kpi-f4", "children"), Output("kpi-f5", "children"), Output("kpi-f6", "children"),
     Output("critical-alerts", "children"),
     Output("chart-categories", "figure"), Output("chart-severity-pie", "figure"),
     Output("chart-attacks-timeline", "figure"), Output("chart-heatmap-hour", "figure"),
     Output("table-top-attackers", "children"), Output("table-top-victims", "children"),
     Output("table-attacks", "children")],
    [Input("interval", "n_intervals")]
)
def update_forensic(n):
    attacks_df = get_attacks_with_ips(1000)
    stats = get_aggregated_stats()
    
    total = stats.get('total_docs', {}).get('value', 0) or 0
    attacks = stats.get('attacks_count', {}).get('doc_count', 0) or 0
    total_bytes = stats.get('total_bytes', {}).get('value', 0) or 0
    
    sev_buckets = stats.get('by_severity', {}).get('buckets', [])
    severity_data = {b['key']: b['doc_count'] for b in sev_buckets}
    
    unique_attackers = attacks_df['src_ip'].nunique() if not attacks_df.empty and 'src_ip' in attacks_df.columns else 0
    unique_victims = attacks_df['dst_ip'].nunique() if not attacks_df.empty and 'dst_ip' in attacks_df.columns else 0
    
    kpis = [
        create_kpi_card("Eventos", f"{total:,}", "Total", "fa-list", COLORS['primary']),
        create_kpi_card("Ataques", f"{attacks:,}", "Detectados", "fa-skull", COLORS['danger']),
        create_kpi_card("Críticos", f"{severity_data.get('critical', 0):,}", "Máx prior", "fa-radiation", COLORS['danger']),
        create_kpi_card("Bytes", format_bytes(total_bytes), "Transfer", "fa-database", COLORS['warning']),
        create_kpi_card("Atacantes", f"{unique_attackers}", "IPs", "fa-user-secret", COLORS['purple']),
        create_kpi_card("Víctimas", f"{unique_victims}", "IPs", "fa-crosshairs", COLORS['info']),
    ]
    
    if not attacks_df.empty and 'severity' in attacks_df.columns:
        critical = attacks_df[attacks_df['severity'].isin(['critical', 'high'])].head(6)
        if not critical.empty:
            alerts = []
            for _, row in critical.iterrows():
                cfg = SEVERITY_CONFIG.get(row.get('severity', 'high'), SEVERITY_CONFIG['high'])
                alerts.append(html.Div([
                    html.I(className=f"fas {cfg['icon']} me-2", style={'color': cfg['color']}),
                    html.Span(str(row.get('attack_type', 'N/A'))[:25], style={'color': cfg['color'], 'fontWeight': '600', 'fontSize': '0.8rem'}),
                    html.Br(),
                    html.Small(f"{row.get('src_ip', 'N/A')} → {row.get('dst_ip', 'N/A')}", style={'color': COLORS['text_muted'], 'fontSize': '0.7rem'})
                ], style={'padding': '0.4rem', 'marginBottom': '0.3rem', 'backgroundColor': cfg['bg'], 'borderRadius': '4px', 'borderLeft': f'3px solid {cfg["color"]}'}))
            critical_content = html.Div(alerts)
        else:
            critical_content = html.Div([html.I(className="fas fa-check-circle fa-2x", style={'color': COLORS['success']}), html.P("Sin alertas", style={'color': COLORS['success']})], className="text-center p-3")
    else:
        critical_content = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    attack_buckets = stats.get('by_attack_type', {}).get('buckets', [])
    if attack_buckets:
        attacks_only = [b for b in attack_buckets if b['key'] != 'Benign'][:8]
        if attacks_only:
            fig_cat = go.Figure(go.Bar(x=[b['key'][:12] for b in attacks_only], y=[b['doc_count'] for b in attacks_only], marker_color=COLORS['chart_colors'][:8]))
            fig_cat.update_layout(**base_chart_layout(250))
        else:
            fig_cat = empty_chart(250)
    else:
        fig_cat = empty_chart(250)
    
    if severity_data:
        fig_sev = go.Figure(go.Pie(labels=list(severity_data.keys()), values=list(severity_data.values()), hole=0.5, marker_colors=[SEVERITY_CONFIG.get(s, SEVERITY_CONFIG['info'])['color'] for s in severity_data.keys()]))
        fig_sev.update_layout(**base_chart_layout(250))
    else:
        fig_sev = empty_chart(250)
    
    timeline_buckets = stats.get('timeline', {}).get('buckets', [])
    if timeline_buckets:
        tl_df = pd.DataFrame([{'time': b['key_as_string'], 'attacks': b.get('attacks', {}).get('doc_count', 0)} for b in timeline_buckets])
        fig_tl = go.Figure(go.Scatter(x=tl_df['time'], y=tl_df['attacks'], fill='tozeroy', line=dict(color=COLORS['danger'])))
        fig_tl.update_layout(**base_chart_layout(250))
    else:
        fig_tl = empty_chart(250)
    
    hour_buckets = stats.get('by_hour', {}).get('buckets', [])
    if hour_buckets:
        hour_counts = {b['key']: b['doc_count'] for b in hour_buckets}
        values = [hour_counts.get(h, 0) for h in range(24)]
        fig_heat = go.Figure(go.Bar(x=[f"{h}h" for h in range(24)], y=values, marker_color=COLORS['warning']))
        fig_heat.update_layout(**base_chart_layout(250))
    else:
        fig_heat = empty_chart(250)
    
    if not attacks_df.empty and 'src_ip' in attacks_df.columns:
        attackers = attacks_df['src_ip'].value_counts().head(8).reset_index()
        attackers.columns = ['ip', 'count']
        attackers_table = create_data_table(attackers, [{'name': 'IP', 'id': 'ip'}, {'name': 'Ataques', 'id': 'count'}], 'att', 6)
    else:
        attackers_table = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    if not attacks_df.empty and 'dst_ip' in attacks_df.columns:
        victims = attacks_df['dst_ip'].value_counts().head(8).reset_index()
        victims.columns = ['ip', 'count']
        victims_table = create_data_table(victims, [{'name': 'IP', 'id': 'ip'}, {'name': 'Ataques', 'id': 'count'}], 'vic', 6)
    else:
        victims_table = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    if not attacks_df.empty:
        table = create_data_table(attacks_df, [
            {'name': 'UID', 'id': 'uid'}, {'name': 'Origen', 'id': 'src_ip'}, {'name': 'Destino', 'id': 'dst_ip'},
            {'name': 'Puerto', 'id': 'dst_port'}, {'name': 'Tipo', 'id': 'attack_type'}, {'name': 'Sev', 'id': 'severity'}
        ], 'atk', 10)
    else:
        table = html.P("Sin ataques", style={'color': COLORS['text_muted']})
    
    return (*kpis, critical_content, fig_cat, fig_sev, fig_tl, fig_heat, attackers_table, victims_table, table)

@app.callback(Output("download-attacks", "data"), [Input("btn-export-attacks", "n_clicks")], prevent_initial_call=True)
def export_attacks(n):
    df = get_attacks_with_ips(10000)
    if df.empty:
        return None
    return dcc.send_data_frame(df.to_csv, f"nids_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", index=False)

# TAB 4: ML
@app.callback(
    [Output("kpi-ml1", "children"), Output("kpi-ml2", "children"), Output("kpi-ml3", "children"),
     Output("kpi-ml4", "children"), Output("kpi-ml5", "children"), Output("kpi-ml6", "children"),
     Output("ml-status", "children"),
     Output("chart-confidence", "figure"), Output("chart-attack-classes", "figure"),
     Output("chart-ml-timeline", "figure"), Output("chart-comparison", "figure"),
     Output("table-ml", "children")],
    [Input("interval", "n_intervals")]
)
def update_ml(n):
    ml = get_ml_status()
    stats = get_aggregated_stats()
    df = get_all_data_with_ips(1000)
    
    total = stats.get('total_docs', {}).get('value', 0) or 0
    attacks = stats.get('attacks_count', {}).get('doc_count', 0) or 0
    avg_conf = stats.get('avg_confidence', {}).get('value', 0) or 0
    
    high_conf = len(df[df['ml_confidence'] >= 0.7]) if not df.empty and 'ml_confidence' in df.columns else 0
    low_conf = len(df[df['ml_confidence'] < 0.3]) if not df.empty and 'ml_confidence' in df.columns else 0
    
    kpis = [
        create_kpi_card("Predicciones", f"{total:,}", "Total", "fa-brain", COLORS['primary']),
        create_kpi_card("Ataques", f"{attacks:,}", "Detectados", "fa-skull", COLORS['danger']),
        create_kpi_card("Confianza", f"{avg_conf*100:.0f}%", "Promedio", "fa-percentage", COLORS['success']),
        create_kpi_card("Alta Conf", f"{high_conf:,}", "≥70%", "fa-check-double", COLORS['success']),
        create_kpi_card("Baja Conf", f"{low_conf:,}", "<30%", "fa-question", COLORS['warning']),
        create_kpi_card("Clases", "15", "Tipos", "fa-tags", COLORS['info']),
    ]
    
    if ml and ml.get('models_loaded'):
        status = html.Div([
            html.I(className="fas fa-check-circle fa-3x mb-2", style={'color': COLORS['success']}),
            html.H5("Activo", style={'color': COLORS['success']}),
            html.P(f"Predicciones: {ml.get('predictions_count', 0):,}", style={'color': COLORS['text'], 'fontSize': '0.85rem'}),
        ], className="text-center")
    else:
        status = html.Div([html.I(className="fas fa-times-circle fa-3x", style={'color': COLORS['danger']}), html.H5("Inactivo", style={'color': COLORS['danger']})], className="text-center")
    
    if not df.empty and 'ml_confidence' in df.columns:
        fig_conf = go.Figure(go.Histogram(x=df['ml_confidence'].dropna()*100, nbinsx=20, marker_color=COLORS['success']))
        fig_conf.update_layout(**base_chart_layout(220))
    else:
        fig_conf = empty_chart(220)
    
    attack_buckets = stats.get('by_attack_type', {}).get('buckets', [])
    if attack_buckets:
        attacks_only = [b for b in attack_buckets if b['key'] != 'Benign'][:8]
        if attacks_only:
            fig_classes = go.Figure(go.Pie(labels=[b['key'] for b in attacks_only], values=[b['doc_count'] for b in attacks_only], hole=0.4, marker_colors=COLORS['chart_colors']))
            fig_classes.update_layout(**base_chart_layout(220))
        else:
            fig_classes = empty_chart(220)
    else:
        fig_classes = empty_chart(220)
    
    timeline_buckets = stats.get('timeline', {}).get('buckets', [])
    if timeline_buckets:
        tl_df = pd.DataFrame([{'time': b['key_as_string'], 'total': b['doc_count'], 'attacks': b.get('attacks', {}).get('doc_count', 0)} for b in timeline_buckets])
        fig_tl = go.Figure()
        fig_tl.add_trace(go.Bar(x=tl_df['time'], y=tl_df['total']-tl_df['attacks'], name='Normal', marker_color=COLORS['success']))
        fig_tl.add_trace(go.Bar(x=tl_df['time'], y=tl_df['attacks'], name='Ataque', marker_color=COLORS['danger']))
        fig_tl.update_layout(**base_chart_layout(250, True), barmode='stack')
    else:
        fig_tl = empty_chart(250)
    
    if not df.empty and 'is_attack' in df.columns and 'ml_confidence' in df.columns:
        fig_comp = go.Figure()
        normal = df[df['is_attack']==False]['ml_confidence'].dropna()*100
        attack = df[df['is_attack']==True]['ml_confidence'].dropna()*100
        if len(normal)>0: fig_comp.add_trace(go.Box(y=normal, name='Normal', marker_color=COLORS['success']))
        if len(attack)>0: fig_comp.add_trace(go.Box(y=attack, name='Ataque', marker_color=COLORS['danger']))
        fig_comp.update_layout(**base_chart_layout(250))
    else:
        fig_comp = empty_chart(250)
    
    if not df.empty:
        table = create_data_table(df, [
            {'name': 'UID', 'id': 'uid'}, {'name': 'Origen', 'id': 'src_ip'}, {'name': 'Destino', 'id': 'dst_ip'},
            {'name': 'Tipo', 'id': 'attack_type'}, {'name': 'Sev', 'id': 'severity'}
        ], 'ml', 8)
    else:
        table = html.P("Sin datos", style={'color': COLORS['text_muted']})
    
    return (*kpis, status, fig_conf, fig_classes, fig_tl, fig_comp, table)

# TAB 5: GEMINI
@app.callback(
    Output("gemini-output", "children"),
    [Input("btn-gemini", "n_clicks")],
    [State("gemini-type", "value"), State("gemini-uid", "value"), State("gemini-context", "value")]
)
def generate_gemini(n, analysis_type, uid, context):
    if not n:
        return html.Div([
            html.H6("👋 Asistente SOC con IA", style={'color': COLORS['primary'], 'marginBottom': '1rem'}),
            html.P("Selecciona un tipo de análisis y haz clic en 'Analizar'.", style={'color': COLORS['text_muted'], 'marginBottom': '1rem'}),
            html.Table([
                html.Tbody([
                    html.Tr([html.Td("📊", style={'padding': '0.3rem'}), html.Td("Ejecutivo", style={'color': COLORS['text'], 'padding': '0.3rem'}), html.Td("Resumen para dirección", style={'color': COLORS['text_muted'], 'padding': '0.3rem'})]),
                    html.Tr([html.Td("🔍", style={'padding': '0.3rem'}), html.Td("General", style={'color': COLORS['text'], 'padding': '0.3rem'}), html.Td("Análisis completo del estado", style={'color': COLORS['text_muted'], 'padding': '0.3rem'})]),
                    html.Tr([html.Td("🎯", style={'padding': '0.3rem'}), html.Td("Amenazas", style={'color': COLORS['text'], 'padding': '0.3rem'}), html.Td("Evaluación técnica de ataques", style={'color': COLORS['text_muted'], 'padding': '0.3rem'})]),
                    html.Tr([html.Td("🛡️", style={'padding': '0.3rem'}), html.Td("Mitigación", style={'color': COLORS['text'], 'padding': '0.3rem'}), html.Td("Plan de acciones", style={'color': COLORS['text_muted'], 'padding': '0.3rem'})]),
                    html.Tr([html.Td("🔥", style={'padding': '0.3rem'}), html.Td("Firewall", style={'color': COLORS['text'], 'padding': '0.3rem'}), html.Td("Reglas de protección", style={'color': COLORS['text_muted'], 'padding': '0.3rem'})]),
                    html.Tr([html.Td("🔬", style={'padding': '0.3rem'}), html.Td("Forense", style={'color': COLORS['text'], 'padding': '0.3rem'}), html.Td("Investigación por UID", style={'color': COLORS['text_muted'], 'padding': '0.3rem'})]),
                ])
            ], style={'width': '100%'})
        ])
    
    stats = get_aggregated_stats()
    total = stats.get('total_docs', {}).get('value', 0) or 0
    attacks = stats.get('attacks_count', {}).get('doc_count', 0) or 0
    rate = (attacks / total * 100) if total > 0 else 0
    
    sev_buckets = stats.get('by_severity', {}).get('buckets', [])
    severity_data = {b['key']: b['doc_count'] for b in sev_buckets}
    
    attack_buckets = stats.get('by_attack_type', {}).get('buckets', [])
    top_attacks = [(b['key'], b['doc_count']) for b in attack_buckets if b['key'] != 'Benign'][:5]
    attacks_table = " | ".join([f"{a[0]}: {a[1]:,}" for a in top_attacks])
    
    attack_detail = ""
    if analysis_type == "forensic" and uid:
        data = get_attack_by_uid(uid.strip())
        if data:
            attack_detail = f"""
INCIDENTE: {uid}
Tipo: {data.get('attack_type')} | Severidad: {data.get('severity')} | Confianza: {data.get('ml_confidence', 0)*100:.0f}%
Origen: {data.get('src_ip')}:{data.get('src_port', 'N/A')} → Destino: {data.get('dst_ip')}:{data.get('dst_port')}
Protocolo: {data.get('proto', 'N/A')} | Bytes: {data.get('total_bytes', 0)} | Paquetes: {data.get('total_pkts', 0)}
"""
        else:
            attack_detail = f"⚠️ UID {uid} no encontrado"
    
    # Instrucciones de formato comunes
    format_rules = """
REGLAS DE FORMATO OBLIGATORIAS:
- Respuesta CORTA y DIRECTA (máximo 400 palabras)
- NO usar asteriscos (*) ni guiones (-) para listas
- Usar NÚMEROS (1. 2. 3.) para listas
- Usar TABLAS con formato Markdown para configuraciones
- Usar emojis solo en títulos de sección
- Separar secciones con líneas en blanco
- Ir al grano, sin introducciones largas
"""

    data_context = f"""
DATOS ACTUALES:
Total flujos: {total:,} | Ataques: {attacks:,} ({rate:.1f}%)
Críticos: {severity_data.get('critical', 0)} | Altos: {severity_data.get('high', 0)} | Medios: {severity_data.get('medium', 0)}
Top ataques: {attacks_table}
{attack_detail}
{f'Contexto adicional: {context}' if context else ''}
"""

    prompts = {
        'executive': f"""{format_rules}
{data_context}

Genera un RESUMEN EJECUTIVO breve para CISO con este formato exacto:

🚦 ESTADO: [Verde/Amarillo/Rojo] - [Una frase de resumen]

📊 MÉTRICAS CLAVE
| Métrica | Valor | Estado |
|---------|-------|--------|
(incluir 4-5 métricas principales)

⚠️ TOP 3 AMENAZAS
1. [Amenaza] - [Impacto en una línea]
2. ...
3. ...

⚡ ACCIONES INMEDIATAS
1. [Acción concreta]
2. [Acción concreta]
3. [Acción concreta]
""",

        'general': f"""{format_rules}
{data_context}

Analiza la seguridad con este formato:

🔍 EVALUACIÓN GENERAL
[2-3 oraciones sobre el estado actual]

📈 INDICADORES
| Indicador | Valor | Tendencia |
|-----------|-------|-----------|
(4-5 indicadores clave)

🎯 HALLAZGOS PRINCIPALES
1. [Hallazgo]
2. [Hallazgo]
3. [Hallazgo]

✅ RECOMENDACIONES
1. [Recomendación]
2. [Recomendación]
""",

        'threats': f"""{format_rules}
{data_context}

Evalúa las amenazas con este formato:

🎯 RESUMEN DE AMENAZAS
[2 oraciones máximo]

📋 ANÁLISIS POR TIPO
| Ataque | Cantidad | Severidad | Vector | MITRE |
|--------|----------|-----------|--------|-------|
(una fila por cada tipo de ataque detectado)

🔴 PRIORIZACIÓN
1. [Amenaza más crítica] - [Por qué]
2. [Segunda amenaza]
3. [Tercera amenaza]

🛡️ CONTRAMEDIDAS INMEDIATAS
1. [Acción]
2. [Acción]
""",

        'mitigation': f"""{format_rules}
{data_context}

Plan de mitigación con este formato:

🚨 ACCIONES INMEDIATAS (0-24h)
1. [Acción específica]
2. [Acción específica]
3. [Acción específica]

🔒 CONTENCIÓN (24-72h)
1. [Medida]
2. [Medida]

🛡️ HARDENING
| Sistema | Configuración | Prioridad |
|---------|---------------|-----------|
(4-5 configuraciones clave)

📋 VERIFICACIÓN
1. [Check de validación]
2. [Check de validación]
""",

        'firewall': f"""{format_rules}
{data_context}

Genera reglas de firewall en TABULAR FORMAT:

🔥 IPTABLES
| # | Comando Completo |
|---|------------------|
| 1 | iptables -A INPUT ... |
| 2 | iptables -A INPUT ... |
(5-8 reglas específicas para los ataques detectados)

🛡️ NFTABLES
| # | Comando Completo |
|---|------------------|
| 1 | nft add rule ... |
| 2 | nft add rule ... |

🌐 CISCO ACL
| # | Comando |
|---|---------|
| 1 | access-list ... |
| 2 | access-list ... |

🔍 SNORT/SURICATA
| # | Regla |
|---|-------|
| 1 | alert tcp ... |
| 2 | alert udp ... |

📝 NOTAS: [Una línea sobre implementación]
""",

        'forensic': f"""{format_rules}
{data_context}

Análisis forense BREVE:

📋 RESUMEN DEL INCIDENTE
[3 oraciones máximo describiendo qué pasó]

⏱️ LÍNEA DE TIEMPO
| Hora | Evento |
|------|--------|
(eventos clave)

🔍 ANÁLISIS TÉCNICO
| Campo | Valor | Significado |
|-------|-------|-------------|
(campos relevantes del incidente)

🎯 MITRE ATT&CK
| Táctica | Técnica | ID |
|---------|---------|-----|
(2-3 técnicas aplicables)

🔗 IoCs
| Tipo | Valor |
|------|-------|
(IPs, hashes, comportamientos)

🛡️ REMEDIACIÓN
1. [Acción inmediata]
2. [Acción inmediata]
3. [Acción de seguimiento]
"""
    }
    
    return call_gemini(prompts.get(analysis_type, prompts['general']))

# TAB 6: REPORTES PDF
@app.callback(
    [Output("report-preview", "children"), Output("report-stats-preview", "children")],
    [Input("interval", "n_intervals")]
)
def update_report_preview(n):
    stats = get_aggregated_stats()
    total = stats.get('total_docs', {}).get('value', 0) or 0
    attacks = stats.get('attacks_count', {}).get('doc_count', 0) or 0
    rate = (attacks / total * 100) if total > 0 else 0
    total_bytes = stats.get('total_bytes', {}).get('value', 0) or 0
    
    sev_buckets = stats.get('by_severity', {}).get('buckets', [])
    severity_data = {b['key']: b['doc_count'] for b in sev_buckets}
    
    attack_buckets = stats.get('by_attack_type', {}).get('buckets', [])
    
    preview = html.Div([
        html.H6("📄 El reporte incluirá:", style={'color': COLORS['primary'], 'marginBottom': '1rem'}),
        html.Ul([
            html.Li("Portada con nivel de riesgo", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Resumen ejecutivo con KPIs", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Análisis de amenazas por severidad", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Tipos de ataque detectados", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Top IPs atacantes y víctimas", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Puertos más utilizados", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Estado del sistema", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Recomendaciones de seguridad", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.Li("Apéndice con ataques recientes", style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
        ], style={'paddingLeft': '1.5rem'})
    ])
    
    stats_preview = dbc.Row([
        dbc.Col([
            html.Div([
                html.H4(f"{total:,}", style={'color': COLORS['primary'], 'marginBottom': '0'}),
                html.Small("Total Flujos", style={'color': COLORS['text_muted']})
            ], className="text-center p-2", style={'backgroundColor': COLORS['bg_header'], 'borderRadius': '8px'})
        ], md=2),
        dbc.Col([
            html.Div([
                html.H4(f"{attacks:,}", style={'color': COLORS['danger'], 'marginBottom': '0'}),
                html.Small("Ataques", style={'color': COLORS['text_muted']})
            ], className="text-center p-2", style={'backgroundColor': COLORS['bg_header'], 'borderRadius': '8px'})
        ], md=2),
        dbc.Col([
            html.Div([
                html.H4(f"{rate:.1f}%", style={'color': COLORS['warning'], 'marginBottom': '0'}),
                html.Small("Tasa", style={'color': COLORS['text_muted']})
            ], className="text-center p-2", style={'backgroundColor': COLORS['bg_header'], 'borderRadius': '8px'})
        ], md=2),
        dbc.Col([
            html.Div([
                html.H4(f"{severity_data.get('critical', 0)}", style={'color': COLORS['danger'], 'marginBottom': '0'}),
                html.Small("Críticos", style={'color': COLORS['text_muted']})
            ], className="text-center p-2", style={'backgroundColor': COLORS['bg_header'], 'borderRadius': '8px'})
        ], md=2),
        dbc.Col([
            html.Div([
                html.H4(format_bytes(total_bytes), style={'color': COLORS['info'], 'marginBottom': '0'}),
                html.Small("Tráfico", style={'color': COLORS['text_muted']})
            ], className="text-center p-2", style={'backgroundColor': COLORS['bg_header'], 'borderRadius': '8px'})
        ], md=2),
        dbc.Col([
            html.Div([
                html.H4(f"{len(attack_buckets)}", style={'color': COLORS['purple'], 'marginBottom': '0'}),
                html.Small("Tipos Ataque", style={'color': COLORS['text_muted']})
            ], className="text-center p-2", style={'backgroundColor': COLORS['bg_header'], 'borderRadius': '8px'})
        ], md=2),
    ], className="g-2")
    
    return preview, stats_preview

@app.callback(
    [Output("download-report", "data"), Output("report-status", "children")],
    [Input("btn-generate-report", "n_clicks")],
    [State("report-type", "value"), State("report-author", "value"), State("report-org", "value"), State("report-options", "value")],
    prevent_initial_call=True
)
def generate_report(n, report_type, author, org, options):
    if not n:
        return None, ""
    
    try:
        include_rec = "recommendations" in (options or [])
        pdf_bytes = generate_soc_report_pdf(report_type, author, org, include_rec)
        
        filename = f"SOC_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        status = html.Div([
            html.I(className="fas fa-check-circle fa-2x mb-2", style={'color': COLORS['success']}),
            html.P("✅ Reporte generado exitosamente!", style={'color': COLORS['success'], 'fontWeight': '600'}),
            html.Small(f"Archivo: {filename}", style={'color': COLORS['text_muted']})
        ])
        
        return dcc.send_bytes(pdf_bytes, filename), status
        
    except Exception as e:
        status = html.Div([
            html.I(className="fas fa-times-circle fa-2x mb-2", style={'color': COLORS['danger']}),
            html.P(f"❌ Error: {str(e)}", style={'color': COLORS['danger']})
        ])
        return None, status

# TAB 7: GESTIÓN DE ÍNDICES
@app.callback(
    [Output("indices-table", "children"), Output("storage-summary", "children"), Output("select-index", "options")],
    [Input("btn-refresh-indices", "n_clicks"), Input("interval", "n_intervals")]
)
def update_indices_list(n_refresh, n_interval):
    indices = get_indices_details()
    
    if not indices:
        empty_msg = html.P("No se encontraron índices NIDS", style={'color': COLORS['text_muted']})
        return empty_msg, empty_msg, []
    
    # Tabla de índices
    table_header = html.Thead(html.Tr([
        html.Th("Índice", style={'color': COLORS['primary']}),
        html.Th("Documentos", style={'color': COLORS['primary'], 'textAlign': 'right'}),
        html.Th("Ataques", style={'color': COLORS['primary'], 'textAlign': 'right'}),
        html.Th("Tamaño", style={'color': COLORS['primary'], 'textAlign': 'right'}),
        html.Th("Período", style={'color': COLORS['primary']}),
    ]))
    
    rows = []
    total_docs = 0
    total_attacks = 0
    total_size = 0
    
    for idx in indices:
        total_docs += idx['docs']
        total_attacks += idx['attacks']
        total_size += idx['size_bytes']
        
        rows.append(html.Tr([
            html.Td(idx['name'].replace('nids-', ''), style={'color': COLORS['text'], 'fontWeight': '500'}),
            html.Td(f"{idx['docs']:,}", style={'color': COLORS['text'], 'textAlign': 'right'}),
            html.Td(f"{idx['attacks']:,}", style={'color': COLORS['danger'], 'textAlign': 'right'}),
            html.Td(f"{idx['size_mb']:.1f} MB", style={'color': COLORS['info'], 'textAlign': 'right'}),
            html.Td(f"{idx['first_event']} → {idx['last_event']}", style={'color': COLORS['text_muted'], 'fontSize': '0.8rem'}),
        ], style={'borderBottom': f'1px solid {COLORS["border"]}'}))
    
    table = html.Table([table_header, html.Tbody(rows)], style={
        'width': '100%', 'borderCollapse': 'collapse', 'fontSize': '0.85rem'
    })
    
    # Resumen de almacenamiento
    summary = html.Div([
        html.Div([
            html.H3(f"{len(indices)}", style={'color': COLORS['primary'], 'marginBottom': '0'}),
            html.Small("Índices", style={'color': COLORS['text_muted']})
        ], className="text-center mb-3"),
        html.Hr(style={'borderColor': COLORS['border']}),
        html.Div([
            html.P([html.I(className="fas fa-file me-2"), f"{total_docs:,} documentos"], style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.P([html.I(className="fas fa-bug me-2", style={'color': COLORS['danger']}), f"{total_attacks:,} ataques"], style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
            html.P([html.I(className="fas fa-hdd me-2", style={'color': COLORS['info']}), f"{total_size/1024/1024:.1f} MB total"], style={'color': COLORS['text'], 'marginBottom': '0.5rem'}),
        ]),
        html.Hr(style={'borderColor': COLORS['border']}),
        html.Small(f"Actualizado: {datetime.now().strftime('%H:%M:%S')}", style={'color': COLORS['text_muted']})
    ])
    
    # Opciones para el select
    options = [{"label": idx['name'], "value": idx['name']} for idx in indices]
    
    return table, summary, options

@app.callback(
    [Output("download-backup", "data"), Output("index-operation-status", "children")],
    [Input("btn-download-index", "n_clicks")],
    [State("select-index", "value"), State("backup-format", "value")],
    prevent_initial_call=True
)
def download_index_backup(n, index_name, format_type):
    if not n or not index_name:
        return None, html.P("Selecciona un índice primero", style={'color': COLORS['warning']})
    
    data, error = export_index_data(index_name, format_type)
    
    if error:
        return None, html.Div([
            html.I(className="fas fa-times-circle me-2", style={'color': COLORS['danger']}),
            f"Error: {error}"
        ], style={'color': COLORS['danger']})
    
    ext = {'json': 'json', 'csv': 'csv', 'ndjson': 'ndjson'}[format_type]
    filename = f"backup_{index_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
    
    status = html.Div([
        html.I(className="fas fa-check-circle me-2", style={'color': COLORS['success']}),
        f"Backup generado: {filename}"
    ], style={'color': COLORS['success']})
    
    return dcc.send_string(data, filename), status

@app.callback(
    Output("index-preview", "children"),
    [Input("btn-preview-index", "n_clicks")],
    [State("select-index", "value")],
    prevent_initial_call=True
)
def preview_index_data(n, index_name):
    if not n or not index_name:
        return html.P("Selecciona un índice primero", style={'color': COLORS['text_muted']})
    
    es = get_es()
    if not es:
        return html.P("Elasticsearch no disponible", style={'color': COLORS['danger']})
    
    try:
        r = es.search(index=index_name, query={"match_all": {}}, size=100, sort=[{"@timestamp": "desc"}])
        docs = [hit['_source'] for hit in r['hits']['hits']]
        
        if not docs:
            return html.P("Índice vacío", style={'color': COLORS['text_muted']})
        
        df = pd.DataFrame(docs)
        cols_to_show = ['@timestamp', 'src_ip', 'dst_ip', 'attack_type', 'severity', 'is_attack']
        available_cols = [c for c in cols_to_show if c in df.columns]
        
        if not available_cols:
            available_cols = list(df.columns)[:6]
        
        return create_data_table(df[available_cols], [{'name': c, 'id': c} for c in available_cols], 'preview', 10)
    except Exception as e:
        return html.P(f"Error: {e}", style={'color': COLORS['danger']})

@app.callback(
    [Output("modal-delete", "is_open"), Output("delete-confirm-text", "children")],
    [Input("btn-delete-index", "n_clicks"), Input("btn-cancel-delete", "n_clicks"), Input("btn-confirm-delete", "n_clicks")],
    [State("select-index", "value"), State("modal-delete", "is_open")],
    prevent_initial_call=True
)
def toggle_delete_modal(n_delete, n_cancel, n_confirm, index_name, is_open):
    ctx = callback_context
    if not ctx.triggered:
        return False, ""
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == "btn-delete-index" and index_name:
        # Obtener info del índice
        indices = get_indices_details()
        idx_info = next((i for i in indices if i['name'] == index_name), None)
        if idx_info:
            text = f"¿Eliminar el índice '{index_name}'? Contiene {idx_info['docs']:,} documentos ({idx_info['size_mb']:.1f} MB)"
        else:
            text = f"¿Eliminar el índice '{index_name}'?"
        return True, text
    
    return False, ""

# Variable global para almacenar el índice a eliminar
_pending_delete_index = {'name': None}

@app.callback(
    Output("index-operation-status", "children", allow_duplicate=True),
    [Input("btn-confirm-delete", "n_clicks")],
    [State("select-index", "value")],
    prevent_initial_call=True
)
def execute_delete_index(n, index_name):
    if not n or not index_name:
        return ""
    
    success, msg = delete_index(index_name)
    
    if success:
        return html.Div([
            html.I(className="fas fa-check-circle me-2", style={'color': COLORS['success']}),
            msg
        ], style={'color': COLORS['success']})
    else:
        return html.Div([
            html.I(className="fas fa-times-circle me-2", style={'color': COLORS['danger']}),
            f"Error: {msg}"
        ], style={'color': COLORS['danger']})

@app.callback(
    Output("download-backup-all", "data"),
    [Input("btn-backup-all", "n_clicks")],
    prevent_initial_call=True
)
def backup_all_indices(n):
    if not n:
        return None
    
    indices = get_indices_details()
    all_data = {}
    
    for idx in indices:
        data, error = export_index_data(idx['name'], 'json', limit=10000)
        if not error and data:
            all_data[idx['name']] = json.loads(data)
    
    filename = f"backup_nids_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return dcc.send_string(json.dumps(all_data, indent=2, default=str), filename)

@app.callback(
    Output("index-operation-status", "children", allow_duplicate=True),
    [Input("btn-clean-old", "n_clicks")],
    prevent_initial_call=True
)
def clean_old_indices(n):
    if not n:
        return ""
    
    success, msg = delete_old_indices(days=7)
    
    if success:
        return html.Div([
            html.I(className="fas fa-check-circle me-2", style={'color': COLORS['success']}),
            msg
        ], style={'color': COLORS['success']})
    else:
        return html.Div([
            html.I(className="fas fa-times-circle me-2", style={'color': COLORS['danger']}),
            f"Error: {msg}"
        ], style={'color': COLORS['danger']})

# TAB 8: MONITOR
@app.callback(
    [Output("sys-arch", "children"), Output("sys-status", "children"), Output("es-indices", "children"), Output("ml-info", "children")],
    [Input("interval", "n_intervals")]
)
def update_monitor(n):
    status = check_system_status()
    
    def node(icon, name, online):
        color = COLORS['success'] if online else COLORS['danger']
        return html.Div([
            html.I(className=f"fas {icon} fa-2x", style={'color': color}),
            html.P(name, className="mt-1 mb-0", style={'color': COLORS['text'], 'fontSize': '0.7rem'})
        ], className="text-center p-2", style={'backgroundColor': f'rgba({59 if online else 239},{130 if online else 68},{246 if online else 68},0.1)', 'borderRadius': '6px', 'minWidth': '70px', 'margin': '2px'})
    
    arch = html.Div([
        node("fa-network-wired", "Red", True),
        html.Span("→", style={'color': COLORS['primary'], 'margin': '0 3px'}),
        node("fa-eye", "Zeek", status['zeek']['online']),
        html.Span("→", style={'color': COLORS['primary'], 'margin': '0 3px'}),
        node("fa-cogs", "Logstash", status['logstash']['online']),
        html.Span("→", style={'color': COLORS['primary'], 'margin': '0 3px'}),
        node("fa-brain", "ML", status['ml_api']['online']),
        html.Span("→", style={'color': COLORS['primary'], 'margin': '0 3px'}),
        node("fa-database", "ES", status['elasticsearch']['online']),
    ], className="d-flex align-items-center justify-content-center flex-wrap")
    
    def badge(online, name):
        return html.Div([html.I(className=f"fas fa-{'check' if online else 'times'}-circle me-2", style={'color': COLORS['success'] if online else COLORS['danger']}), name], style={'marginBottom': '0.3rem', 'color': COLORS['text'], 'fontSize': '0.85rem'})
    
    svc = html.Div([
        badge(status['elasticsearch']['online'], f"ES ({status['elasticsearch']['cluster']})"),
        badge(status['ml_api']['online'], "ML API"),
        badge(status['logstash']['online'], "Logstash"),
        badge(status['zeek']['online'], "Zeek"),
        html.Hr(style={'borderColor': COLORS['border'], 'margin': '0.5rem 0'}),
        html.Small(f"📊 {status['elasticsearch']['docs']:,} docs | {status['elasticsearch']['size']}", style={'color': COLORS['text_muted']})
    ])
    
    if status['indices']:
        indices = html.Div([html.Div([html.Strong(idx['name'].replace('nids-','')), html.Span(f" {idx['docs']:,} docs", style={'color': COLORS['text_muted']})], style={'fontSize': '0.8rem', 'padding': '0.3rem', 'backgroundColor': COLORS['bg_header'], 'borderRadius': '4px', 'marginBottom': '0.3rem'}) for idx in status['indices'][:5]])
    else:
        indices = html.P("Sin índices", style={'color': COLORS['text_muted']})
    
    ml_info = html.Div([
        html.P(f"🤖 Modelo: RandomForest", style={'color': COLORS['text'], 'fontSize': '0.85rem'}),
        html.P(f"📊 Predicciones: {status['ml_api']['predictions']:,}", style={'color': COLORS['text'], 'fontSize': '0.85rem'}),
        html.P(f"⚠️ Ataques: {status['ml_api']['attacks']:,}", style={'color': COLORS['danger'], 'fontSize': '0.85rem'}),
    ]) if status['ml_api']['online'] else html.P("ML no disponible", style={'color': COLORS['text_muted']})
    
    return arch, svc, indices, ml_info

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  NIDS SOC Dashboard v5.1 - CON REPORTES PDF")
    print("=" * 60)
    status = check_system_status()
    print(f"  ES: {'✓' if status['elasticsearch']['online'] else '✗'} | ML: {'✓' if status['ml_api']['online'] else '✗'} | Docs: {status['elasticsearch']['docs']:,}")
    print("=" * 60)
    print("  URL: http://localhost:8050")
    print("=" * 60)
    app.run(debug=False, host='0.0.0.0', port=8050)
