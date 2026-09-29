import json
import re

def is_json(text: str) -> bool:
    try:
        json.loads(text)
        return True
    except:
        return False

def is_xml(text: str) -> bool:
    return text.strip().startswith('<?xml') or text.strip().startswith('<') and text.strip().endswith('>')

def is_csv(text: str, min_fields: int = 3) -> bool:
    return ',' in text and len(text.split(',')) >= min_fields

def is_cef(text: str) -> bool:
    return text.startswith('CEF:')

def is_leef(text: str) -> bool:
    return text.startswith('LEEF:')

def is_syslog_rfc5424(text: str) -> bool:
    return bool(re.match(r'^<\d+>\d\s', text))

def is_syslog_rfc3164(text: str) -> bool:
    return bool(re.match(r'^<\d+>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}', text))

def detect_format(text: str) -> str:
    if is_json(text): return 'json'
    if is_cef(text): return 'cef'
    if is_leef(text): return 'leef'
    if is_syslog_rfc5424(text): return 'syslog_rfc5424'
    if is_syslog_rfc3164(text): return 'syslog_rfc3164'
    if is_xml(text): return 'xml'
    if is_csv(text): return 'csv'
    return 'unknown'
