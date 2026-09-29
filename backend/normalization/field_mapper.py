import os
import re
import yaml
from typing import Dict, Any, Optional, List
from dateutil import parser as dt_parser

class FieldMapper:
    """
    Configurable, declarative YAML-driven field mapper for ULPF.
    Supports both list-based mappings and dictionary-based mappings,
    case-insensitive matching, value maps, and fallback to generic mappings.
    """

    def __init__(self):
        self.mappings: Dict[str, Any] = {}
        config_env = os.environ.get('ULPF_CONFIG_DIR')
        if config_env:
            self.config_dir = os.path.join(config_env, 'field_mappings') if not config_env.endswith('field_mappings') else config_env
        else:
            backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            candidate = os.path.join(backend_dir, 'config', 'field_mappings')
            if os.path.exists(candidate):
                self.config_dir = candidate
            else:
                self.config_dir = os.path.join(os.path.dirname(backend_dir), 'backend', 'config', 'field_mappings')
        self.load_mappings()

    def load_mappings(self):
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir, exist_ok=True)
            return

        for filename in os.listdir(self.config_dir):
            if filename.endswith('.yaml') or filename.endswith('.yml'):
                key = os.path.splitext(filename)[0].lower()
                filepath = os.path.join(self.config_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f) or {}
                        self.mappings[key] = data
                        # Also index by source property if declared in YAML
                        src_decl = data.get('source')
                        if src_decl:
                            self.mappings[str(src_decl).lower()] = data
                except Exception as e:
                    print(f"[WARN] Error loading field mapping {filename}: {e}")

    def find_mapping_for_source(self, source_id: str, parser_plugin: str = "") -> Dict[str, Any]:
        """
        Intelligently resolves the optimal YAML mapping file based on
        source identifier, parser class name, or device type.
        """
        s_clean = (source_id or "").lower().strip()
        p_name = (parser_plugin or "").replace("Parser", "")
        p_clean = p_name.lower().strip()

        # 1. Direct match on source_id
        if s_clean in self.mappings:
            return self.mappings[s_clean]

        # 2. Match on parser name (e.g. CiscoASAParser -> cisco_asa)
        if p_clean in self.mappings:
            return self.mappings[p_clean]

        # Proper camelCase/PascalCase to snake_case handling acronyms (e.g., CiscoASA -> cisco_asa)
        s1 = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', p_name)
        p_snake = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
        if p_snake in self.mappings:
            return self.mappings[p_snake]

        # 3. Fuzzy search in mapping keys
        for k in self.mappings:
            if k in s_clean or (p_clean and k in p_clean) or (p_snake and k in p_snake):
                return self.mappings[k]

        # 4. Fallback to generic mapping
        return self.mappings.get('generic', {})

    def map_fields(self, parsed: dict, source_id: str, parser_plugin: str = "") -> dict:
        mapping_conf = self.find_mapping_for_source(source_id, parser_plugin)
        result = parsed.copy()

        # 1. Process Format A: list of mappings `mappings: [ {from, to, type, value_map, normalize} ]`
        if 'mappings' in mapping_conf and isinstance(mapping_conf['mappings'], list):
            for rule in mapping_conf['mappings']:
                src_key = rule.get('from')
                dst_key = rule.get('to')
                if not src_key or not dst_key:
                    continue

                val = self._extract_value(parsed, src_key)
                if val is not None:
                    # Apply value map
                    vmap = rule.get('value_map', {})
                    str_val = str(val).strip().lower()
                    
                    # Try case-insensitive value map lookup
                    matched_vmap = False
                    for map_k, map_v in vmap.items():
                        if str(map_k).lower() == str_val:
                            val = map_v
                            matched_vmap = True
                            break

                    # Apply normalization
                    norm_op = rule.get('normalize')
                    if norm_op == 'lowercase' and isinstance(val, str):
                        val = val.lower()
                    elif norm_op == 'uppercase' and isinstance(val, str):
                        val = val.upper()

                    # Apply type coercion
                    val = self._coerce_type(val, rule.get('type'))

                    # Store in result (both leaf key and full path)
                    leaf = dst_key.split('.')[-1]
                    result[dst_key] = val
                    result[leaf] = val

        # 2. Process Format B: dictionary of fields `fields: { dst_field: { source, type, value_map, transform } }`
        elif 'fields' in mapping_conf and isinstance(mapping_conf['fields'], dict):
            for dst_key, rule in mapping_conf['fields'].items():
                src_key = rule.get('source', dst_key)
                val = self._extract_value(parsed, src_key)
                if val is not None:
                    # Value map
                    vmap = rule.get('value_map', {})
                    if str(val) in vmap:
                        val = vmap[str(val)]

                    # Transform
                    transform = rule.get('transform')
                    if transform == 'lowercase' and isinstance(val, str):
                        val = val.lower()
                    elif transform == 'uppercase' and isinstance(val, str):
                        val = val.upper()

                    # Type coercion
                    val = self._coerce_type(val, rule.get('type'))

                    leaf = dst_key.split('.')[-1]
                    result[dst_key] = val
                    result[leaf] = val

        # 3. Apply defaults from mapping file
        defaults = mapping_conf.get('defaults', {})
        for d_k, d_v in defaults.items():
            if d_k not in result:
                result[d_k] = d_v
                leaf = d_k.split('.')[-1]
                if leaf not in result:
                    result[leaf] = d_v

        return result

    @staticmethod
    def _extract_value(data: dict, key: str) -> Optional[Any]:
        """Extracts value using exact key, dot-notation, or case-insensitive search."""
        if key in data:
            return data[key]

        if '.' in key:
            parts = key.split('.')
            curr = data
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return None
            return curr

        # Case-insensitive scan
        key_lower = key.lower()
        for k, v in data.items():
            if str(k).lower() == key_lower:
                return v

        return None

    @staticmethod
    def _coerce_type(val: Any, val_type: Optional[str]) -> Any:
        if val is None or not val_type:
            return val
        t = val_type.lower()
        try:
            if t == 'integer' or t == 'int':
                return int(val)
            elif t == 'float':
                return float(val)
            elif t == 'string' or t == 'str':
                return str(val)
            elif t == 'datetime':
                return dt_parser.parse(str(val)).isoformat()
        except Exception:
            pass
        return val
