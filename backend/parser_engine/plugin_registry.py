import os
import sys
import importlib.util
from typing import List, Tuple, Type, Optional
from parser_engine.base_parser import BaseParser

class PluginRegistry:
    def __init__(self):
        self.plugins: List[BaseParser] = []
        self._load_plugins()
        
    def _load_plugins(self):
        plugins_dir = os.path.join(os.path.dirname(__file__), 'plugins')
        if os.path.exists(plugins_dir):
            for filename in os.listdir(plugins_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    self.register_plugin(os.path.join(plugins_dir, filename))
                
        self.plugins.sort(key=lambda p: p.PRIORITY)
        
    def register_plugin(self, filepath: str) -> Optional[BaseParser]:
        module_name = os.path.splitext(os.path.basename(filepath))[0]
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            
            registered_instance = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if isinstance(attr, type) and issubclass(attr, BaseParser) and attr is not BaseParser:
                    # Remove existing if same SOURCE_ID
                    self.plugins = [p for p in self.plugins if p.SOURCE_ID != attr.SOURCE_ID]
                    instance = attr()
                    self.plugins.append(instance)
                    registered_instance = instance
                    
            self.plugins.sort(key=lambda p: p.PRIORITY)
            return registered_instance
        return None

    def detect_parser(self, raw: str, metadata: dict) -> Tuple[Optional[BaseParser], float]:
        best_parser = None
        best_score = -1.0
        
        for plugin in self.plugins:
            try:
                score = plugin.can_parse(raw, metadata)
                if score > best_score:
                    best_score = score
                    best_parser = plugin
                    
                if score >= 0.95:  # Fast exit on deterministic pattern
                    break
            except Exception as e:
                print(f"[WARN] Error running can_parse on {plugin.__class__.__name__}: {e}")
                
        return best_parser, (best_score if best_score > 0 else 0.0)

    def parse(self, raw: str, metadata: dict) -> Tuple[dict, Optional[BaseParser], float]:
        parser, conf = self.detect_parser(raw, metadata)
        if parser:
            try:
                fields = parser.parse(raw, metadata)
                return fields, parser, conf
            except Exception as e:
                print(f"[WARN] Error executing parse on {parser.__class__.__name__}: {e}")
                return {}, parser, conf
        return {}, None, 0.0

    def get_parser_by_name(self, name: str) -> Optional[BaseParser]:
        for p in self.plugins:
            if p.__class__.__name__ == name or p.SOURCE_ID == name:
                return p
        return None
        
    def list_plugins(self) -> list:
        return [{
            "name": p.__class__.__name__,
            "source_id": p.SOURCE_ID,
            "version": getattr(p, "VERSION", "1.0.0"),
            "priority": p.PRIORITY,
            "description": p.__doc__.strip() if p.__doc__ else f"Parser for {p.SOURCE_ID} events"
        } for p in self.plugins]
