import ast
import hashlib
from typing import Tuple, List

FORBIDDEN_CALLS = {
    'system', 'popen', 'spawn', 'exec', 'eval', '__import__',
    'rmtree', 'remove', 'unlink', 'kill'
}

FORBIDDEN_MODULES = {
    'subprocess', 'pty', 'socket', 'urllib', 'http.client', 'paramiko', 'telnetlib'
}

class SecurePluginValidator:
    """
    Performs static AST security analysis on uploaded parser plugins
    to prevent code injection and malicious payloads in air-gapped environments.
    """

    @classmethod
    def validate_code(cls, code_bytes: bytes) -> Tuple[bool, str, str]:
        """
        Returns: (is_safe: bool, message: str, sha256_hash: str)
        """
        code_str = code_bytes.decode('utf-8', errors='ignore')
        code_hash = hashlib.sha256(code_bytes).hexdigest()

        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            return False, f"Syntax error in plugin: {e}", code_hash

        # Inspect AST nodes
        has_base_parser = False

        for node in ast.walk(tree):
            # Check prohibited imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_mod = alias.name.split('.')[0]
                    if root_mod in FORBIDDEN_MODULES:
                        return False, f"Security violation: Forbidden module imported '{alias.name}'", code_hash

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_mod = node.module.split('.')[0]
                    if root_mod in FORBIDDEN_MODULES:
                        return False, f"Security violation: Forbidden module imported '{node.module}'", code_hash

            # Check dangerous function calls
            elif isinstance(node, ast.Call):
                func = node.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr

                if func_name and func_name in FORBIDDEN_CALLS:
                    return False, f"Security violation: Prohibited function call '{func_name}'", code_hash

            # Check class definition
            elif isinstance(node, ast.ClassDef):
                for base in node.bases:
                    if (isinstance(base, ast.Name) and base.id == 'BaseParser') or \
                       (isinstance(base, ast.Attribute) and base.attr == 'BaseParser'):
                        has_base_parser = True

        if not has_base_parser:
            return False, "Plugin must define a class subclassing 'BaseParser'", code_hash

        return True, "Plugin passed static security checks", code_hash
