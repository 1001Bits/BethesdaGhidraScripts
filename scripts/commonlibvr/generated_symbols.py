"""Read assignments from a generated CommonLib importer without executing it.

The generator writes ``SYMBOLS = _json_sym.loads('<json>')``; slicing off
``SYMBOLS = `` and ``json.loads``-ing the rest always fails.  Exec'ing the
importer prelude is no option either: it needs a live ``currentProgram``.
"""
import ast
import json


def assignment_value(line):
    """Value of a generated ``NAME = ...`` line; plain literals are evaluated."""
    value = ast.parse(line).body[0].value
    if isinstance(value, ast.Call):
        func = value.func
        if (isinstance(func, ast.Attribute) and func.attr == 'loads' and
                len(value.args) == 1 and not value.keywords and
                isinstance(value.args[0], ast.Constant) and
                isinstance(value.args[0].value, str)):
            return json.loads(value.args[0].value)
        raise ValueError('unsupported generated assignment: ' + line[:80])
    return ast.literal_eval(value)


def load_symbols(import_path):
    with open(import_path, encoding='utf-8') as f:
        for line in f:
            if line.startswith('SYMBOLS = '):
                return assignment_value(line)
    raise RuntimeError('SYMBOLS not found in ' + import_path)
