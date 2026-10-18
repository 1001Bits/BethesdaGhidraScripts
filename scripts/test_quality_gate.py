import quality_gate


def _errors(tmp_path, monkeypatch, source):
    path = tmp_path / "scripts" / "driver.py"
    path.parent.mkdir()
    path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(quality_gate, "ROOT", tmp_path)
    monkeypatch.setattr(quality_gate, "_python_files", lambda: iter([path]))
    return quality_gate.static_checks()[0]


def test_gate_rejects_nonexistent_memory_block_methods(tmp_path, monkeypatch):
    errors = _errors(tmp_path, monkeypatch,
                     "def f(block):\n    return block.isWritable()\n")
    assert len(errors) == 1 and "MemoryBlock.isWrite()" in errors[0]


def test_gate_rejects_in_globals_entry_guard(tmp_path, monkeypatch):
    errors = _errors(tmp_path, monkeypatch,
                     "if 'currentProgram' in globals():\n    pass\n")
    assert len(errors) == 1 and "always False under PyGhidra" in errors[0]


def test_gate_accepts_the_real_spellings(tmp_path, monkeypatch):
    assert _errors(tmp_path, monkeypatch,
                   "def f(block, g):\n"
                   "    return block.isWrite() and g['currentProgram']\n") == []


def test_gate_rejects_raw_get_domain_object_calls(tmp_path, monkeypatch):
    errors = _errors(tmp_path, monkeypatch,
                     "def f(df, c, m):\n"
                     "    return df.getDomainObject(c, True, False, m)\n")
    assert len(errors) == 1 and "ghidra_project.open_program()" in errors[0]


def test_gate_ignores_get_domain_object_text_and_open_program(tmp_path, monkeypatch):
    assert _errors(tmp_path, monkeypatch,
                   "TEMPLATE = 'p = df.getDomainObject(c, True, False, m)'\n"
                   "def f(df, c, m, open_program):\n"
                   "    # df.getDomainObject(c, True, False, m)\n"
                   "    return open_program(df, c, m, write=False)\n") == []


def test_only_open_program_may_call_get_domain_object():
    """The live tree: every opener goes through ghidra_project.open_program."""
    import ast
    offenders = []
    for path in quality_gate._python_files():
        relative = path.relative_to(quality_gate.ROOT).as_posix()
        if relative == quality_gate.OPEN_PROGRAM_HOME:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        offenders += [
            "{}:{}".format(relative, node.lineno) for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "getDomainObject"]
    assert offenders == []
