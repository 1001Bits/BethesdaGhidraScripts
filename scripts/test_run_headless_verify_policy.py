import run_headless


def _skyrim_spec():
    return dict(run_headless.SPOT_CHECKS["skyrim"])


def test_skyrim_no_longer_requires_obsolete_commonlib_function_names():
    assert _skyrim_spec()["functions"] == []


def test_total_symbol_drift_is_advisory_not_atomic_failure():
    spec = _skyrim_spec()
    errors, warnings = run_headless._evaluate_sanity(
        spec,
        named_funcs=spec["min_named"],
        enum_count=spec["min_enums"],
        struct_count=spec["min_structs"],
        sym_count=243_288,
        spot_ok=True,
    )
    assert errors == []
    assert len(warnings) == 1
    assert "243,288" in warnings[0]
    assert "250,000" in warnings[0]


def test_all_historical_counts_and_spot_checks_are_diagnostic_only():
    spec = _skyrim_spec()
    errors, warnings = run_headless._evaluate_sanity(
        spec,
        named_funcs=spec["min_named"] - 1,
        enum_count=spec["min_enums"] - 1,
        struct_count=spec["min_structs"] - 1,
        sym_count=spec["min_syms"] - 1,
        spot_ok=False,
    )
    assert errors == []
    assert len(warnings) == 5
