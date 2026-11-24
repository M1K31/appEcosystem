from ecosystem_ai.analyst_prompt import ANALYST_SYSTEM_PROMPT, build_analyst_modelfile


def test_prompt_pins_the_schema_fields_and_classes():
    for token in ("action_class", "rationale", "confidence", "system_change", "observe"):
        assert token in ANALYST_SYSTEM_PROMPT


def test_prompt_forbids_execution_and_self_approval():
    low = ANALYST_SYSTEM_PROMPT.lower()
    assert "never" in low and "execute" in low and "approv" in low


def test_modelfile_references_base_and_system():
    mf = build_analyst_modelfile("llama3.1:8b-instruct")
    assert mf.startswith("FROM llama3.1:8b-instruct") and "SYSTEM" in mf


def test_template_file_matches_builder():
    from pathlib import Path

    import ecosystem_ai

    tpl = Path(ecosystem_ai.__file__).parent / "templates" / "analyst.Modelfile"
    assert tpl.read_text() == build_analyst_modelfile("llama3.1:8b-instruct")
    assert '"""' not in ANALYST_SYSTEM_PROMPT
