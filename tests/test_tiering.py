"""Mode-tier gating: a tool above the configured mode is never registered —
structural absence is the anti-prompt-injection control (threat model T1)."""

from fenrir_mcp import tools

RO = set(tools.registered("readonly"))
STD = set(tools.registered("standard"))
FULL = set(tools.registered("full"))

WRITE_TOOLS = {
    "fenrir_incident_write", "fenrir_timeline_write", "fenrir_ioc_write",
    "fenrir_ioc_enrich", "fenrir_entity_write", "fenrir_file_upload",
    "fenrir_evidence_register", "fenrir_evidence_custody", "fenrir_task_write",
    "fenrir_respond_write", "fenrir_comms_write", "fenrir_people_write",
    "fenrir_legal_write", "fenrir_costs_write", "fenrir_email_analyze",
    "fenrir_pcap_analyze", "fenrir_webhistory_import", "fenrir_timeline_import",
    "fenrir_artifact_write", "fenrir_collection_write", "fenrir_osint_enrich",
    "fenrir_report_generate", "fenrir_post_incident_write", "fenrir_yara_write",
    "fenrir_attribution_write",
}

FULL_TOOLS = {
    "fenrir_delete", "fenrir_evidence_dispose", "fenrir_admin_users",
    "fenrir_admin_teams", "fenrir_admin_platform",
}


def test_readonly_has_no_write_or_destructive_tools():
    assert not (RO & WRITE_TOOLS)
    assert not (RO & FULL_TOOLS)


def test_standard_has_writes_but_no_destructive_tools():
    assert WRITE_TOOLS <= STD
    assert not (STD & FULL_TOOLS)


def test_full_has_everything():
    assert WRITE_TOOLS <= FULL
    assert FULL_TOOLS <= FULL
    assert RO <= STD <= FULL


def test_escape_hatch_exists_in_every_mode():
    assert "fenrir_api" in RO
    assert "fenrir_api" in STD
    assert "fenrir_api" in FULL


def test_catalog_size_matches_design():
    # docs/TOOLS.md: 21 RO + 25 STD + 5 FULL + escape hatch (one STD slot was
    # folded into people_write, one added as attribution_write)
    assert len(RO) == 22          # 21 curated RO + fenrir_api
    assert len(FULL - STD) == 5
    assert len(FULL) == len(RO) + len(WRITE_TOOLS) + len(FULL_TOOLS)
