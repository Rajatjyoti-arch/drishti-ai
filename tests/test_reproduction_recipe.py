"""Unit tests for ReproductionRecipeGenerator."""

import pytest
from drishti.verifier.reproduction import ReproductionRecipeGenerator


def test_i01_reproduction_recipe_generation():
    """I-01 recipe contains 4 steps, $DRISHTI_* environment variables, and zero leaked secrets."""
    recipes = ReproductionRecipeGenerator.generate_i01_recipes(
        victim_booking_id="TBOH_victim_999",
        attacker_booking_id="TBOH_attacker_111",
    )

    assert len(recipes) == 4
    for r in recipes:
        # Strict zero secret leakage: commands must use $DRISHTI_* environment variables
        assert "$DRISHTI_TARGET_URL" in r.curl_command
        assert "secret" not in r.curl_command.lower()
        assert "password" not in r.curl_command.lower()

    # Step 3 must target victim resource with attacker token
    step_3 = recipes[2]
    assert "TBOH_victim_999" in step_3.curl_command
    assert "$DRISHTI_ATTACKER_TOKEN" in step_3.curl_command
    assert step_3.expected_status == 403


def test_i02_reproduction_recipe_generation():
    """I-02 recipe properly parameters tampered price and baseline quote."""
    recipes = ReproductionRecipeGenerator.generate_i02_recipes(
        booking_id="TBOH_tampered_888",
        tampered_amount=100,
        tampered_currency="INR",
        authoritative_amount=1800000,
        authoritative_currency="INR",
    )

    assert len(recipes) == 4
    step_3 = recipes[2]
    assert '"client_amount_minor_units": 100' in step_3.curl_command
    assert '"client_currency": "INR"' in step_3.curl_command
    assert step_3.expected_status == 400

    step_4 = recipes[3]
    assert "TBOH_tampered_888" in step_4.curl_command


def test_reproduction_script_generation():
    """Generates an executable bash reproduction script with safe defaults."""
    recipes = ReproductionRecipeGenerator.generate_i01_recipes(victim_booking_id="TBOH_123")
    script = ReproductionRecipeGenerator.generate_reproduction_script(
        recipes=recipes,
        target_url="https://api.tbo.com",
    )

    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "DRISHTI_TARGET_URL" in script
    assert "DRISHTI_ATTACKER_TOKEN" in script
    assert "TBOH_123" in script
