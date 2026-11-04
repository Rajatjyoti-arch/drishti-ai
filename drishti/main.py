"""Drishti AI: CLI entrypoint and orchestrator loop."""

import sys
import json
from pathlib import Path
from drishti.core.contract import AuthorizationContract
from drishti.policy.gate import DeterministicPolicyGate

def verify_contract_cmd(contract_path: Path):
    try:
        contract = AuthorizationContract.load_from_file(contract_path)
        print("==================================================")
        print("✓ Authorization Contract Valid")
        print("==================================================")
        print(f"Permitted Targets: {', '.join(contract.permitted_targets)}")
        print(f"Max Rate Budget:   {contract.request_budgets.max_requests_per_second} req/s")
        print(f"Max Total Budget:  {contract.request_budgets.max_total_requests_per_run} requests")
        print(f"Test Tenants:      {contract.test_tenants}")
        print("==================================================")
    except Exception as e:
        print(f"✗ Contract Validation Failed: {e}", file=sys.stderr)
        sys.exit(1)

def run_loop_cmd(contract_path: Path):
    print("==================================================")
    print("Drishti AI: Starting Milestone 1 Frozen Loop")
    print("==================================================")
    contract = AuthorizationContract.load_from_file(contract_path)
    gate = DeterministicPolicyGate(contract)
    print(f"✓ Policy Gate Initialized: {len(contract.permitted_targets)} allowed target domains")
    print("✓ Request budgets and concurrency limits bound.")
    print("Ready to ingest change events (commit SHA / HAR capture)...")

def main():
    try:
        import typer
        from rich.console import Console
        from rich.panel import Panel

        app = typer.Typer(help="Drishti AI: Agentic Real-Time DAST for B2B Travel Ecosystems")
        console = Console()

        @app.command()
        def verify_contract(contract_path: Path = Path("configs/auth_contract.json")):
            """Validates the Authorization Contract configuration."""
            contract = AuthorizationContract.load_from_file(contract_path)
            console.print(Panel(
                f"[bold green]✓ Authorization Contract Valid[/bold green]\n"
                f"Targets: {', '.join(contract.permitted_targets)}\n"
                f"Max Rate: {contract.request_budgets.max_requests_per_second} req/s\n"
                f"Max Total: {contract.request_budgets.max_total_requests_per_run} requests",
                title="Drishti Policy Gate"
            ))

        @app.command()
        def run(contract_path: Path = Path("configs/auth_contract.json")):
            """Executes the frozen 7-step single-loop security assessment."""
            run_loop_cmd(contract_path)

        app()
    except ImportError:
        # Fallback to standard library argparse if typer is not yet installed
        import argparse
        parser = argparse.ArgumentParser(description="Drishti AI: Agentic Real-Time DAST for B2B Travel Ecosystems")
        subparsers = parser.add_subparsers(dest="command")

        verify_p = subparsers.add_parser("verify-contract", help="Validate Authorization Contract")
        verify_p.add_argument("--contract-path", default="configs/auth_contract.json", help="Path to contract JSON")

        run_p = subparsers.add_parser("run", help="Run Milestone 1 single-loop")
        run_p.add_argument("--contract-path", default="configs/auth_contract.json", help="Path to contract JSON")

        args = parser.parse_args()
        if args.command == "verify-contract":
            verify_contract_cmd(Path(args.contract_path))
        elif args.command == "run":
            run_loop_cmd(Path(args.contract_path))
        else:
            parser.print_help()

if __name__ == "__main__":
    main()
