#!/usr/bin/env python3
"""
Command-line tool for validating FLYNC configurations.

Supports validation of:
- Complete FLYNC workspaces
- Individual ECUs
- Security configurations (MACSec, Firewall)
- SOME/IP services
- TSN configurations
- Any partial FLYNC model

Usage:
    # Validate complete workspace
    python validate_config.py workspace /path/to/config

    # Validate single ECU
    python validate_config.py ecu /path/to/ecu.flync.yaml

    # Validate MACSec config
    python validate_config.py macsec /path/to/macsec.flync.yaml
    
    # Validate any model type
    python validate_config.py model ECU /path/to/ecu.flync.yaml
"""

import argparse
import sys
from pathlib import Path
from typing import Type

from rich.console import Console
from rich.table import Table

from flync.core.base_models.base_model import FLYNCBaseModel
from flync.sdk.utils import (
    PartialConfigValidator,
    format_error_location_with_data,
    format_error_location
)
from flync.sdk.workspace.flync_workspace import FLYNCWorkspace

console = Console()


# Model type mappings for CLI
MODEL_TYPES = {
    'ecu': 'flync.model.flync_4_ecu.ECU',
    'macsec': 'flync.model.flync_4_security.MACSec',
    'firewall': 'flync.model.flync_4_security.Firewall',
    'someip': 'flync.model.flync_4_someip.SOMEIPServiceInterface',
    'qos': 'flync.model.flync_4_tsn.QoS',
    'ptp': 'flync.model.flync_4_tsn.PTP',
    'controller': 'flync.model.flync_4_ecu.Controller',
    'switch': 'flync.model.flync_4_ecu.Switch',
}


def import_model_class(class_path: str) -> Type[FLYNCBaseModel]:
    """Import a model class from its module path."""
    module_path, class_name = class_path.rsplit('.', 1)
    module = __import__(module_path, fromlist=[class_name])
    return getattr(module, class_name)


def validate_workspace(path: Path) -> bool:
    """Validate a complete FLYNC workspace."""
    console.print(f"\n[bold blue]Validating workspace:[/bold blue] {path}")
    
    try:
        workspace = FLYNCWorkspace.load_workspace(
            workspace_name=path.name,
            workspace_path=path,
            strict=False,
        )
        
        if workspace.load_errors:
            console.print(f"\n[bold red]✗ Validation failed with {len(workspace.load_errors)} error(s)[/bold red]")
            
            table = Table(show_header=True, header_style="bold red")
            table.add_column("Error Type", style="red")
            table.add_column("Location", style="yellow")
            table.add_column("Message", style="white")
            
            for error in workspace.load_errors:
                error_type = error.get('type', 'unknown')
                loc = format_error_location(error.get('loc', []))
                msg = error.get('msg', 'Unknown error')
                table.add_row(error_type, loc, msg)
            
            console.print(table)
            return False
        else:
            console.print("\n[bold green]✓ Workspace is valid![/bold green]")
            
            if workspace.flync_model:
                console.print(f"\n[bold]Summary:[/bold]")
                console.print(f"  ECUs: {len(workspace.flync_model.ecus)}")
                console.print(f"  Controllers: {len(workspace.flync_model.get_all_controllers())}")
                console.print(f"  Interfaces: {len(workspace.flync_model.get_all_interfaces())}")
            
            return True
            
    except Exception as e:
        console.print(f"\n[bold red]✗ Error loading workspace:[/bold red] {e}")
        return False


def validate_partial(model_type: str, path: Path) -> bool:
    """Validate a partial configuration."""
    console.print(f"\n[bold blue]Validating {model_type}:[/bold blue] {path}")
    
    # Get model class
    if model_type in MODEL_TYPES:
        model_class_path = MODEL_TYPES[model_type]
    else:
        model_class_path = model_type
    
    try:
        model_class = import_model_class(model_class_path)
    except (ImportError, AttributeError) as e:
        console.print(f"[bold red]✗ Cannot import model class {model_class_path}:[/bold red] {e}")
        return False
    
    # Validate
    validator = PartialConfigValidator()
    result = validator.validate_from_file(model_class, path)
    
    if validator.has_errors():
        console.print(f"\n[bold red]✗ Validation failed with {len(validator.errors)} error(s)[/bold red]")
        
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Error Type", style="red")
        table.add_column("Location", style="yellow")
        table.add_column("Message", style="white")
        
        for error in validator.errors:
            error_type = error.get('type', 'unknown')
            loc = format_error_location_with_data(
                error.get('loc', []),
                validator._last_validated_data
            )
            msg = error.get('msg', 'Unknown error')
            table.add_row(error_type, loc, msg)
        
        console.print(table)
        return False
    else:
        console.print("\n[bold green]✓ Configuration is valid![/bold green]")
        
        if result and hasattr(result, 'name'):
            console.print(f"  Name: {result.name}")
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Validate FLYNC configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate complete workspace
  %(prog)s workspace /path/to/config
  
  # Validate single ECU
  %(prog)s ecu /path/to/ecu.flync.yaml
  
  # Validate MACSec configuration
  %(prog)s macsec /path/to/macsec.flync.yaml
  
  # Validate custom model type
  %(prog)s model flync.model.flync_4_tsn.QoS /path/to/qos.flync.yaml

Supported partial types:
  ecu, macsec, firewall, someip, qos, ptp, controller, switch
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Workspace validation
    workspace_parser = subparsers.add_parser('workspace', help='Validate complete workspace')
    workspace_parser.add_argument('path', type=Path, help='Path to workspace')
    
    # Partial validation shortcuts
    for model_name in MODEL_TYPES.keys():
        partial_parser = subparsers.add_parser(model_name, help=f'Validate {model_name} configuration')
        partial_parser.add_argument('path', type=Path, help=f'Path to {model_name} configuration file')
    
    # Generic model validation
    model_parser = subparsers.add_parser('model', help='Validate any model type')
    model_parser.add_argument('type', help='Model class path (e.g., flync.model.flync_4_ecu.ECU)')
    model_parser.add_argument('path', type=Path, help='Path to configuration file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    if args.command == 'workspace':
        success = validate_workspace(args.path)
    elif args.command == 'model':
        success = validate_partial(args.type, args.path)
    elif args.command in MODEL_TYPES:
        success = validate_partial(args.command, args.path)
    else:
        console.print(f"[bold red]Unknown command: {args.command}[/bold red]")
        sys.exit(1)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
