"""
Standalone model validation utilities for FLYNC.

This module provides utilities to validate partial FLYNC configurations
without requiring a complete FLYNCModel workspace. Useful for:
- Validating individual ECUs
- Validating security configurations (MACSec, Firewall)
- Validating SOME/IP services
- Testing and development workflows
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar, Union, Tuple

import yaml
from pydantic import ValidationError
from pydantic_core import ErrorDetails

from flync.core.base_models.base_model import FLYNCBaseModel
from flync.core.utils.exceptions_handling import validate_with_policy

T = TypeVar('T', bound=FLYNCBaseModel)


def format_error_location_with_data(
    error_loc: Tuple[Union[int, str], ...],
    data: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Format error location using actual values from the data when possible.
    
    This function tries to resolve indices/keys to actual values like names
    or identifiers, making the error location much more meaningful.
    
    Examples:
        Given data with switches[0].name = 'hpc_switch1':
        ('switches', 0, 'ingress_streams', 'stream_0', 'drop_at_ingress')
        → 'hpc_switch1 - ingress_streams - stream_0 - drop_at_ingress'
        
        Without data, falls back to bracket notation:
        → 'switches[0] - ingress_streams - stream_0 - drop_at_ingress'
    
    Args:
        error_loc: Location tuple from Pydantic error
        data: The data being validated (dict from YAML/JSON)
        
    Returns:
        Human-readable location string with actual values when possible
    """
    if not error_loc:
        return "<root>"
    
    if data is None:
        # Fallback to bracket notation
        return format_error_location(error_loc)
    
    parts = []
    current = data
    
    for i, item in enumerate(error_loc):
        if isinstance(item, int):
            # Try to get the item from the current level
            try:
                if isinstance(current, list) and 0 <= item < len(current):
                    list_item = current[item]
                    # Try to get a name/id/identifier from this item
                    identifier = _get_identifier(list_item)
                    if identifier:
                        parts.append(identifier)
                        current = list_item
                    else:
                        # Fallback: show index
                        if parts:
                            parts[-1] = f"{parts[-1]}[{item}]"
                        else:
                            parts.append(f"[{item}]")
                        current = list_item
                else:
                    # Index out of range, show as bracket
                    if parts:
                        parts[-1] = f"{parts[-1]}[{item}]"
                    else:
                        parts.append(f"[{item}]")
            except (TypeError, IndexError, KeyError):
                # Can't access, show bracket notation
                if parts:
                    parts[-1] = f"{parts[-1]}[{item}]"
                else:
                    parts.append(f"[{item}]")
        else:
            # String key - just add it
            parts.append(str(item))
            # Navigate to next level
            try:
                if isinstance(current, dict):
                    current = current.get(item)
                elif isinstance(current, list):
                    # Can't navigate further in list with string key
                    current = None
            except (TypeError, KeyError):
                current = None
    
    return " → ".join(parts)


def _get_identifier(item: Any) -> Optional[str]:
    """
    Extract a human-readable identifier from a list item.
    
    Tries these in order:
    1. 'name' field (most common in FLYNC)
    2. 'id' field
    3. 'key' field
    4. String representation if it looks like a name
    
    Args:
        item: The item to extract identifier from
        
    Returns:
        A string identifier, or None if not found
    """
    if not isinstance(item, dict):
        return None
    
    # Try common field names
    for field in ['name', 'id', 'key', 'identifier', 'label']:
        if field in item:
            value = item[field]
            if isinstance(value, (str, int)):
                return str(value)
    
    return None


def format_error_location(error_loc: Tuple[Union[int, str], ...]) -> str:
    """
    Format error location in a bracket notation.
    
    Converts Pydantic location tuples into readable paths with bracket notation.
    Examples:
        ('switches', 0, 'ingress_streams', 'stream_0', 'drop_at_ingress')
        → 'switches[0] - ingress_streams - stream_0 - drop_at_ingress'
    
    Args:
        error_loc: Location tuple from Pydantic error
        
    Returns:
        Human-readable location string
    """
    if not error_loc:
        return "<root>"
    
    parts = []
    for item in error_loc:
        if isinstance(item, int):
            # For list indices, show as [index]
            if parts:
                parts[-1] = f"{parts[-1]}[{item}]"
            else:
                parts.append(f"[{item}]")
        else:
            # For field names, show as separate segment
            parts.append(str(item))
    
    # Join with " - " for better readability
    return " - ".join(parts)


def format_error_location_simple(error_loc: Tuple[Union[int, str], ...]) -> str:
    """
    Format error location in dot notation.
    
    Examples:
        ('switches', 0) → 'switches.0'
        ('ingress_streams', 'stream_0') → 'ingress_streams.stream_0'
    
    Args:
        error_loc: Location tuple from Pydantic error
        
    Returns:
        Dot-notation location string
    """
    if not error_loc:
        return "<root>"
    
    return ".".join(str(x) for x in error_loc)


class PartialConfigValidator:
    """
    Validator for partial FLYNC configurations.
    
    Supports validation of individual model types without requiring
    a complete FLYNCModel workspace structure.
    
    Example:
        >>> validator = PartialConfigValidator()
        >>> ecu = validator.validate_from_file(ECU, "path/to/ecu_config.yaml")
        >>> macsec = validator.validate_from_dict(MACSec, macsec_data)
    """
    
    def __init__(self):
        self.errors: List[ErrorDetails] = []
        self.warnings: List[str] = []
        self._last_validated_data: Optional[Dict[str, Any]] = None
    
    def validate_from_file(
        self,
        model_class: Type[T],
        file_path: Union[str, Path],
    ) -> Optional[T]:
        """
        Validate a model from a YAML file.
        
        Args:
            model_class: The Pydantic model class to validate against
            file_path: Path to the YAML configuration file
            
        Returns:
            Validated model instance or None if validation failed
            
        Example:
            >>> from flync.model.flync_4_ecu import ECU
            >>> validator = PartialConfigValidator()
            >>> ecu = validator.validate_from_file(ECU, "my_ecu.flync.yaml")
            >>> if ecu:
            ...     print(f"Valid ECU: {ecu.name}")
            ... else:
            ...     print(f"Errors: {validator.errors}")
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.errors.append({
                'type': 'file_not_found',
                'msg': f"File not found: {file_path}",
                'loc': tuple(),
                'input': str(file_path),
            })
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            self.errors.append({
                'type': 'yaml_parse_error',
                'msg': f"YAML parsing failed: {e}",
                'loc': tuple(),
                'input': str(file_path),
            })
            return None
        
        return self.validate_from_dict(model_class, data)
    
    def validate_from_dict(
        self,
        model_class: Type[T],
        data: Dict[str, Any],
    ) -> Optional[T]:
        """
        Validate a model from a dictionary.
        
        Args:
            model_class: The Pydantic model class to validate against
            data: Dictionary containing configuration data
            
        Returns:
            Validated model instance or None if validation failed
            
        Example:
            >>> from flync.model.flync_4_security import MACSec
            >>> validator = PartialConfigValidator()
            >>> macsec_data = {
            ...     "cipher": {"type": "integrity_with_confidentiality"},
            ...     "key_length": 128
            ... }
            >>> macsec = validator.validate_from_dict(MACSec, macsec_data)
        """
        # Store data for error location formatting
        self._last_validated_data = data
        
        try:
            model, errors = validate_with_policy(model_class, data)
            self.errors.extend(errors)
            return model
        except ValidationError as e:
            self.errors.extend(e.errors())
            return None
    
    def validate_batch(
        self,
        model_class: Type[T],
        file_paths: List[Union[str, Path]],
    ) -> Dict[str, Optional[T]]:
        """
        Validate multiple files of the same model type.
        
        Args:
            model_class: The model class to validate against
            file_paths: List of file paths to validate
            
        Returns:
            Dictionary mapping file paths to validated models
            
        Example:
            >>> from flync.model.flync_4_ecu import ECU
            >>> validator = PartialConfigValidator()
            >>> ecu_files = ["ecu1.yaml", "ecu2.yaml", "ecu3.yaml"]
            >>> results = validator.validate_batch(ECU, ecu_files)
            >>> valid_ecus = {k: v for k, v in results.items() if v is not None}
        """
        results = {}
        for file_path in file_paths:
            file_path_str = str(file_path)
            results[file_path_str] = self.validate_from_file(
                model_class,
                file_path,
            )
        return results
    
    def has_errors(self) -> bool:
        """Check if any validation errors occurred."""
        return len(self.errors) > 0
    
    def get_error_summary(self) -> str:
        """Get a formatted summary of all errors with human-readable locations."""
        if not self.errors:
            return "No errors"
        
        summary_lines = [f"Found {len(self.errors)} validation error(s):"]
        for i, error in enumerate(self.errors, 1):
            # Use data-aware formatting if we have the data
            loc = format_error_location_with_data(
                error.get('loc', []),
                self._last_validated_data
            )
            msg = error.get('msg', 'Unknown error')
            error_type = error.get('type', 'unknown')
            summary_lines.append(
                f"  {i}. [{error_type}] {loc}: {msg}"
            )
        return "\n".join(summary_lines)
    
    def clear(self):
        """Clear all errors and warnings."""
        self.errors.clear()
        self.warnings.clear()


def validate_ecu(file_path: Union[str, Path]) -> Optional['ECU']:
    """
    Convenience function to validate a single ECU configuration.
    
    Args:
        file_path: Path to ECU YAML file
        
    Returns:
        Validated ECU instance or None
        
    Example:
        >>> from flync.sdk.validation import validate_ecu
        >>> ecu = validate_ecu("configs/my_ecu.flync.yaml")
        >>> if ecu:
        ...     print(f"ECU {ecu.name} is valid!")
    """
    from flync.model.flync_4_ecu import ECU
    validator = PartialConfigValidator()
    result = validator.validate_from_file(ECU, file_path)
    if validator.has_errors():
        print(validator.get_error_summary())
    return result


def validate_macsec(file_path: Union[str, Path]) -> Optional['MACSec']:
    """
    Convenience function to validate a MACSec configuration.
    
    Args:
        file_path: Path to MACSec YAML file
        
    Returns:
        Validated MACSec instance or None
        
    Example:
        >>> from flync.sdk.validation import validate_macsec
        >>> macsec = validate_macsec("configs/macsec.flync.yaml")
    """
    from flync.model.flync_4_security import MACSec
    validator = PartialConfigValidator()
    result = validator.validate_from_file(MACSec, file_path)
    if validator.has_errors():
        print(validator.get_error_summary())
    return result


def validate_firewall(file_path: Union[str, Path]) -> Optional['Firewall']:
    """
    Convenience function to validate a Firewall configuration.
    
    Args:
        file_path: Path to Firewall YAML file
        
    Returns:
        Validated Firewall instance or None
    """
    from flync.model.flync_4_security import Firewall
    validator = PartialConfigValidator()
    result = validator.validate_from_file(Firewall, file_path)
    if validator.has_errors():
        print(validator.get_error_summary())
    return result


def validate_someip_service(
    file_path: Union[str, Path]
) -> Optional['SOMEIPServiceInterface']:
    """
    Convenience function to validate a SOME/IP service configuration.
    
    Args:
        file_path: Path to SOME/IP service YAML file
        
    Returns:
        Validated service instance or None
    """
    from flync.model.flync_4_someip import SOMEIPServiceInterface
    validator = PartialConfigValidator()
    result = validator.validate_from_file(SOMEIPServiceInterface, file_path)
    if validator.has_errors():
        print(validator.get_error_summary())
    return result


def validate_model(
    model_class: Type[T],
    data: Union[Dict[str, Any], str, Path],
) -> Optional[T]:
    """
    Generic validation function for any FLYNC model.
    
    Args:
        model_class: The Pydantic model class to validate
        data: Either a dict, file path string, or Path object
        
    Returns:
        Validated model instance or None
        
    Example:
        >>> from flync.model.flync_4_tsn import QoS
        >>> from flync.sdk.validation import validate_model
        >>> 
        >>> # From file
        >>> qos = validate_model(QoS, "qos_config.yaml")
        >>> 
        >>> # From dict
        >>> qos_data = {"stream_reservation": [...]}
        >>> qos = validate_model(QoS, qos_data)
    """
    validator = PartialConfigValidator()
    
    if isinstance(data, (str, Path)):
        result = validator.validate_from_file(model_class, data)
    elif isinstance(data, dict):
        result = validator.validate_from_dict(model_class, data)
    else:
        raise ValueError(
            f"data must be dict, str, or Path, got {type(data)}"
        )
    
    if validator.has_errors():
        print(validator.get_error_summary())
    
    return result
