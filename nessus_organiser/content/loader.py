"""
nessus_organiser.content.loader

Load finding content definitions from YAML files.

This module provides helper functions for loading finding metadata used by 
reporting and analysis components.
"""

import yaml

from pathlib import Path


CONTENT_DIRECTORY = Path(__file__).parent


def _load_content(
    filename: str,
) -> dict:
    """
    Load a content definition file.

    Args:
        filename:
            YAML filename to load from the content directory.

    Returns:
        Parsed YAML content.

    Raises:
        FileNotFoundError:
            If the content file does not exist.

        ValueError:
            If the YAML file is empty.
    """

    path = CONTENT_DIRECTORY / filename

    with open(path, encoding="utf-8") as fp:
        content = yaml.safe_load(fp)

    if not content:
        raise ValueError(
            f"Content library '{filename}' is empty."
        )

    return content


def load_tls_content() -> dict:
    """
    Load TLS finding definitions.

    Returns:
        Dictionary containing TLS finding metadata loaded from tls.yml.
    """

    return _load_content("tls.yml")


def load_patch_management_content() -> dict:
    """
    Load patch management finding definitions.

    Returns:
        Dictionary containing patch management finding metadata loaded from
        patch_management.yml.
    """

    return _load_content("patching.yml")