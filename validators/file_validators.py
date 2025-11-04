"""
file_validators.py
-------------------
Responsible for validating the existence, readability, and integrity of file paths 
and file-based inputs across the Kalitool_Autobot project.
"""

import os
import logging

logger = logging.getLogger(__name__)


def validate_file_exists(file_path: str) -> bool:
    """
    Check if the specified file exists.

    Args:
        file_path (str): Path to the file.

    Returns:
        bool: True if file exists, otherwise raises FileNotFoundError.
    """
    if not os.path.isfile(file_path):
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(f"File not found: {file_path}")
    logger.debug(f"File exists: {file_path}")
    return True


def validate_file_extension(file_path: str, allowed_extensions: list) -> bool:
    """
    Validate that the file has an allowed extension.

    Args:
        file_path (str): Path to the file.
        allowed_extensions (list): List of allowed file extensions (e.g., ['.yaml', '.txt']).

    Returns:
        bool: True if valid, otherwise raises ValueError.
    """
    _, ext = os.path.splitext(file_path)
    if ext.lower() not in [e.lower() for e in allowed_extensions]:
        logger.error(f"Invalid file extension '{ext}'. Allowed: {allowed_extensions}")
        raise ValueError(f"Invalid file extension '{ext}'. Allowed: {allowed_extensions}")
    logger.debug(f"Valid file extension: {ext}")
    return True


def validate_file_readable(file_path: str) -> bool:
    """
    Ensure that the file is readable by the current user.

    Args:
        file_path (str): Path to the file.

    Returns:
        bool: True if readable, otherwise raises PermissionError.
    """
    if not os.access(file_path, os.R_OK):
        logger.error(f"File is not readable: {file_path}")
        raise PermissionError(f"File is not readable: {file_path}")
    logger.debug(f"File is readable: {file_path}")
    return True


def validate_directory_exists(directory_path: str) -> bool:
    """
    Validate that the given directory exists.

    Args:
        directory_path (str): Path to the directory.

    Returns:
        bool: True if exists, otherwise raises FileNotFoundError.
    """
    if not os.path.isdir(directory_path):
        logger.error(f"Directory not found: {directory_path}")
        raise FileNotFoundError(f"Directory not found: {directory_path}")
    logger.debug(f"Directory exists: {directory_path}")
    return True


def validate_writable_directory(directory_path: str) -> bool:
    """
    Ensure that the directory is writable by the current user.

    Args:
        directory_path (str): Path to the directory.

    Returns:
        bool: True if writable, otherwise raises PermissionError.
    """
    if not os.access(directory_path, os.W_OK):
        logger.error(f"Directory is not writable: {directory_path}")
        raise PermissionError(f"Directory is not writable: {directory_path}")
    logger.debug(f"Directory is writable: {directory_path}")
    return True
