"""Advanced utilities module for RansomwareDefenseKit

Exports:
- process_utils: Process monitoring and behavioral analysis
- hashing: Advanced file hashing with performance optimization
- logger: High-performance buffered event logging
"""

from .process_utils import (
    ProcessBehaviorMonitor,
    get_process_info,
    terminate_process
)

from .hashing import (
    compute_hash,
    compute_multi_hash,
    verify_file_integrity,
    batch_hash_files,
    get_file_signature,
    SUPPORTED_ALGORITHMS,
    CHUNK_SIZE
)

from .logger import EventLogger

__all__ = [
    # Process utilities
    'ProcessBehaviorMonitor',
    'get_process_info',
    'terminate_process',
    
    # Hashing utilities
    'compute_hash',
    'compute_multi_hash',
    'verify_file_integrity',
    'batch_hash_files',
    'get_file_signature',
    'SUPPORTED_ALGORITHMS',
    'CHUNK_SIZE',
    
    # Logging
    'EventLogger'
]