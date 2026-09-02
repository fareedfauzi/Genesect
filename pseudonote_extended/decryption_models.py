# -*- coding: utf-8 -*-
import typing
from dataclasses import dataclass, field

@dataclass
class DecryptionTarget:
    source_kind: str              # string, data, global, immediate, local, selection
    view_kind: str                # pseudocode, disassembly, hex
    start_ea: typing.Optional[int]
    end_ea: typing.Optional[int]
    function_ea: typing.Optional[int]
    expression_ea: typing.Optional[int]
    item_width: int               # 1, 2, 4, or 8
    count: int
    raw_bytes: bytes
    original_value: typing.Optional[int]
    signed: typing.Optional[bool]
    byte_order: str               # little or big
    ida_type: str
    display_name: str
    patchability: str             # exact, comment_only, unsupported
    patch_reason: str
    selection_text: str
    provenance: typing.List[str]

@dataclass
class DecryptionParameters:
    algorithm_id: str
    mode: str
    direction: str                # decrypt/decode or encode
    item_width: int
    byte_order: str
    key_bytes: typing.Optional[bytes]
    key_provenance: str
    iv_bytes: typing.Optional[bytes]
    iv_provenance: str
    round_count: typing.Optional[int]
    delta: typing.Optional[int]
    rotation: typing.Optional[int]
    arithmetic_mask: typing.Optional[int]
    input_offset: int
    input_count: int
    termination_rule: str
    padding_policy: str
    expected_encoding: str

@dataclass
class DecryptionCandidate:
    engine: str                   # known or AI
    algorithm_family: str
    exact_variant: str
    parameters: DecryptionParameters
    generated_script: str
    script_hash: str
    evidence_list: typing.List[str]
    confidence: int
    output_bytes: bytes
    decoded_representations: typing.Dict[str, str]
    quality_score: int
    warnings: typing.List[str]
    execution_duration_ms: int
    error: str

@dataclass
class DecryptionAuditRecord:
    timestamp: str
    target_provenance: typing.List[str]
    original_bytes_sha256: str
    engine: str
    algorithm: str
    parameters_dict: typing.Dict[str, typing.Any]
    prompt_metadata: typing.Optional[typing.Dict[str, typing.Any]]
    script_sha256: str
    output_sha256: str
    output_length: int
    decision: str                 # comment, patch, copy, export
    patch_verified: bool
    failure_reason: str
