# -*- coding: utf-8 -*-
import typing

class AlgorithmDefinition:
    def __init__(self, id, title, category, parameter_schema, availability, block_size, key_sizes, iv_sizes, transform):
        self.id = id
        self.title = title
        self.category = category
        self.parameter_schema = parameter_schema
        self.availability = availability
        self.block_size = block_size
        self.key_sizes = key_sizes
        self.iv_sizes = iv_sizes
        self.transform = transform

class DecryptionEngine:
    def __init__(self):
        self.registry = {}
        self._register_basics()

    def _register_basics(self):
        def _xor_repeating(data: bytes, params: dict) -> bytes:
            key = params.get("key", b"")
            if not key:
                return data
            out = bytearray()
            for i, b in enumerate(data):
                out.append(b ^ key[i % len(key)])
            return bytes(out)

        def _xor_single(data: bytes, params: dict) -> bytes:
            key = params.get("key", b"\x00")
            if not key: key = b"\x00"
            kb = key[0]
            return bytes([b ^ kb for b in data])

        self.registry["xor_single"] = AlgorithmDefinition(
            id="xor_single", title="XOR (Single Byte)", category="Basic",
            parameter_schema={"key": "byte"},
            availability=True, block_size=1, key_sizes=[1], iv_sizes=[0],
            transform=_xor_single
        )

        self.registry["xor_repeating"] = AlgorithmDefinition(
            id="xor_repeating", title="XOR (Repeating Key)", category="Basic",
            parameter_schema={"key": "bytes"},
            availability=True, block_size=1, key_sizes=[], iv_sizes=[0],
            transform=_xor_repeating
        )
        
        def _add_byte(data: bytes, params: dict) -> bytes:
            val = params.get("value", b"\x00")
            if not val: val = b"\x00"
            v = val[0]
            return bytes([(b + v) & 0xFF for b in data])

        self.registry["add_byte"] = AlgorithmDefinition(
            id="add_byte", title="ADD (Single Byte)", category="Basic",
            parameter_schema={"value": "byte"},
            availability=True, block_size=1, key_sizes=[1], iv_sizes=[0],
            transform=_add_byte
        )

        def _sub_byte(data: bytes, params: dict) -> bytes:
            val = params.get("value", b"\x00")
            if not val: val = b"\x00"
            v = val[0]
            return bytes([(b - v) & 0xFF for b in data])

        self.registry["sub_byte"] = AlgorithmDefinition(
            id="sub_byte", title="SUB (Single Byte)", category="Basic",
            parameter_schema={"value": "byte"},
            availability=True, block_size=1, key_sizes=[1], iv_sizes=[0],
            transform=_sub_byte
        )
    
    def run_algorithm(self, algo_id: str, data: bytes, params: dict) -> bytes:
        if algo_id not in self.registry:
            raise ValueError(f"Unknown algorithm: {algo_id}")
        algo = self.registry[algo_id]
        return algo.transform(data, params)

ENGINE = DecryptionEngine()
