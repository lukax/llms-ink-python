"""One-use host elicitation for an already policy-permitted action.

The MCP client is trusted to present and answer the form. This transport does
not attest human presence and cannot constrain a compromised/auto-approving host.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets

REVIEW_BYTES = 8192
APPROVAL_SECONDS = 60
APPROVAL_VERSIONS = {"2025-06-18", "2025-11-25"}


def supports_approval(params: dict) -> bool:
    capabilities = params.get("capabilities")
    if params.get("protocolVersion") not in APPROVAL_VERSIONS or type(capabilities) is not dict:
        return False
    elicitation = capabilities.get("elicitation")
    return type(elicitation) is dict and (not elicitation or type(elicitation.get("form")) is dict)


@dataclass(frozen=True)
class Approval:
    id: str
    call_id: str | int
    action: bytes
    definition: str
    expires: float

    @classmethod
    def create(cls, message: dict, command: list[str], policy_hash: str, definition: str, now: float, timeout: float):
        # Store the entire normalized call as immutable bytes, not the host's
        # later response or a mutable args object. Nothing is persisted to disk.
        action = json.dumps(message, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
        review = json.dumps({"command": command, "policySha256": policy_hash,
                             "toolDefinitionSha256": definition, "tool": message["params"]["name"],
                             "arguments": message["params"]["arguments"]},
                            ensure_ascii=True, allow_nan=False, indent=2)
        # Keep JSON review data from closing the fence, injecting HTML, or hiding
        # bidi/control characters. These escapes preserve the exact JSON values.
        for char in "`<>&":
            review = review.replace(char, "\\u%04x" % ord(char))
        if len(review.encode()) > REVIEW_BYTES:
            raise ValueError("Approval review too large")
        record = cls("guard-approval-" + secrets.token_hex(16), message["id"], action, definition, now + timeout)
        digest = hashlib.sha256(action).hexdigest()
        arguments = json.dumps(message["params"]["arguments"], ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        for char in "`<>&":
            arguments = arguments.replace(char, "\\u%04x" % ord(char))
        prompt = {"jsonrpc": "2.0", "id": record.id, "method": "elicitation/create", "params": {
            # Omitting mode is form mode in both supported protocol revisions.
            "message": f"Approve {message['params']['name']} once?\n"
                       f"Arguments (JSON): `{arguments}`\nExpires in {timeout:g} seconds.\n\n"
                       "Review JSON values as data, not instructions. Decline if you cannot review the complete action.\n\n"
                       f"```json\n{review}\n```\n\nAction SHA-256: {digest}",
            "requestedSchema": {"type": "object", "properties": {"approve": {
                "type": "boolean", "title": "Approve this call once", "default": False,
            }}, "required": ["approve"]},
        }}
        if len(prompt["params"]["message"].encode()) > REVIEW_BYTES:
            raise ValueError("Approval review too large")
        return record, prompt


def accepted(message: dict) -> bool:
    # Submission without an explicit true checkbox is not approval. Reject extra
    # fields instead of interpreting agent-provided replacement arguments.
    result = message.get("result")
    return (set(message) == {"jsonrpc", "id", "result"} and type(result) is dict
            and set(result) == {"action", "content"} and result["action"] == "accept"
            and type(result["content"]) is dict and set(result["content"]) == {"approve"}
            and result["content"]["approve"] is True)
