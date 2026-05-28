from models import Component, Threat
from typing import List

STRIDE_RULES = {
    "process": [
        {
            "category": "Spoofing",
            "condition": lambda c: True,
            "title": "Process Identity Spoofing",
            "description": "An attacker could impersonate this process to other components.",
            "risk": "HIGH",
            "mitigation": "Implement mutual authentication (mTLS, API keys, OAuth2).",
        },
        {
            "category": "Tampering",
            "condition": lambda c: True,
            "title": "Process Input Tampering",
            "description": "Inputs to this process may be manipulated to alter behavior.",
            "risk": "HIGH",
            "mitigation": "Validate and sanitize all inputs. Use integrity checks (HMAC).",
        },
        {
            "category": "Elevation of Privilege",
            "condition": lambda c: c.is_internet_facing,
            "title": "Privilege Escalation via Internet-Facing Process",
            "description": "Internet exposure increases the attack surface for privilege escalation.",
            "risk": "HIGH",
            "mitigation": "Apply least privilege, use containerization, and WAF protection.",
        },
    ],
    "datastore": [
        {
            "category": "Information Disclosure",
            "condition": lambda c: c.stores_sensitive_data,
            "title": "Sensitive Data Exposure",
            "description": "Sensitive data stored here could be exfiltrated by an attacker.",
            "risk": "HIGH",
            "mitigation": "Encrypt data at rest (AES-256). Apply strict access controls.",
        },
        {
            "category": "Tampering",
            "condition": lambda c: True,
            "title": "Data Store Integrity Violation",
            "description": "An attacker could modify stored records to corrupt system state.",
            "risk": "MEDIUM",
            "mitigation": "Use audit logs, checksums, and DB-level access restrictions.",
        },
        {
            "category": "Repudiation",
            "condition": lambda c: True,
            "title": "Missing Audit Trail",
            "description": "No proof of who accessed or modified data in this store.",
            "risk": "MEDIUM",
            "mitigation": "Enable database audit logging and write-protected log storage.",
        },
    ],
    "dataflow": [
        {
            "category": "Information Disclosure",
            "condition": lambda c: True,
            "title": "Unencrypted Data in Transit",
            "description": "Data flowing through this channel may be intercepted.",
            "risk": "HIGH",
            "mitigation": "Enforce TLS 1.2+ on all data flows. Disable plaintext protocols.",
        },
        {
            "category": "Denial of Service",
            "condition": lambda c: c.is_internet_facing,
            "title": "Data Flow Flooding / DoS",
            "description": "This flow could be flooded to exhaust system resources.",
            "risk": "MEDIUM",
            "mitigation": "Implement rate limiting, throttling, and circuit breakers.",
        },
    ],
    "external_entity": [
        {
            "category": "Spoofing",
            "condition": lambda c: True,
            "title": "External Entity Impersonation",
            "description": "This external entity could be spoofed by a malicious actor.",
            "risk": "HIGH",
            "mitigation": "Verify identity using certificates or signed tokens (JWT).",
        },
        {
            "category": "Repudiation",
            "condition": lambda c: True,
            "title": "Unverifiable External Actions",
            "description": "Actions by this entity cannot be tied to a verified identity.",
            "risk": "MEDIUM",
            "mitigation": "Log all interactions with timestamps and authenticated identifiers.",
        },
    ],
}

RISK_SCORE = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

def analyze(components: List[Component]) -> List[Threat]:
    threats = []
    for component in components:
        rules = STRIDE_RULES.get(component.component_type, [])
        for rule in rules:
            if rule["condition"](component):
                threats.append(Threat(
                    stride_category=rule["category"],
                    title=rule["title"],
                    affected_component=component.name,
                    description=rule["description"],
                    risk_level=rule["risk"],
                    mitigation=rule["mitigation"],
                ))
    threats.sort(key=lambda t: RISK_SCORE.get(t.risk_level, 0), reverse=True)
    return threats