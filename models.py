from dataclasses import dataclass, field
from typing import List

@dataclass
class Component:
    name: str
    component_type: str
    description: str
    technologies: List[str] = field(default_factory=list)
    is_internet_facing: bool = False
    stores_sensitive_data: bool = False

@dataclass
class Threat:
    stride_category: str
    title: str
    affected_component: str
    description: str
    risk_level: str
    mitigation: str
    cve_reference: str = ""
