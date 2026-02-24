"""Probe registry for llm-audit."""

from llm_audit.probes.base import BaseProbe
from llm_audit.probes.data_leakage import DataLeakageProbe
from llm_audit.probes.indirect_injection import IndirectInjectionProbe
from llm_audit.probes.insecure_output import InsecureOutputProbe
from llm_audit.probes.jailbreak import JailbreakProbe
from llm_audit.probes.prompt_injection import PromptInjectionProbe
from llm_audit.probes.excessive_agency import ExcessiveAgencyProbe
from llm_audit.probes.model_dos import ModelDoSProbe
from llm_audit.probes.training_data_extraction import TrainingDataExtractionProbe

ALL_PROBES: dict[str, type[BaseProbe]] = {
    "prompt_injection": PromptInjectionProbe,
    "indirect_injection": IndirectInjectionProbe,
    "jailbreak": JailbreakProbe,
    "data_leakage": DataLeakageProbe,
    "insecure_output": InsecureOutputProbe,
    "training_data_extraction": TrainingDataExtractionProbe,
    "model_dos": ModelDoSProbe,
    "excessive_agency": ExcessiveAgencyProbe,
}

__all__ = [
    "BaseProbe",
    "PromptInjectionProbe",
    "IndirectInjectionProbe",
    "JailbreakProbe",
    "DataLeakageProbe",
    "InsecureOutputProbe",
    "TrainingDataExtractionProbe",
    "ModelDoSProbe",
    "ExcessiveAgencyProbe",
    "ALL_PROBES",
]
