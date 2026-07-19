"""Prompt templates for the maintained LAMD implementation.

The wording and decision criteria track the released research prototype. The
Tier-1 schema retains the paper's five dependency types and extends Parallel
relations to represent groups of two or more variables. JSON response shapes
let the pipeline parse model output deterministically.
"""

# Keep the released prompt wording intact; wrapping these lines would alter the
# exact text sent to the model.
# ruff: noqa: E501

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .models import ApiInfo
from .relations import Relation


def tier1_summary_prompt(cfg_content: str, api_signature: str) -> str:
    """Return the original function-level analysis prompt."""

    del api_signature  # The original summary prompt did not name the API.
    return f"""You are a cybersecurity expert specialized in Android malware analysis.

The provided control flow graph represents a slice of the function that includes the instructions related to sensitive API calls.
Analyze this function's control flow graph in detail.

=== Control Flow Graph ===
{cfg_content}

Please provide your analysis in the following format:

Function Purpose:
[Describe the function's behavior and purpose]

Control Flow Analysis:
[Describe the main flow of the function, including parameters, invoked functions, and return values]

Limit the output to 200 words.
"""


def tier1_prompt(cfg_content: str, api_signature: str) -> str:
    """Return the relation-aware function prompt with n-ary Parallel groups."""

    del api_signature  # The original relation prompt referred to the final invocation.
    return f"""You are a cybersecurity expert specialized in Android malware analysis.

The provided control flow graph represents a slice of the function that includes the instructions related to sensitive API calls.
Analyze this function's control flow graph in detail.

Additionally, identify variable relationships for each statement leading to the final invocation statement. Extract only the variable names (e.g., "r0", "$r1") without any additional fields or context.

Identify these FIVE types of relationships:

1. Direct Relationship:
   - Variables that used directly as function parameters in the final invocation statement
   - Example: In "invoke $r1.method(r2)", use only "$r1" and "r2" as variables

2. Transitive Relationship:
   - Variables whose values flow through assignments/operations to reach the final invocation but not directly used in the final invocation statement
   - Example: If "r2 = r3.getValue()" and later "invoke r1.method(r2)", use only "r3" as variable

3. Conditional Relationship:
   - Variables used in if/switch conditional statements
   - Example: If "if r4 == 0 goto invoke r1.method()", use only "r4" as variable

4. Parallel Relationship:
   - Groups of two or more variables that jointly participate in the same operation
   - For the final invocation, group all variable arguments into one Parallel relationship; exclude the receiver object and constants
   - For a computation, report all contributing source variables together; do not include the computed target variable
   - Example: If "r3 = r1 + r2", use variables=["r1", "r2"]
   - Example: For "virtualinvoke r0.send(r1, r2, r3)", use variables=["r1", "r2", "r3"] rather than pairwise combinations

5. Derived Relationship:
   - When one variable's value is derived from another variable through assignment or computation
   - Use only base variable names for both source and target
   - Example: If "r5 = r6.field", use target="r5", source="r6"

=== Control Flow Graph ===
{cfg_content}

Please provide your analysis in the following structure:
{{
  "functionPurpose": "Describe the function's behavior and purpose",
  "controlFlowAnalysis": "Describe the main flow of the function, including parameters, invoked functions, and return values",
  "relationships": [
    {{"type": "Direct", "variable": "varName"}},
    {{"type": "Transitive", "variable": "varName"}},
    {{"type": "Conditional", "variable": "varName"}},
    {{"type": "Parallel", "variables": ["firstVarName", "secondVarName", "additionalVarName"]}},
    {{"type": "Derived", "target": "targetVarName", "source": "sourceVarName"}}
  ]
}}

Ensure that:
- Only variable names are included (e.g., "r0", "$r1").
- No constants, additional fields or context are provided.
- All relevant variables for each statement are identified.
- Only relevant relationships are included. If a type has no applicable variables (e.g., conditional), omit it from the JSON.
- Do not include duplicate relationships.
"""


def revision_prompt(
    cfg_content: str,
    api_signature: str,
    original_summary: str,
    expected_relations: Iterable[Relation],
) -> str:
    """Correct a low-coverage summary while retaining the original prompt style.

    The released prototype did not expose a standalone correction template.
    This compatibility prompt is required by the maintained DRC correction
    stage and deliberately avoids adding new malware-classification guidance.
    """

    expected = [relation.to_dict() for relation in sorted(expected_relations)]
    return f"""You are a cybersecurity expert specialized in Android malware analysis.

The provided control flow graph represents a slice of the function that includes the instructions related to sensitive API calls.
Analyze this function's control flow graph in detail and correct the analysis using the verified variable relationships.

Sensitive API: {api_signature}

Verified relationships:
{json.dumps(expected, indent=2, sort_keys=True)}

Original analysis:
{original_summary}

=== Control Flow Graph ===
{cfg_content}

Please provide your corrected analysis in the following format:

Function Purpose:
[Describe the function's behavior and purpose]

Control Flow Analysis:
[Describe the main flow of the function, including parameters, invoked functions, and return values]

Limit the output to 200 words.
"""


def tier2_prompt(api: ApiInfo, contexts: Iterable[dict[str, Any]]) -> str:
    """Return the original API-level combined-analysis prompt."""

    permissions = ", ".join(api.permissions) if api.permissions else "None"
    sections: list[str] = []
    for index, context in enumerate(contexts, start=1):
        function_sections = []
        for function in context["functions"]:
            function_sections.append(f"Function: {function['name']}\n{function['summary']}")
        sections.append(
            f"=== Context #{index} ===\n"
            f"Call Graph:\n{context['call_graph']}\n\n"
            "Function Analyses:\n" + "\n\n".join(function_sections)
        )

    return f"""You are a cybersecurity expert specialized in Android malware analysis.

The provided data represents sensitive API usage in the Android application.
The function analyses are summaries of control flow graphs derived from program slicing that focus on instructions involving sensitive API calls, which may not contain full implementation details unrelated to sensitive APIs.

=== Sensitive API Information ===
API Name: {api.signature}
Required permissions: {permissions}

Using the provided call graphs and function analyses, provide a comprehensive analysis of the API usage.

=== Analysis of Each Context ===
{chr(10).join(sections)}

Please provide your analysis in the following format:

API Behavior:
[Describe the main functionality and behavior of this API in the context]

Implementation Analysis:
[Describe how the API is used in the application and if there are any indicators of malicious behavior based on the provided information only]

Limit the output to 200 words.
"""


def tier3_prompt(api_analyses: Iterable[dict[str, Any]]) -> str:
    """Return the original APK-level decision prompt with JSON transport."""

    sections = [
        f"Analysis #{index}:\n{item['analysis']}"
        for index, item in enumerate(api_analyses, start=1)
    ]
    return f"""You are a cybersecurity expert specialized in Android malware analysis.
Review all the analyses of sensitive API usages in this Android application to determine if it is MALWARE or BENIGN.
If it is MALWARE, state the type of malware. Choose one from the following list: ["Spyware", "Ransomware", "Adware", "Banker", "Trojan", "Downloader", "Miner", "Scareware", "Rootkit", "Botnet"]

Consider the following:
- Are there indicators of compromise?
- Is there evidence of malicious use for each API usage analyzed?
- If there are one or more malicious patterns and behaviors, classify the application as MALWARE.

=== Analysis Results ===
{chr(10).join(sections)}

Based on these provided analyses, provide a comprehensive security assessment. Return one JSON object with this structure:
{{
  "prediction": "MALWARE or BENIGN",
  "malware_type": "type of malware or null",
  "application_purpose": "main functionality and purpose of the application",
  "key_findings": ["critical point supporting the prediction", "critical point supporting the prediction"],
  "conclusion": "concise summary of the analysis and recommendation"
}}

Provide 2-3 key findings. Use null for malware_type when the prediction is BENIGN. Limit the output to 200 words.
"""


def flat_prompt(contexts: Iterable[dict[str, Any]]) -> str:
    """Return the original direct graph-analysis (LAMD-R) prompt."""

    sections: list[str] = []
    for context in contexts:
        permissions = ", ".join(context["permissions"]) or "None"
        for instance in context["instances"]:
            slices = "\n\n".join(f"Slice Graph:\n{item}" for item in instance["slices"])
            sections.append(
                f"=== API: {context['api']} ===\n"
                f"Required Permissions: {permissions}\n\n"
                f"Call Graph:\n{instance['call_graph']}\n\n"
                f"{slices}"
            )

    return f"""Act as a malware analyst by thoroughly examining this decompiled code. Methodically break down each step, focusing keenly on understanding the underlying logic and objective. Your task is to craft a detailed summary that encapsulates the code's behavior, pinpointing any malicious functionality. Start with a verdict (Benign or Malicious), then a list of activities including a list of IOCs if any URLs, created files, registry entries, mutex, network activity, etc.

{chr(10).join(sections)}

Return the result as one JSON object with keys "prediction", "malware_type", "application_purpose", "key_findings", and "conclusion". Use exactly "MALWARE" or "BENIGN" for prediction, provide 2-3 key findings, and use null for malware_type when the prediction is BENIGN.
"""
