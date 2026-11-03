"""Framework mappings: MITRE ATLAS techniques/mitigations, NIST AI RMF, OWASP LLM Top 10.

ATLAS identifiers and names were checked against the ATLAS data release
v5.6.0 (mitre-atlas/atlas-data, dist/ATLAS.yaml). NIST AI RMF references are
to AI RMF 1.0 (NIST AI 100-1) core functions and the Generative AI Profile
(NIST AI 600-1) risk "Information Security". OWASP references are to the
2025 OWASP Top 10 for LLM Applications.
"""

ATLAS_TECHNIQUES = {
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0052": "Phishing",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    "AML.T0074": "Masquerading",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
}

# Defense layer -> ATLAS mitigations it implements
LAYER_MITIGATIONS = {
    "input_guard": ["AML.M0015 Adversarial Input Detection", "AML.M0020 Generative AI Guardrails"],
    "output_guard": ["AML.M0020 Generative AI Guardrails", "AML.M0033 Input and Output Validation for AI Agent Components"],
    "allowlist": ["AML.M0028 AI Agent Tools Permissions Configuration", "AML.M0027 Single-User AI Agent Permissions Configuration"],
    "policy": ["AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data", "AML.M0026 Privileged AI Agent Permissions Configuration"],
    "approval": ["AML.M0029 Human In-the-Loop for AI Agent Actions"],
    "trace": ["AML.M0024 AI Telemetry Logging"],
}

# Attack category -> where it lands in the NIST AI RMF and why
CATEGORY_RMF = {
    "direct_injection": ["MAP: threat model includes the user as adversary", "MEASURE 2.7: security and resilience evaluated", "MANAGE: refuse or constrain at the input boundary"],
    "indirect_injection": ["MAP: third-party content (RAG, web, email) is an attack surface", "MEASURE 2.7: security and resilience evaluated", "MANAGE: treat tool output as untrusted data"],
    "exfiltration": ["MEASURE 2.7", "MEASURE 2.10: privacy risk examined", "MANAGE: egress controls and data-flow (taint) policy"],
    "privilege_escalation": ["GOVERN: roles, entitlements and accountability for agent actions", "MEASURE 2.7", "MANAGE: least privilege and human approval for privileged tools"],
    "jailbreak": ["MEASURE 2.7", "MEASURE 2.6: safety risks evaluated", "MANAGE: guardrails and output review"],
    "integrity": ["MAP: provenance of retrieved knowledge", "MEASURE 2.5: validity and reliability", "MANAGE: provenance-aware retrieval; no layer here addresses it"],
    "utility": ["MEASURE: cost of controls on legitimate use"],
}

OWASP = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM09": "Misinformation",
}
