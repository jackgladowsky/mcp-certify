package mcpcertify

# ============================================================================
# MCP Server Security Policy
# Default rule set for mcp-certify OPA integration
# ============================================================================

# --------------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------------

# Check if a string contains any element from a set (case-insensitive)
contains_any(str, patterns) {
    contains(str, patterns[_])
}

# Check if a tool description references an approved host
approved_host(desc) {
    approved := {"localhost", "127.0.0.1", "example.com"}
    host := approved[_]
    contains(desc, host)
}

# Normalize a tool name to lowercase for comparison
is_exact_match(name, pattern) {
    lower(name) == pattern
}

# Check if a tool has the readOnlyHint annotation explicitly set to false
has_mutation_annotation(tool) {
    tool.annotations.readOnlyHint == false
}

# --------------------------------------------------------------------------
# Rule: No tools should reference sensitive file paths
# Severity: high
# --------------------------------------------------------------------------

deny_sensitive_paths[msg] {
    tool := input.tools[_]
    sensitive := ["~/.ssh", "~/.aws", "~/.gnupg", "/etc/passwd", "/etc/shadow", ".env"]
    path := sensitive[_]
    contains(tool.description, path)
    msg := sprintf("Tool '%s' references sensitive path '%s' in description", [tool.name, path])
}

# Also check input schema descriptions for sensitive paths
deny_sensitive_paths[msg] {
    tool := input.tools[_]
    sensitive := ["~/.ssh", "~/.aws", "~/.gnupg", "/etc/passwd", "/etc/shadow", ".env"]
    path := sensitive[_]
    prop := tool.inputSchema.properties[prop_name]
    contains(prop.description, path)
    msg := sprintf("Tool '%s' parameter '%s' references sensitive path '%s'", [tool.name, prop_name, path])
}

# --------------------------------------------------------------------------
# Rule: No outbound network except approved hosts
# Severity: high
# --------------------------------------------------------------------------

deny_unapproved_network[msg] {
    tool := input.tools[_]
    regex.match(`https?://[^\s"')]+`, tool.description)
    not approved_host(tool.description)
    msg := sprintf("Tool '%s' references unapproved external host in description", [tool.name])
}

# Check for URLs in custom allow/deny lists if provided
deny_unapproved_network[msg] {
    tool := input.tools[_]
    count(input.deny_hosts) > 0
    host := input.deny_hosts[_]
    contains(tool.description, host)
    msg := sprintf("Tool '%s' references denied host '%s'", [tool.name, host])
}

# --------------------------------------------------------------------------
# Rule: Mutation-capable tools must be explicitly declared
# Severity: medium
# --------------------------------------------------------------------------

deny_undeclared_mutations[msg] {
    tool := input.tools[_]
    mutation_patterns := ["write", "delete", "update", "create", "modify", "remove", "drop", "insert", "put", "patch", "set"]
    pattern := mutation_patterns[_]
    contains(lower(tool.name), pattern)
    not has_mutation_annotation(tool)
    msg := sprintf("Tool '%s' appears mutation-capable but lacks explicit readOnlyHint annotation", [tool.name])
}

# Also flag tools whose descriptions suggest mutations without annotation
deny_undeclared_mutations[msg] {
    tool := input.tools[_]
    mutation_desc_patterns := ["will delete", "will modify", "will update", "will create", "will remove", "will overwrite", "writes to", "mutates"]
    pattern := mutation_desc_patterns[_]
    contains(lower(tool.description), pattern)
    not has_mutation_annotation(tool)
    msg := sprintf("Tool '%s' description suggests mutation capability but lacks explicit readOnlyHint annotation", [tool.name])
}

# --------------------------------------------------------------------------
# Rule: No command execution tools
# Severity: critical
# --------------------------------------------------------------------------

deny_command_execution[msg] {
    tool := input.tools[_]
    exec_patterns := ["exec", "execute", "eval", "shell", "bash", "cmd", "run_command", "run_shell", "run_script"]
    pattern := exec_patterns[_]
    is_exact_match(tool.name, pattern)
    msg := sprintf("Tool '%s' provides direct command execution capability", [tool.name])
}

# Also detect tools with shell-like names using common separators
deny_command_execution[msg] {
    tool := input.tools[_]
    exec_roots := ["exec", "execute", "eval", "shell", "bash", "cmd"]
    root := exec_roots[_]
    startswith(lower(tool.name), concat("", [root, "_"]))
    msg := sprintf("Tool '%s' appears to provide command execution capability", [tool.name])
}

deny_command_execution[msg] {
    tool := input.tools[_]
    exec_roots := ["exec", "execute", "eval", "shell", "bash", "cmd"]
    root := exec_roots[_]
    startswith(lower(tool.name), concat("", [root, "-"]))
    msg := sprintf("Tool '%s' appears to provide command execution capability", [tool.name])
}

# --------------------------------------------------------------------------
# Rule: All tools must have input schemas
# Severity: medium
# --------------------------------------------------------------------------

deny_missing_schema[msg] {
    tool := input.tools[_]
    not tool.inputSchema
    msg := sprintf("Tool '%s' has no input schema defined", [tool.name])
}

# Also flag empty schemas (type object with no properties)
deny_missing_schema[msg] {
    tool := input.tools[_]
    tool.inputSchema
    tool.inputSchema.type == "object"
    not tool.inputSchema.properties
    msg := sprintf("Tool '%s' has an empty input schema with no properties", [tool.name])
}

# --------------------------------------------------------------------------
# Aggregate all violations with severity and rule metadata
# --------------------------------------------------------------------------

violations[v] {
    msg := deny_sensitive_paths[_]
    v := {"msg": msg, "severity": "high", "rule": "sensitive-paths"}
}

violations[v] {
    msg := deny_unapproved_network[_]
    v := {"msg": msg, "severity": "high", "rule": "unapproved-network"}
}

violations[v] {
    msg := deny_undeclared_mutations[_]
    v := {"msg": msg, "severity": "medium", "rule": "undeclared-mutations"}
}

violations[v] {
    msg := deny_command_execution[_]
    v := {"msg": msg, "severity": "critical", "rule": "command-execution"}
}

violations[v] {
    msg := deny_missing_schema[_]
    v := {"msg": msg, "severity": "medium", "rule": "missing-schema"}
}

# --------------------------------------------------------------------------
# Summary helpers
# --------------------------------------------------------------------------

# Count of violations by severity
violation_count[sev] = num {
    severities := {"critical", "high", "medium", "low", "info"}
    sev := severities[_]
    num := count([v | v := violations[_]; v.severity == sev])
}

# Overall pass/fail
policy_pass {
    count(violations) == 0
}
