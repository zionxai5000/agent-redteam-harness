# Tool-call authorization policy for a tool-using LLM agent.
# Rule order matters: the first matching rule wins (else-chain).
# Mirrors arh/defenses/policy.py; tests/test_policy.py checks parity with OPA.
#
#   opa eval -d policies/agent.rego -d policy_data.json -I 'data.arh.agent.decision'
package arh.agent

import rego.v1

default decision := {"effect": "allow", "rule": "default_allow"}

call := input.call

ctx := input.context

pol := data.policy

decision := {"effect": "deny", "rule": "least_privilege"} if {
	ctx.enforce_scope
	not call.tool in ctx.scope
} else := {"effect": "deny", "rule": "path_denied"} if {
	call.tool == "read_file"
	some pattern in pol.deny_paths
	glob.match(pattern, null, call.args.path) # null: "*" may cross any char, like fnmatch
} else := {"effect": "deny", "rule": "egress_host"} if {
	call.tool == "fetch_url"
	not ctx.derived.host in pol.allowed_fetch_hosts
} else := {"effect": "deny", "rule": "taint_egress_url"} if {
	call.tool == "fetch_url"
	ctx.derived.has_query
	tainted
} else := {"effect": "deny", "rule": "egress_domain"} if {
	call.tool == "send_email"
	not ctx.derived.domain in pol.allowed_email_domains
} else := {"effect": "deny", "rule": "taint_egress_email"} if {
	call.tool == "send_email"
	tainted
	not call.args.to in ctx.user_named.recipients
} else := {"effect": "require_approval", "rule": "privileged_tool"} if {
	call.tool in pol.privileged_tools
} else := {"effect": "require_approval", "rule": "unbound_recipient"} if {
	call.tool == "send_email"
	not call.args.to in ctx.user_named.recipients
}

tainted if {
	some label in ctx.taint
	label in pol.sensitive_labels
}
