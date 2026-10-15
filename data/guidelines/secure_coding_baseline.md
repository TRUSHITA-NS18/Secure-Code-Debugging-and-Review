# Input validation and bounds
Validate external input at trust boundaries. Check array indexes and buffer lengths before access. Test zero, minimum, maximum, and over-maximum values.

# Secrets management
Do not commit passwords, tokens, private keys, or production connection strings. Rotate exposed secrets and use the organization-approved secret-management process.

# Command execution
Avoid shell command construction with untrusted input. Prefer argument APIs, allowlists, and avoiding shell invocation where possible.

# Pointer and resource lifetime
Define pointer ownership and lifetime. Check API return values and validate nullable pointers before dereference. Pair resource acquisition with cleanup on success and error paths.

# Defensive error handling
Handle errors explicitly and do not ignore return codes from safety-relevant operations.

# Review and compliance
AI-generated observations are candidates only. A qualified reviewer must validate evidence and proposed changes. This is illustrative starter guidance, not an approved MISRA or organizational standard.
