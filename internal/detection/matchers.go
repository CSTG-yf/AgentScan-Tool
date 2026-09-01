// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// Shared matchers for the generic rule set. All matching is
// agent-agnostic: it inspects the unified event vocabulary
// (event_type / target / tool_name / operation / attributes), never
// product names.

// credentialPaths: files whose sole purpose is storing credentials.
// Reading them outside an explicit user flow is a credential_access
// signal. (~ expands for both POSIX and Windows home layouts.)
var credentialPathPatterns = []string{
	".aws/credentials",
	".netrc",
	".env",
	".npmrc",
	".pypirc",
	".kube/config",
	".docker/config.json",
	".git-credentials",
	".gitconfig",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	".ssh/authorized_keys",
	".azure/accessTokens.json",
	".azure/azureProfile.json",
	".gcloud/credentials.db",
	".config/gcloud/credentials.db",
	"credentials.json",
	"serviceaccount",
	"service_account",
	"sa_key",
	"gha_token",
}

// sensitivePathPatterns: system/secret material that is risky to read
// but not always credential-shaped (shadow, private keys, token
// caches, secret stores).
var sensitivePathPatterns = []string{
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/passwd",
	"~/.ssh",
	".ssh/id_",
	"private_key",
	"privatekey",
	"secrets.yml",
	"secrets.yaml",
	"secrets.json",
	"secret.key",
	"token.json",
	"tokens.json",
	".vault-token",
	"htpasswd",
	"wp-config.php",
	"settings.php",
}

// dangerousCommandRegexes: one-shot shell patterns that are almost
// never benign in agent-generated commands.
var dangerousCommandRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bcurl\b[^|;]*\|\s*(sudo\s+)?(ba)?sh\b`),
	regexp.MustCompile(`(?i)\bwget\b[^|;]*\|\s*(sudo\s+)?(ba)?sh\b`),
	regexp.MustCompile(`(?i)\brm\s+-rf?\s+/(?:\s|$|\*)`),
	regexp.MustCompile(`(?i)\bchmod\s+(-R\s+)?777\s+/`),
	regexp.MustCompile(`(?i)\b(eval|exec)\b.*\$\(.*curl|\bbase64\s+-d\b[^|;]*\|`),
	regexp.MustCompile(`(?i)\bnc\s+(-e|-c)\s`),
	regexp.MustCompile(`(?i)/dev/tcp/`),
	regexp.MustCompile(`(?i)\bpowershell\b.*(-enc|-encodedcommand|downloadstring|iex|invoke-expression)`),
	regexp.MustCompile(`(?i)\b(iex|invoke-expression)\b`),
	regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\b`),
	regexp.MustCompile(`(?i)\bdd\s+if=/dev/(zero|random)\s+of=/dev/`),
	regexp.MustCompile(`(?i):\(\)\s*\{\s*:\|:&\s*\}\s*;:`), // fork bomb
	regexp.MustCompile(`(?i)\b(certutil|bitsadmin|mshta|rundll32)\b.*/\s*(http|https|ftp)`),
	regexp.MustCompile(`(?i)\bsudo\b[^|;]*\|\s*sh\b`),
}

// suspiciousExecPatterns: process.exec command lines that indicate
// obfuscated or injected execution regardless of parent process.
var suspiciousExecRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)powershell(\.exe)?\s+.*-(enc|encodedcommand|e(nc)?\s)`),
	regexp.MustCompile(`(?i)\bcmd(\.exe)?\s+/c\s.*\b(curl|wget|certutil|bitsadmin)\b`),
	regexp.MustCompile(`(?i)\b(base64|certutil)\b.*\b(decode|-decode|-decodehex)\b`),
	regexp.MustCompile(`(?i)\b(wscript|cscript|mshta)\b`),
	regexp.MustCompile(`(?i)^/tmp/|^/dev/shm/|%TEMP%|\\Temp\\.*\.(exe|bat|ps1|vbs)`),
	regexp.MustCompile(`(?i)\bpython\d?\s+-c\s+.*base64`),
	regexp.MustCompile(`(?i)\bnohup\b.*\bdisable_.*key\b`),
}

// untrustedHostRegexes: destinations commonly abused for staging or
// exfiltration, plus dynamic-DNS and malware-friendly TLDs.
var untrustedHostRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^(pastebin\.com|transfer\.sh|ngrok\.io|trycloudflare\.com|hookb\.in|webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(fun|pro|site|online)|dnslog\.cn|burpcollaborator\.net)`),
	regexp.MustCompile(`(?i)\.(zip|mov|top|xyz|gq|tk|ml|cf|loan|work|click|country)\b`),
}

// rawIPHostRegex matches bare-IP HTTP targets (no DNS = likely
// hardcoded C2 or bypass).
var rawIPHostRegex = regexp.MustCompile(`^(https?://)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)`)

// eventText bundles the searchable text of one event so path/command
// matchers do not care which column the payload landed in.
func eventText(ev audit.BehaviorEvent) string {
	return strings.Join([]string{
		ev.Target,
		ev.Path,
		ev.Operation,
		ev.ToolName,
		ev.Action,
		ev.Detail,
	}, " ")
}

// matchesAnyPath reports whether the event text references one of the
// given path fragments (case-insensitive, forward/back slash
// normalized).
func matchesAnyPath(text string, patterns []string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(text, `\`, "/"))
	for _, p := range patterns {
		if strings.Contains(normalized, strings.ReplaceAll(strings.ToLower(p), `\`, "/")) {
			return true
		}
	}
	return false
}

// IsCredentialAccessText reports whether the text touches a
// credential store path.
func IsCredentialAccessText(text string) bool { return matchesAnyPath(text, credentialPathPatterns) }

// IsSensitiveFileText reports whether the text touches a sensitive
// system/secret path.
func IsSensitiveFileText(text string) bool { return matchesAnyPath(text, sensitivePathPatterns) }

// MatchesDangerousCommand reports whether the text contains a
// dangerous shell pattern.
func MatchesDangerousCommand(text string) bool {
	for _, re := range dangerousCommandRegexes {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// MatchesSuspiciousExec reports whether a process command line looks
// obfuscated or staged.
func MatchesSuspiciousExec(text string) bool {
	for _, re := range suspiciousExecRegexes {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// IsUntrustedDestination reports whether a host/target looks like a
// raw IP or a known staging/exfil endpoint.
func IsUntrustedDestination(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if rawIPHostRegex.MatchString(target) {
		return true
	}
	host := target
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	for _, re := range untrustedHostRegexes {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

// isReadEventType: events whose semantics are "content was read".
func isReadEventType(t string) bool {
	return t == "file.read" || t == "tool.pre_call" || t == "tool.post_call"
}

// isSendEventType: events whose semantics are "data left the host".
func isSendEventType(t string) bool {
	return t == "network.send" || t == "network.request" || t == "network.download"
}

// isExecEventType: events whose semantics are "code/process ran".
func isExecEventType(t string) bool {
	return t == "process.exec" || t == "tool.pre_call"
}

// downloadishText reports whether the text looks like a download
// command (curl/wget/certutil to a file).
var downloadCommandRegex = regexp.MustCompile(`(?i)\b(curl|wget|certutil|bitsadmin|invoke-webrequest|iwr)\b.*(-o\b|--output|urlcache|/transfer|/download|>)`)

func downloadishText(text string) bool { return downloadCommandRegex.MatchString(text) }

// shellishText reports whether the text runs a shell interpreter.
var shellRegex = regexp.MustCompile(`(?i)(^|[/\\\s])(ba|z|fi|k)?sh(\.exe)?(\s|$)|\bcmd(\.exe)?\s+/c|\bpowershell(\.exe)?\s`)

func shellishText(text string) bool { return shellRegex.MatchString(text) }
