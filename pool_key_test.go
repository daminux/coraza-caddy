package coraza

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRules creates a rule file and returns its path.
func writeRules(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// TestPoolKey_ReflectsIncludedContent: editing an included file must change the
// key, otherwise LoadOrNew serves the pooled instance with its previously
// compiled rules and the change is silently ignored — even with
// `caddy reload --force`.
func TestPoolKey_ReflectsIncludedContent(t *testing.T) {
	dir := t.TempDir()
	p := writeRules(t, dir, "rules.conf",
		`SecRule REQUEST_URI "@contains /a" "id:1,phase:1,deny"`)

	m := &corazaModule{Directives: "Include " + p}
	before := m.computePoolKey()

	writeRules(t, dir, "rules.conf",
		`SecRule REQUEST_URI "@contains /b" "id:1,phase:1,deny"`)
	after := m.computePoolKey()

	if before == after {
		t.Error("pool key unchanged after editing an included file: the WAF would " +
			"be reused with stale rules")
	}
}

// TestPoolKey_SharesIdenticalContent: two configurations pointing at different
// paths with identical contents must share one instance. This is the common
// case of one exclusion file per site — otherwise each site pays for a full
// instance, CRS rules included, for an identical configuration.
func TestPoolKey_SharesIdenticalContent(t *testing.T) {
	dir := t.TempDir()
	rules := `SecRule REQUEST_URI "@contains /x" "id:1,phase:1,deny"`
	a := writeRules(t, dir, "site-a.conf", rules)
	b := writeRules(t, dir, "site-b.conf", rules)

	ka := (&corazaModule{Directives: "Include " + a}).computePoolKey()
	kb := (&corazaModule{Directives: "Include " + b}).computePoolKey()

	if ka != kb {
		t.Errorf("different keys for identical rule sets (%s vs %s): instances "+
			"would not be shared", a, b)
	}
}

// TestPoolKey_IgnoresComments: files differing only by comments are
// functionally identical. Coraza ignores those lines, so the key must too —
// otherwise a per-site header comment defeats sharing entirely.
func TestPoolKey_IgnoresComments(t *testing.T) {
	dir := t.TempDir()
	rule := `SecRule REQUEST_URI "@contains /x" "id:1,phase:1,deny"`
	a := writeRules(t, dir, "a.conf", "# exclusions for a.example.com\n\n"+rule)
	b := writeRules(t, dir, "b.conf", "# exclusions for b.example.com\n"+rule+"\n")

	ka := (&corazaModule{Directives: "Include " + a}).computePoolKey()
	kb := (&corazaModule{Directives: "Include " + b}).computePoolKey()

	if ka != kb {
		t.Error("comment-only differences change the pool key")
	}
}

// TestPoolKey_DistinguishesRealDifferences guards against over-normalisation:
// configurations that genuinely differ must not be merged.
func TestPoolKey_DistinguishesRealDifferences(t *testing.T) {
	dir := t.TempDir()
	a := writeRules(t, dir, "a.conf", `SecRule REQUEST_URI "@contains /a" "id:1,phase:1,deny"`)
	b := writeRules(t, dir, "b.conf", `SecRule REQUEST_URI "@contains /b" "id:2,phase:1,deny"`)

	ka := (&corazaModule{Directives: "Include " + a}).computePoolKey()
	kb := (&corazaModule{Directives: "Include " + b}).computePoolKey()

	if ka == kb {
		t.Error("different rule sets share a key: one site would run another's rules")
	}
}

// TestPoolKey_MissingFileIsDeterministic: a missing Include must not panic nor
// yield a varying key. The error is reported later, by WAF construction.
func TestPoolKey_MissingFileIsDeterministic(t *testing.T) {
	m := &corazaModule{Directives: "Include /nonexistent/does-not-exist.conf"}
	if m.computePoolKey() != m.computePoolKey() {
		t.Error("key is not deterministic when an included file is missing")
	}
}
