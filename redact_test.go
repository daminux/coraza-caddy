package coraza

import (
	"encoding/json"
	"strings"
	"testing"
)

// Les secrets de ces tests sont choisis pour etre reconnaissables : s'ils
// apparaissent dans une sortie, c'est une fuite.
const (
	secretPwd    = "Tr0ub4dor&3"
	secretBearer = "213c5ea69132fdeba986456c6497bb43"
	secretCookie = "sess-9f8e7d6c5b4a"
)

func assertNoSecret(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("fuite : %q present dans\n%s", s, out)
		}
	}
}

func TestRedactErrorLog_PasswordVariable(t *testing.T) {
	in := `[client "1.2.3.4"] Coraza: Warning. SQL Injection [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] ` +
		`[data "Matched Data: s&sos found within ARGS:_password: ` + secretPwd + `' or 1=1--"] [severity "critical"] [uri "/fr/moncompte/login_check/"] [unique_id "abc"]`
	out := redactErrorLog(in)
	assertNoSecret(t, out, secretPwd, "s&sos", "or 1=1")
	for _, keep := range []string{`[id "942100"]`, "found within ARGS:_password", `[uri "/fr/moncompte/login_check/"]`, `[unique_id "abc"]`} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q devait etre conserve :\n%s", keep, out)
		}
	}
}

func TestRedactErrorLog_JSONBodyAsArgName(t *testing.T) {
	// Corps JSON non analyse : il atterrit entier dans ARGS_NAMES, nom de la
	// variable compris -- le secret est alors DANS le nom.
	in := `[id "932130"] [data "Matched Data: >( found within ARGS_NAMES:{\"login\":\"bob\",\"password\":\"` + secretPwd + `\"}: {\"login\":\"bob\",\"password\":\"` + secretPwd + `\"}"] [uri "/api/login"]`
	out := redactErrorLog(in)
	assertNoSecret(t, out, secretPwd)
	if !strings.Contains(out, `[id "932130"]`) || !strings.Contains(out, "ARGS_NAMES") {
		t.Errorf("regle et collection doivent rester :\n%s", out)
	}
}

func TestRedactErrorLog_HeaderAndCookie(t *testing.T) {
	basic := "Ym9iOlRyMHViNGRvciYz" // base64("bob:Tr0ub4dor&3")
	for _, in := range []string{
		`[id "920xxx"] [data "Matched Data: Basic ` + basic + ` found within REQUEST_HEADERS:Authorization: Basic ` + basic + `"]`,
		`[id "942xxx"] [data "Matched Data: ` + secretCookie + ` found within REQUEST_COOKIES:PHPSESSID: ` + secretCookie + `"]`,
	} {
		out := redactErrorLog(in)
		assertNoSecret(t, out, basic, secretCookie)
		if !strings.Contains(out, "found within REQUEST_") {
			t.Errorf("la variable doit rester : %s", out)
		}
	}
}

func TestRedactErrorLog_ExtraMatchSegments(t *testing.T) {
	// Regle a plusieurs correspondances : Coraza ajoute [msg_match_N] et
	// [data_match_N]. Cas reel (T20) : corps JSON lu comme nom de parametre.
	in := `[id "942100"] [msg "SQL Injection"] [data "Matched Data: s&1c found within ARGS:x: y"] ` +
		`[msg_match_1 "SQL Injection"] [data_match_1 "Matched Data: 1c found within ARGS:{\"login\":\"bob\",\"password\":\"` + secretPwd + `' OR 1: 1--\"}"] [uri "/api/login"]`
	out := redactErrorLog(in)
	assertNoSecret(t, out, secretPwd)
	if !strings.Contains(out, "[data_match_1 ") || !strings.Contains(out, `[id "942100"]`) {
		t.Errorf("structure perdue : %s", out)
	}
}

func TestRedactErrorLog_NonSensitiveUntouched(t *testing.T) {
	// Le diagnostic des faux positifs repose sur la donnee reconnue : on ne
	// masque que ce qui est sensible.
	in := `[id "932330"] [data "Matched Data: !-5 found within REQUEST_FILENAME: /cuisine/mets-de-huile-!-50_ref-979/"] [uri "/cuisine/mets-de-huile-!-50_ref-979/"]`
	if out := redactErrorLog(in); out != in {
		t.Errorf("message sans secret modifie :\n avant %s\n apres %s", in, out)
	}
}

func TestRedactErrorLog_PasswordInQueryString(t *testing.T) {
	in := `[id "942100"] [data "Matched Data: x found within ARGS:q: x"] [uri "/login?user=bob&pwd=` + secretPwd + `&q=x"]`
	out := redactErrorLog(in)
	assertNoSecret(t, out, secretPwd)
	if !strings.Contains(out, "user=bob") || !strings.Contains(out, "q=x") {
		t.Errorf("les autres parametres doivent rester :\n%s", out)
	}
}

func TestRedactBody(t *testing.T) {
	cases := []struct {
		name, body string
		keep       []string
	}{
		{"urlencoded", "_username=bob&_password=" + secretPwd + "&_remember_me=on", []string{"_username=bob", "_remember_me=on", "_password="}},
		{"urlencoded encode", "login=bob&mot_de_passe=" + strings.ReplaceAll(secretPwd, "&", "%26"), []string{"login=bob"}},
		{"json", `{"login":"bob","credentials":{"password":"` + secretPwd + `"},"remember":true}`, []string{`"login":"bob"`, `"remember":true`, `"password"`}},
		{"json tableau", `[{"pwd":"` + secretPwd + `"}]`, []string{`"pwd"`}},
		{"brut avec cle sensible", "--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + secretPwd + "\r\n--boundary--", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := redactBody(c.body)
			assertNoSecret(t, out, secretPwd, strings.ReplaceAll(secretPwd, "&", "%26"))
			for _, k := range c.keep {
				if !strings.Contains(out, k) {
					t.Errorf("%q devait etre conserve : %s", k, out)
				}
			}
		})
	}
	// Corps sans rien de sensible : intact (diagnostic des faux positifs).
	plain := `{"content":"<p>Bonjour</p>","internal":false}`
	if got := redactBody(plain); got != plain {
		t.Errorf("corps sans secret modifie : %s", got)
	}
}

func TestRedactAuditJSON(t *testing.T) {
	in := map[string]any{
		"transaction": map[string]any{
			"id": "sXgBYRFvgKOrlbfV",
			"request": map[string]any{
				"method": "POST",
				"uri":    "/login?token=" + secretBearer,
				"headers": map[string]any{
					"authorization": []any{"Bearer " + secretBearer},
					"cookie":        []any{"PHPSESSID=" + secretCookie},
					"user-agent":    []any{"Mozilla/5.0"},
				},
				"body": "_username=bob&_password=" + secretPwd,
			},
			"response": map[string]any{
				"headers": map[string]any{"set-cookie": []any{"PHPSESSID=" + secretCookie}},
			},
		},
		"messages": []any{
			map[string]any{
				"error_message": `[id "942100"] [data "Matched Data: x found within ARGS:_password: ` + secretPwd + `"]`,
				"data":          map[string]any{"id": 942100, "data": "Matched Data: x found within ARGS:_password: " + secretPwd},
			},
		},
	}
	raw, _ := json.Marshal(in)
	out, err := redactAuditJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	assertNoSecret(t, s, secretPwd, secretBearer, secretCookie)
	for _, keep := range []string{"sXgBYRFvgKOrlbfV", "Mozilla/5.0", "_username=bob", `942100`, "found within ARGS:_password"} {
		if !strings.Contains(s, keep) {
			t.Errorf("%q devait etre conserve :\n%s", keep, s)
		}
	}
	// Meme forme qu'avant : les outils de lecture (collect.py) ne changent pas.
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("sortie non JSON : %v", err)
	}
	if _, ok := back["transaction"].(map[string]any)["request"].(map[string]any)["headers"]; !ok {
		t.Error("structure transaction.request.headers perdue")
	}
}
