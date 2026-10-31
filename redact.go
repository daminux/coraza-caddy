package coraza

// Masquage des secrets dans tout ce que le WAF ecrit : journal d'audit et
// messages de regles (logs du conteneur).
//
// Pourquoi : Coraza journalise, pour toute requete qui declenche une regle,
// le corps complet (partie C), les en-tetes (partie B) et la donnee reconnue
// ("Matched Data: X found within ARGS:_password: <valeur>"). Un formulaire de
// connexion y etait donc ecrit EN CLAIR : 611 en prod au 2026-10-31, dont des
// connexions legitimes. Coraza ne sait pas masquer (pas de sanitiseArg), et
// retirer les parties ferait perdre les numeros de regle, indispensables pour
// enqueter. On garde donc tout, sauf les VALEURS sensibles.
//
// Le JSON produit a exactement la forme du format JSON de Coraza : les outils
// de lecture n'ont rien a changer. Activation : SecAuditLogFormat jsonredacted.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

const masked = "[masqué]"

// sensitive reconnait un NOM de champ porteur de secret. Large a dessein : un
// faux positif ne coute qu'une valeur masquee dans un journal, un faux negatif
// ecrit un mot de passe sur disque.
// authorization et cookie y figurent pour les regles qui frappent un en-tete :
// "found within REQUEST_HEADERS:Authorization: Basic <identifiants>".
var sensitive = regexp.MustCompile(`(?i)(passw|passwd|pwd|mot[_-]?de[_-]?passe|motdepasse|secret|token|api[_-]?key|authorization|cookie|(?:^|[^a-z])(?:pass|mdp|otp|cvv|pin)(?:[^a-z]|$))`)

// En-tetes dont la valeur est un secret quel que soit leur contenu.
var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true,
	"set-cookie": true, "x-api-key": true, "x-auth-token": true,
}

var (
	// Segments de ErrorLog() qui peuvent porter une valeur : la donnee reconnue
	// et le message, plus leurs variantes _match_N quand une regle a plusieurs
	// correspondances (corazarules.writeExtraRuleDetails).
	reDataSeg = regexp.MustCompile(`\[((?:data|msg)(?:_match_\d+)?) "((?:[^"\\]|\\.)*)"\]`)
	reURISeg  = regexp.MustCompile(`\[uri "((?:[^"\\]|\\.)*)"\]`)
	reColl    = regexp.MustCompile(`^[A-Z_]+`)
)

func init() {
	plugins.RegisterAuditLogFormatter("jsonredacted", redactedJSONFormatter{})
}

type redactedJSONFormatter struct{}

func (redactedJSONFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	raw, err := json.Marshal(al)
	if err != nil {
		return nil, err
	}
	// En cas d'echec, on renvoie l'erreur : l'entree est perdue plutot
	// qu'ecrite en clair (echec ferme).
	return redactAuditJSON(raw)
}

func (redactedJSONFormatter) MIME() string { return "application/json; charset=utf-8" }

// redactErrorLog masque une ligne de regle au format Coraza ErrorLog().
func redactErrorLog(s string) string {
	s = reDataSeg.ReplaceAllStringFunc(s, func(seg string) string {
		m := reDataSeg.FindStringSubmatch(seg)
		return `[` + m[1] + ` "` + redactMatchedData(m[2]) + `"]`
	})
	return reURISeg.ReplaceAllStringFunc(s, func(seg string) string {
		inner := reURISeg.FindStringSubmatch(seg)[1]
		return `[uri "` + redactURI(inner) + `"]`
	})
}

// redactMatchedData traite "Matched Data: X found within VAR[:cle]: VALEUR".
// Si un secret peut s'y trouver, X et la valeur sont masques ; la collection
// et un nom de cle inoffensif restent, pour savoir OU la regle a frappe.
func redactMatchedData(d string) string {
	if !sensitive.MatchString(d) {
		return d
	}
	const pre, mid = "Matched Data: ", " found within "
	i := strings.Index(d, mid)
	if !strings.HasPrefix(d, pre) || i < 0 {
		return masked
	}
	rest := d[i+len(mid):]
	coll := reColl.FindString(rest)
	if coll == "" {
		return pre + masked
	}
	where := coll
	if tail := rest[len(coll):]; strings.HasPrefix(tail, ":") {
		key := tail[1:]
		if j := strings.Index(key, ": "); j >= 0 {
			key = key[:j]
		}
		if len(key) > 64 || strings.ContainsAny(key, `{}="\`) {
			key = masked // nom de variable qui est en fait un corps
		}
		where += ":" + key
	}
	return pre + masked + mid + where + ": " + masked
}

// redactURI masque la valeur des parametres d'URL sensibles.
func redactURI(u string) string {
	q := strings.IndexByte(u, '?')
	if q < 0 || !sensitive.MatchString(u[q+1:]) {
		return u
	}
	return u[:q+1] + redactPairs(u[q+1:])
}

// redactPairs masque les valeurs sensibles d'une suite cle=valeur&..., dans
// l'ordre d'origine.
func redactPairs(s string) string {
	parts := strings.Split(s, "&")
	for i, p := range parts {
		k, _, found := strings.Cut(p, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		if found && sensitive.MatchString(dk) {
			parts[i] = k + "=" + masked
		}
	}
	return strings.Join(parts, "&")
}

// redactBody masque les secrets d'un corps de requete : valeurs ciblees en
// JSON et en urlencoded, corps entier sinon (multipart, format inconnu).
func redactBody(b string) string {
	if !sensitive.MatchString(b) {
		return b
	}
	if t := strings.TrimSpace(b); json.Valid([]byte(t)) && (strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")) {
		dec := json.NewDecoder(strings.NewReader(t))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			if out, err := marshalNoEscape(maskJSON(v)); err == nil {
				return out
			}
		}
	}
	if !strings.ContainsAny(b, "\r\n") && strings.Contains(b, "=") {
		return redactPairs(b)
	}
	return fmt.Sprintf("[masqué : corps de %d octets contenant un champ sensible]", len(b))
}

func maskJSON(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitive.MatchString(k) {
				t[k] = masked
			} else {
				t[k] = maskJSON(val)
			}
		}
	case []any:
		for i := range t {
			t[i] = maskJSON(t[i])
		}
	}
	return v
}

func marshalNoEscape(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// redactAuditJSON applique le masquage a une entree d'audit au format JSON de
// Coraza, sans en changer la structure.
func redactAuditJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if tx, ok := doc["transaction"].(map[string]any); ok {
		if req, ok := tx["request"].(map[string]any); ok {
			if u, ok := req["uri"].(string); ok {
				req["uri"] = redactURI(u)
			}
			if b, ok := req["body"].(string); ok {
				req["body"] = redactBody(b)
			}
			maskHeaders(req["headers"])
			if args, ok := req["args"].(map[string]any); ok {
				maskJSON(args)
			}
		}
		if resp, ok := tx["response"].(map[string]any); ok {
			maskHeaders(resp["headers"])
		}
	}
	if msgs, ok := doc["messages"].([]any); ok {
		for _, m := range msgs {
			mm, ok := m.(map[string]any)
			if !ok {
				continue
			}
			if e, ok := mm["error_message"].(string); ok {
				mm["error_message"] = redactErrorLog(e)
			}
			if s, ok := mm["message"].(string); ok {
				mm["message"] = redactMatchedData(s)
			}
			if d, ok := mm["data"].(map[string]any); ok {
				for _, k := range []string{"data", "msg"} {
					if s, ok := d[k].(string); ok {
						d[k] = redactMatchedData(s)
					}
				}
			}
		}
	}
	return json.Marshal(doc)
}

func maskHeaders(h any) {
	hm, ok := h.(map[string]any)
	if !ok {
		return
	}
	for name, vals := range hm {
		ln := strings.ToLower(name)
		if !sensitiveHeaders[ln] && !sensitive.MatchString(ln) {
			continue
		}
		list, ok := vals.([]any)
		if !ok {
			hm[name] = masked
			continue
		}
		for i, v := range list {
			s, _ := v.(string)
			// Garder le schema (Basic, Bearer) : utile, et sans secret.
			if (ln == "authorization" || ln == "proxy-authorization") && strings.Contains(s, " ") {
				list[i] = strings.SplitN(s, " ", 2)[0] + " " + masked
			} else {
				list[i] = masked
			}
		}
	}
}
