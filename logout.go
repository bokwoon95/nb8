package nb8

import (
	"html/template"
	"net/http"
	"time"

	"github.com/bokwoon95/sq"
)

func (nbrew *Notebrew) logout(w http.ResponseWriter, r *http.Request, ip string) {
	if nbrew.DB == nil {
		notFound(w, r)
		return
	}
	authenticationTokenHash := getAuthenticationTokenHash(r)
	if authenticationTokenHash == nil {
		http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/admin/", http.StatusFound)
		return
	}
	switch r.Method {
	case "GET":
		funcMap := map[string]any{
			"stylesCSS":  func() template.CSS { return template.CSS(stylesCSS) },
			"baselineJS": func() template.JS { return template.JS(baselineJS) },
			"referer":    func() string { return r.Referer() },
		}
		tmpl, err := template.New("logout.html").Funcs(funcMap).ParseFS(rootFS, "embed/logout.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		contentSecurityPolicy(w, "", false)
		executeTemplate(w, r, time.Time{}, tmpl, nil)
	case "POST":
		http.SetCookie(w, &http.Cookie{
			Path:   "/",
			Name:   "authentication",
			Value:  "0",
			MaxAge: -1,
		})
		if authenticationTokenHash != nil {
			_, err := sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM authentication WHERE authentication_token_hash = {authenticationTokenHash}",
				Values: []any{
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/admin/login/", http.StatusFound)
	default:
		methodNotAllowed(w, r)
	}
}
