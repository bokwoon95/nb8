package nb8

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/bokwoon95/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) login(w http.ResponseWriter, r *http.Request, ip string) {
	type Request struct {
		Username        string `json:"username,omitempty"`
		Password        string `json:"password,omitempty"`
		CaptchaResponse string `json:"captchaResponse,omitempty"`
	}
	type Response struct {
		Status              Error              `json:"status"`
		Username            string             `json:"username,omitempty"` // could be username -or- email, check sitePrefix for username instead
		RequireCaptcha      bool               `json:"requireCaptcha,omitempty"`
		CaptchaSiteKey      string             `json:"captchaSiteKey,omitempty"`
		Errors              map[string][]Error `json:"errors,omitempty"`
		AuthenticationToken string             `json:"authenticationToken,omitempty"`
		Redirect            string             `json:"redirect,omitempty"`
		SitePrefix          string             `json:"sitePrefix,omitempty"`
	}

	if nbrew.DB == nil {
		notFound(w, r)
		return
	}

	isAuthenticated := func() bool {
		authenticationTokenHash := getAuthenticationTokenHash(r)
		if authenticationTokenHash == nil {
			return false
		}
		exists, err := sq.FetchExistsContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "SELECT 1 FROM authentication WHERE authentication_token_hash = {authenticationTokenHash}",
			Values: []any{
				sq.BytesParam("authenticationTokenHash", authenticationTokenHash),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return exists
	}

	getFailedLoginsForIP := func(ip string) (int, error) {
		failedLogins, err := sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM ip_login WHERE ip = {ip}",
			Values: []any{
				sq.StringParam("ip", ip),
			},
		}, func(row *sq.Row) int {
			return row.Int("failed_logins")
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		return failedLogins, nil
	}

	type CaptchaCredentials struct {
		SecretKey string `json:"secretKey,omitempty"`
		SiteKey   string `json:"siteKey,omitempty"`
	}
	getCaptchaCredentials := func() (CaptchaCredentials, error) {
		var captchaCredentials CaptchaCredentials
		b, err := fs.ReadFile(nbrew.FS, "config/captcha.json")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return captchaCredentials, err
		}
		err = json.Unmarshal(b, &captchaCredentials)
		return captchaCredentials, err
	}

	signupsAreOpen := func() bool {
		file, err := nbrew.FS.Open("config/signups.txt")
		if err != nil {
			return false
		}
		defer file.Close()
		reader := bufio.NewReader(file)
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			getLogger(r.Context()).Error(err.Error())
			return false
		}
		isOpen, _ := strconv.ParseBool(line)
		return isOpen
	}

	sanitizeRedirect := func(redirect string) string {
		uri, err := url.Parse(path.Clean(redirect))
		if err != nil {
			return ""
		}
		head, tail, _ := strings.Cut(strings.Trim(uri.Path, "/"), "/")
		if head != "users" || tail == "" || tail == "login" {
			return ""
		}
		uri = &url.URL{
			Path:     strings.Trim(uri.Path, "/"),
			RawQuery: uri.RawQuery,
		}
		if path.Ext(uri.Path) == "" {
			uri.Path = "/" + uri.Path + "/"
		} else {
			uri.Path = "/" + uri.Path
		}
		return uri.String()
	}

	r.Body = http.MaxBytesReader(w, r.Body, 2<<20 /* 2MB */)
	switch r.Method {
	case "GET":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			captchaCredentials, err := getCaptchaCredentials()
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.CaptchaSiteKey = captchaCredentials.SiteKey
			if captchaCredentials.SecretKey != "" && captchaCredentials.SiteKey != "" {
				failedLogins, err := getFailedLoginsForIP(ip)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				if failedLogins >= 3 {
					response.RequireCaptcha = true
				}
			}
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			funcMap := map[string]any{
				"join":           path.Join,
				"signupsAreOpen": signupsAreOpen,
				"stylesCSS":      func() template.CSS { return template.CSS(stylesCSS) },
			}
			tmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(rootFS, "embed/login.html")
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			contentSecurityPolicy(w, "", true)
			executeTemplate(w, r, time.Time{}, tmpl, &response)
		}

		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}
		var response Response
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		nbrew.clearSession(w, r, "flash")
		if response.Status != "" {
			writeResponse(w, r, response)
			return
		}
		if r.Form.Has("401") {
			response.Status = ErrNotAuthenticated
			writeResponse(w, r, response)
			return
		}
		response.Redirect = sanitizeRedirect(r.Form.Get("redirect"))
		if isAuthenticated() {
			response.Status = ErrAlreadyAuthenticated
			writeResponse(w, r, response)
			return
		}
		response.Status = Success
		writeResponse(w, r, response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			if response.Status == ErrIncorrectLoginCredentials || response.Status == ErrUserNotFound {
				if nbrew.Dialect == sq.DialectMySQL {
					_, err := sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
						Dialect: nbrew.Dialect,
						Format: "INSERT INTO ip_login (ip, failed_logins) VALUES ({ip}, 1)" +
							" ON DUPLICATE KEY UPDATE failed_logins = COALESCE(failed_logins, 0) + 1",
						Values: []any{
							sq.StringParam("ip", ip),
						},
					})
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
				} else {
					_, err := sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
						Dialect: nbrew.Dialect,
						Format: "INSERT INTO ip_login (ip, failed_logins) VALUES ({ip}, 1)" +
							" ON CONFLICT (ip) DO UPDATE SET failed_logins = COALESCE(failed_logins, 0) + 1",
						Values: []any{
							sq.StringParam("ip", ip),
						},
					})
					if err != nil {
						getLogger(r.Context()).Error(err.Error())
						internalServerError(w, r, err)
						return
					}
				}
				_, err := sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "UPDATE users SET failed_logins = COALESCE(failed_logins, 0) + 1 WHERE username = {username}",
					Values: []any{
						sq.StringParam("username", strings.TrimPrefix(response.SitePrefix, "@")),
					},
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			} else if response.Status.Success() {
				_, err := sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "DELETE FROM ip_login WHERE ip = {ip}",
					Values: []any{
						sq.StringParam("ip", ip),
					},
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "UPDATE users SET failed_logins = NULL WHERE username = {username}",
					Values: []any{
						sq.StringParam("username", strings.TrimPrefix(response.SitePrefix, "@")),
					},
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			if r.Form.Has("api") {
				w.Header().Set("Content-Type", "application/json")
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			if !response.Status.Success() {
				err := nbrew.setSession(w, r, "flash", &response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				var query string
				if response.Redirect != "" {
					query = "?redirect=" + url.QueryEscape(response.Redirect)
				}
				http.Redirect(w, r, "/users/login/"+query, http.StatusFound)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Path:     "/",
				Name:     "authentication",
				Value:    response.AuthenticationToken,
				Secure:   nbrew.Domain != "localhost" && !strings.HasPrefix(nbrew.Domain, "localhost:"),
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				MaxAge:   int((time.Hour * 24 * 365).Seconds()),
			})
			if response.Redirect != "" {
				http.Redirect(w, r, response.Redirect, http.StatusFound)
				return
			}
			http.Redirect(w, r, "/"+path.Join("files", response.SitePrefix)+"/", http.StatusFound)
		}

		var request Request
		var redirect string
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(2 << 20 /* 2MB */)
				if err != nil {
					badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					badRequest(w, r, err)
					return
				}
			}
			request.Username = r.Form.Get("username")
			request.Password = r.Form.Get("password")
			request.CaptchaResponse = r.Form.Get("h-captcha-response")
			redirect = r.Form.Get("redirect")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			Username: strings.TrimPrefix(request.Username, "@"),
			Errors:   make(map[string][]Error),
			Redirect: sanitizeRedirect(redirect),
		}
		if isAuthenticated() {
			response.Status = ErrAlreadyAuthenticated
			writeResponse(w, r, response)
			return
		}

		if response.Username == "" {
			response.Errors["username"] = append(response.Errors["username"], ErrRequired)
		}
		if request.Password == "" {
			response.Errors["password"] = append(response.Errors["password"], ErrRequired)
		}
		if len(response.Errors) > 0 {
			response.Status = ErrValidationFailed
			writeResponse(w, r, response)
			return
		}

		var err error
		var email string
		var passwordHash []byte
		var failedLogins int
		var userNotFound bool
		if strings.Contains(response.Username, "@") {
			email = response.Username
		}
		if email != "" {
			result, err := sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", email),
				},
			}, func(row *sq.Row) (result struct {
				Username     string
				PasswordHash []byte
				FailedLogins int
			}) {
				result.Username = row.String("username")
				result.PasswordHash = row.Bytes("password_hash")
				result.FailedLogins = row.Int("failed_logins")
				return result
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				userNotFound = true
			}
			if result.Username != "" {
				response.SitePrefix = "@" + result.Username
			}
			passwordHash = result.PasswordHash
			failedLogins = result.FailedLogins
		} else {
			result, err := sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "SELECT {*} FROM users WHERE username = {username}",
				Values: []any{
					sq.StringParam("username", response.Username),
				},
			}, func(row *sq.Row) (result struct {
				PasswordHash []byte
				FailedLogins int
			}) {
				result.PasswordHash = row.Bytes("password_hash")
				result.FailedLogins = row.Int("failed_logins")
				return result
			})
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				userNotFound = true
			}
			if response.Username != "" {
				response.SitePrefix = "@" + response.Username
			}
			passwordHash = result.PasswordHash
			failedLogins = result.FailedLogins
		}

		captchaCredentials, err := getCaptchaCredentials()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.CaptchaSiteKey = captchaCredentials.SiteKey
		if captchaCredentials.SecretKey != "" && captchaCredentials.SiteKey != "" {
			if failedLogins >= 3 {
				response.RequireCaptcha = true
			} else {
				failedLogins, err = getFailedLoginsForIP(ip)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				if failedLogins >= 3 {
					response.RequireCaptcha = true
				}
			}
		}

		if response.RequireCaptcha {
			if request.CaptchaResponse == "" {
				response.Status = ErrRetryWithCaptcha
				writeResponse(w, r, response)
				return
			}
			client := &http.Client{
				Timeout: 60 * time.Second,
			}
			values := url.Values{
				"secret":   []string{captchaCredentials.SecretKey},
				"response": []string{request.CaptchaResponse},
				"remoteip": []string{ip},
				"sitekey":  []string{captchaCredentials.SiteKey},
			}
			resp, err := client.Post("https://api.hcaptcha.com/siteverify", "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			defer resp.Body.Close()
			result := make(map[string]any)
			err = json.NewDecoder(resp.Body).Decode(&result)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			success, _ := result["success"].(bool)
			if !success {
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				defer bufPool.Put(buf)
				encoder := json.NewEncoder(buf)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(result)
				if err != nil {
					getLogger(r.Context()).Warn(err.Error())
				} else {
					getLogger(r.Context()).Warn(strings.TrimSpace(buf.String()))
				}
				response.Status = ErrCaptchaChallengeFailed
				writeResponse(w, r, response)
				return
			}
		}

		if userNotFound {
			response.Status = ErrUserNotFound
			writeResponse(w, r, response)
			return
		}

		err = bcrypt.CompareHashAndPassword(passwordHash, []byte(request.Password))
		if err != nil {
			response.Status = ErrIncorrectLoginCredentials
			writeResponse(w, r, response)
			return
		}

		var authenticationToken [8 + 16]byte
		binary.BigEndian.PutUint64(authenticationToken[:8], uint64(time.Now().Unix()))
		_, err = rand.Read(authenticationToken[8:])
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		var authenticationTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(authenticationToken[8:])
		copy(authenticationTokenHash[:8], authenticationToken[:8])
		copy(authenticationTokenHash[8:], checksum[:])
		if email != "" {
			_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO authentication (authentication_token_hash, user_id)" +
					" VALUES ({authenticationTokenHash}, (SELECT user_id FROM users WHERE email = {email}))",
				Values: []any{
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash[:]),
					sq.StringParam("email", email),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		} else {
			_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format: "INSERT INTO authentication (authentication_token_hash, user_id)" +
					" VALUES ({authenticationTokenHash}, (SELECT user_id FROM users WHERE username = {username}))",
				Values: []any{
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash[:]),
					sq.StringParam("username", response.Username),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		response.AuthenticationToken = strings.TrimLeft(hex.EncodeToString(authenticationToken[:]), "0")
		response.Status = LoginSuccess
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
