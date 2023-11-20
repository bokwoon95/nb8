package nb8

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bokwoon95/sq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
)

func (nbrew *Notebrew) signup(w http.ResponseWriter, r *http.Request, ip string) {
	type Request struct {
		SignupToken     string `json:"signupToken,omitempty"`
		Username        string `json:"username,omitempty"`
		Email           string `json:"email,omitempty"`
		Password        string `json:"password,omitempty"`
		ConfirmPassword string `json:"confirmPassword,omitempty"`
		CaptchaResponse string `json:"captchaResponse,omitempty"`
		DryRun          bool   `json:"dryRun,omitempty"`
	}
	type Response struct {
		Status         Error              `json:"status"`
		SignupToken    string             `json:"signupToken,omitempty"`
		Username       string             `json:"username,omitempty"`
		Email          string             `json:"email,omitempty"`
		RequireCaptcha bool               `json:"requireCaptcha,omitempty"`
		CaptchaSiteKey string             `json:"captchaSiteKey,omitempty"`
		Errors         map[string][]Error `json:"errors,omitempty"`
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
		b, err := fs.ReadFile(nbrew.FS, "config/signups.txt")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
			}
			return false
		}
		isOpen, _ := strconv.ParseBool(string(bytes.TrimSpace(b)))
		return isOpen
	}

	hashAndValidateSignupToken := func(signupToken string) (signupTokenHash []byte, err error) {
		if signupToken == "" || len(signupToken) > 48 {
			return nil, nil
		}
		b, err := hex.DecodeString(fmt.Sprintf("%048s", signupToken))
		if err != nil {
			return nil, nil
		}
		checksum := blake2b.Sum256(b[8:])
		signupTokenHash = make([]byte, 8+blake2b.Size256)
		copy(signupTokenHash[:8], b[:8])
		copy(signupTokenHash[8:], checksum[:])
		exists, err := sq.FetchExistsContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "SELECT 1 FROM signup WHERE signup_token_hash = {signupTokenHash}",
			Values: []any{
				sq.BytesParam("signupTokenHash", signupTokenHash),
			},
		})
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil
		}
		return signupTokenHash, nil
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
			response.RequireCaptcha = captchaCredentials.SecretKey != "" && captchaCredentials.SiteKey != "" && response.SignupToken == ""
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
				"isInviteLink": func() bool { return r.Form.Has("token") },
				"stylesCSS":    func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":   func() template.JS { return template.JS(baselineJS) },
			}
			tmpl, err := template.New("signup.html").Funcs(funcMap).ParseFS(rootFS, "embed/signup.html")
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
		signupTokenHash, err := hashAndValidateSignupToken(r.Form.Get("token"))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if signupTokenHash != nil {
			response.SignupToken = r.Form.Get("token")
		}
		if isAuthenticated() {
			response.Status = ErrAlreadyAuthenticated
			writeResponse(w, r, response)
			return
		}
		if !signupsAreOpen() {
			if !r.Form.Has("token") {
				response.Status = ErrSignupsNotOpen
				writeResponse(w, r, response)
				return
			}
			if response.SignupToken == "" {
				response.Status = ErrInvalidToken
				writeResponse(w, r, response)
				return
			}
		}
		response.Status = Success
		writeResponse(w, r, response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
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
				if response.SignupToken != "" {
					query = "?token=" + url.QueryEscape(response.SignupToken)
				}
				http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/users/signup/"+query, http.StatusFound)
				return
			}
			err := nbrew.setSession(w, r, "flash", map[string]any{
				"status":   response.Status,
				"username": response.Username,
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/users/login/", http.StatusFound)
		}

		var request Request
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
			request.SignupToken = r.Form.Get("signupToken")
			request.Username = r.Form.Get("username")
			request.Email = r.Form.Get("email")
			request.Password = r.Form.Get("password")
			request.ConfirmPassword = r.Form.Get("confirmPassword")
			request.CaptchaResponse = r.Form.Get("h-captcha-response")
			request.DryRun, _ = strconv.ParseBool(r.Form.Get("dryRun"))
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			SignupToken: request.SignupToken,
			Username:    request.Username,
			Email:       request.Email,
			Errors:      make(map[string][]Error),
		}
		if isAuthenticated() {
			response.Status = ErrAlreadyAuthenticated
			writeResponse(w, r, response)
			return
		}
		captchaCredentials, err := getCaptchaCredentials()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.CaptchaSiteKey = captchaCredentials.SiteKey
		var signupTokenHash []byte
		if captchaCredentials.SecretKey != "" && captchaCredentials.SiteKey != "" {
			signupTokenHash, err = hashAndValidateSignupToken(request.SignupToken)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		if !signupsAreOpen() {
			if request.SignupToken == "" {
				response.Status = ErrSignupsNotOpen
				writeResponse(w, r, response)
				return
			}
			if signupTokenHash == nil {
				response.Status = ErrInvalidToken
				writeResponse(w, r, response)
				return
			}
		}

		response.RequireCaptcha = captchaCredentials.SecretKey != "" && captchaCredentials.SiteKey != "" && signupTokenHash == nil && !request.DryRun
		if response.RequireCaptcha {
			if request.CaptchaResponse == "" {
				response.Status = ErrRetryWithCaptcha
				writeResponse(w, r, response)
				return
			}
			if nbrew.Scheme == "https://" {
				err = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(60 * time.Second))
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			}
			client := &http.Client{
				Timeout: 60 * time.Second,
			}
			values := url.Values{
				"secret":   []string{captchaCredentials.SecretKey},
				"response": []string{request.CaptchaResponse},
				"remoteip": []string{nbrew.realClientIP(r)},
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

		if request.Username == "" {
			response.Errors["username"] = append(response.Errors["username"], ErrRequired)
		} else {
			for _, char := range request.Username {
				if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
					continue
				}
				response.Errors["username"] = append(response.Errors["username"], ErrForbiddenCharacters)
				break
			}
		}
		if len(response.Errors["username"]) == 0 {
			fileInfo, err := fs.Stat(nbrew.FS, "@"+request.Username)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if fileInfo != nil {
				response.Errors["username"] = append(response.Errors["username"], ErrUsernameUnavailable)
			} else {
				exists, err := sq.FetchExistsContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format:  "SELECT 1 FROM site WHERE site_name = {username}",
					Values: []any{
						sq.StringParam("username", request.Username),
					},
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				if exists {
					response.Errors["username"] = append(response.Errors["username"], ErrUsernameUnavailable)
				}
			}
		}

		if request.Email == "" {
			response.Errors["email"] = append(response.Errors["email"], ErrRequired)
		} else {
			_, err = mail.ParseAddress(request.Email)
			if err != nil {
				response.Errors["email"] = append(response.Errors["email"], ErrInvalidEmail)
			}
		}
		if len(response.Errors["email"]) == 0 {
			exists, err := sq.FetchExistsContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM users WHERE email = {email}",
				Values: []any{
					sq.StringParam("email", request.Email),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if exists {
				response.Errors["email"] = append(response.Errors["email"], ErrEmailAlreadyUsed)
			}
		}

		if request.Password == "" {
			response.Errors["password"] = append(response.Errors["password"], ErrRequired)
		} else {
			if utf8.RuneCountInString(request.Password) < 8 {
				response.Errors["password"] = append(response.Errors["password"], ErrPasswordTooShort)
			}
			if IsCommonPassword([]byte(request.Password)) {
				response.Errors["password"] = append(response.Errors["password"], ErrPasswordTooCommon)
			}
		}
		if len(response.Errors["password"]) == 0 {
			if request.ConfirmPassword == "" {
				response.Errors["confirmPassword"] = append(response.Errors["confirmPassword"], ErrRequired)
			} else {
				if request.Password != request.ConfirmPassword {
					response.Errors["confirmPassword"] = append(response.Errors["confirmPassword"], ErrPasswordNotMatch)
				}
			}
		}

		if len(response.Errors) > 0 {
			response.Status = ErrValidationFailed
			writeResponse(w, r, response)
			return
		}

		if request.DryRun {
			response.Status = Success
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}

		siteID := NewID()
		userID := NewID()
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		tx, err := nbrew.DB.Begin()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		defer tx.Rollback()
		if signupTokenHash != nil {
			_, err = sq.ExecContext(r.Context(), tx, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "DELETE FROM signup WHERE signup_token_hash = {signupTokenHash}",
				Values: []any{
					sq.BytesParam("signupTokenHash", signupTokenHash),
				},
			})
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		_, err = sq.ExecContext(r.Context(), tx, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO site (site_id, site_name) VALUES ({siteID}, {siteName})",
			Values: []any{
				sq.UUIDParam("siteID", siteID),
				sq.StringParam("siteName", request.Username),
			},
		})
		if err != nil {
			var errcode string
			if nbrew.ErrorCode != nil {
				errcode = nbrew.ErrorCode(err)
			}
			if IsKeyViolation(nbrew.Dialect, errcode) {
				response.Errors["username"] = append(response.Errors["username"], ErrUsernameUnavailable)
				response.Status = ErrValidationFailed
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		_, err = sq.ExecContext(r.Context(), tx, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format: "INSERT INTO users (user_id, username, email, password_hash)" +
				" VALUES ({userID}, {username}, {email}, {passwordHash})",
			Values: []any{
				sq.UUIDParam("userID", userID),
				sq.StringParam("username", request.Username),
				sq.StringParam("email", request.Email),
				sq.StringParam("passwordHash", string(passwordHash)),
			},
		})
		if err != nil {
			var errcode string
			if nbrew.ErrorCode != nil {
				errcode = nbrew.ErrorCode(err)
			}
			if IsKeyViolation(nbrew.Dialect, errcode) {
				response.Errors["email"] = append(response.Errors["email"], ErrEmailAlreadyUsed)
				response.Status = ErrValidationFailed
				writeResponse(w, r, response)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		_, err = sq.ExecContext(r.Context(), tx, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO site_user (site_id, user_id) VALUES ({siteID}, {userID})",
			Values: []any{
				sq.UUIDParam("siteID", siteID),
				sq.UUIDParam("userID", userID),
			},
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		err = nbrew.FS.Mkdir("@"+request.Username, 0755)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		dirs := []string{
			"notes",
			"output",
			"output/images",
			"output/themes",
			"pages",
			"posts",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(path.Join("@"+request.Username, dir), 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}
		err = tx.Commit()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		response.Status = SignupSuccess
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}
