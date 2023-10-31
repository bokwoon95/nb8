package nb8

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

type Error string

const (
	// Class 00 - Success
	Success                     = Error("NB-00000 success")
	SignupSuccess               = Error("NB-00001 signup success")
	LoginSuccess                = Error("NB-00002 login success")
	LogoutSuccess               = Error("NB-00003 logout success")
	SentPaswordResetLinkSuccess = Error("NB-00004 sent password reset link successfully")
	ResetPasswordSuccess        = Error("NB-00005 reset password successfully")

	// Class 03 - General
	ErrAlreadyAuthenticated      = Error("NB-03000 already authenticated")
	ErrSignupsNotOpen            = Error("NB-03001 signups are not open")
	ErrInvalidToken              = Error("NB-03002 invalid token")
	ErrRetryWithCaptcha          = Error("NB-03003 retry with captcha")
	ErrCaptchaChallengeFailed    = Error("NB-03004 captcha challenge failed")
	ErrRequired                  = Error("NB-03005 required")
	ErrForbiddenCharacters       = Error("NB-03006 forbidden characters")
	ErrUsernameUnavailable       = Error("NB-03007 username unavailable")
	ErrInvalidEmail              = Error("NB-03008 invalid email")
	ErrEmailAlreadyUsed          = Error("NB-03009 email already used by an existing user account")
	ErrPasswordTooShort          = Error("NB-03010 password too short, minimum 8 characters")
	ErrPasswordTooCommon         = Error("NB-03011 password too common")
	ErrPasswordNotMatch          = Error("NB-03012 password does not match")
	ErrValidationFailed          = Error("NB-03013 validation failed")
	ErrIncorrectLoginCredentials = Error("NB-03014 incorrect login credentials")
	ErrUserNotFound              = Error("NB-03015 user not found")

	// Class 99 - HTTP equivalent
	ErrBadRequest           = Error("NB-99400 bad request")
	ErrNotAuthenticated     = Error("NB-99401 not authenticated")
	ErrNotAuthorized        = Error("NB-99403 not authorized")
	ErrNotFound             = Error("NB-99404 not found")
	ErrMethodNotAllowed     = Error("NB-99405 method not allowed")
	ErrUnsupportedMediaType = Error("NB-99415 unsupported media type")
	ErrServerError          = Error("NB-99500 server error")
)

func (e Error) Error() string {
	return string(e)
}

func (e Error) Success() bool {
	str := string(e)
	if len(str) > 8 && str[:3] == "NB-" && str[8] == ' ' {
		return str[3] == '0' && str[4] == '0'
	}
	return false
}

func (e Error) Code() string {
	str := string(e)
	if len(str) > 8 && str[:3] == "NB-" && str[8] == ' ' {
		return str[:8]
	}
	return ""
}

func (e Error) Message() string {
	code := e.Code()
	if code != "" {
		return strings.TrimSpace(strings.TrimPrefix(string(e), code))
	}
	return string(e)
}

func (e Error) Equal(target Error) bool {
	code := e.Code()
	if code != "" {
		return code == target.Code()
	}
	return string(e) == string(target)
}

func (e Error) Is(target error) bool {
	if target, ok := target.(Error); ok {
		return e.Equal(target)
	}
	return false
}

var errorTemplate = template.Must(template.
	New("error.html").
	Funcs(map[string]any{
		"safeHTML": func(v any) template.HTML {
			if str, ok := v.(string); ok {
				return template.HTML(str)
			}
			return ""
		},
	}).
	ParseFS(rootFS, "embed/error.html"),
)

func badRequest(w http.ResponseWriter, r *http.Request, serverErr error) {
	var msg string
	var maxBytesErr *http.MaxBytesError
	if errors.As(serverErr, &maxBytesErr) {
		msg = "the data you are sending is too big (max " + fileSizeToString(maxBytesErr.Limit) + ")"
	} else {
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if contentType == "application/json" {
			if serverErr == io.EOF {
				msg = "missing JSON body"
			} else if serverErr == io.ErrUnexpectedEOF {
				msg = "malformed JSON"
			} else {
				msg = serverErr.Error()
			}
		} else {
			msg = serverErr.Error()
		}
	}
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		serverErr = encoder.Encode(map[string]any{
			"status": string(ErrBadRequest) + ": " + msg,
		})
		if serverErr != nil {
			getLogger(r.Context()).Error(serverErr.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `400 bad request`,
		"Headline": "400 bad request",
		"Byline":   msg,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrBadRequest)+": "+msg, http.StatusBadRequest)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusBadRequest)
	buf.WriteTo(w)
}

func notAuthenticated(w http.ResponseWriter, r *http.Request) {
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrNotAuthenticated,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	var query string
	if r.Method == "GET" {
		if r.URL.RawQuery != "" {
			query = "?redirect=" + url.QueryEscape(r.URL.Path+"?"+r.URL.RawQuery)
		} else {
			query = "?redirect=" + url.QueryEscape(r.URL.Path)
		}
	}
	err := errorTemplate.Execute(buf, map[string]any{
		"Title":    `401 unauthorized`,
		"Headline": "401 unauthorized",
		"Byline":   fmt.Sprintf(`You are not authenticated, please <a href="/admin/login/%s" class="linktext">log in</a>.`, query),
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotAuthenticated), http.StatusUnauthorized)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusUnauthorized)
	buf.WriteTo(w)
}

func notAuthorized(w http.ResponseWriter, r *http.Request) {
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrNotAuthorized,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "403 forbidden",
		"Headline": "403 forbidden",
		"Byline":   "You do not have permission to view this page (try using a different account).",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotAuthorized), http.StatusForbidden)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusForbidden)
	buf.WriteTo(w)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrNotFound,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "404 not found",
		"Headline": "404 not found",
		"Byline":   "The page you are looking for does not exist.",
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotFound), http.StatusNotFound)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusNotFound)
	buf.WriteTo(w)
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": string(ErrMethodNotAllowed) + ": " + r.Method,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "405 method not allowed",
		"Headline": "405 method not allowed: " + r.Method,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrNotFound), http.StatusMethodNotAllowed)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusMethodNotAllowed)
	buf.WriteTo(w)
}

func unsupportedContentType(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")
	var msg string
	if contentType == "" {
		msg = "missing Content-Type"
	} else {
		msg = "unsupported Content-Type: " + contentType
	}
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrUnsupportedMediaType.Code() + " " + msg,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	err := errorTemplate.Execute(buf, map[string]any{
		"Referer":  r.Referer(),
		"Title":    "415 unsupported media type",
		"Headline": msg,
	})
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, ErrUnsupportedMediaType.Code()+" "+msg, http.StatusUnsupportedMediaType)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusUnsupportedMediaType)
	buf.WriteTo(w)
}

func internalServerError(w http.ResponseWriter, r *http.Request, serverErr error) {
	accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
	if accept == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(map[string]any{
			"status": ErrServerError,
		})
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	var data map[string]any
	if errors.Is(serverErr, context.DeadlineExceeded) {
		data = map[string]any{
			"Referer":  r.Referer(),
			"Title":    "deadline exceeded",
			"Headline": "The server took too long to respond.",
		}
	} else {
		data = map[string]any{
			"Referer":  r.Referer(),
			"Title":    "500 internal server error",
			"Headline": "500 internal server error",
			"Byline":   "The server encountered an error.",
			"Details":  serverErr.Error(),
		}
	}
	err := errorTemplate.Execute(buf, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, string(ErrServerError), http.StatusInternalServerError)
		return
	}
	contentSecurityPolicy(w, "", false)
	w.WriteHeader(http.StatusInternalServerError)
	buf.WriteTo(w)
}
