package nb8

type Status string

const (
	// Class 00 - Success
	Success = Status("NB-00000 success")

	// Class 03 - General

	// Class 99 - HTTP equivalent
	ErrBadRequest           = Status("NB-99400 bad request")
	ErrNotAuthenticated     = Status("NB-99401 not authenticated")
	ErrNotAuthorized        = Status("NB-99403 not authorized")
	ErrNotFound             = Status("NB-99404 not found")
	ErrMethodNotAllowed     = Status("NB-99405 method not allowed")
	ErrUnsupportedMediaType = Status("NB-99415 unsupported media type")
	ErrServerError          = Status("NB-99500 server error")
)
