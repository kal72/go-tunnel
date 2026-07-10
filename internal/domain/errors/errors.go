package errors

import "errors"

var (
	ErrNotFound       = errors.New("resource not found")
	ErrUnauthorized   = errors.New("unauthorized access")
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidInput   = errors.New("invalid input")
	ErrAlreadyExists  = errors.New("resource already exists")
	ErrInternalServer = errors.New("internal server error")
)
