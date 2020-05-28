package errors

import "net/http"

type ResErr struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

// NewBadRequestError for error template with status 400
func NewBadRequestError(message string) *ResErr {
	return &ResErr{
		Message: message,
		Status:  http.StatusBadRequest,
		Error:   "bad_request",
	}

}

// NewNotFoundError for error template with status 40
func NewNotFoundError(message string) *ResErr {
	return &ResErr{
		Message: message,
		Status:  http.StatusNotFound,
		Error:   "not_found",
	}
}

// NewInternalServerError something went wrong
func NewInternalServerError(message string) *ResErr {
	return &ResErr{
		Message: message,
		Status:  http.StatusInternalServerError,
		Error:   "internal_server_error",
	}
}
