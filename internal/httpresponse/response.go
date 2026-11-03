package httpresponse

import (
	"encoding/json"
	"net/http"
)

const (
	jsonContentType = "application/json; charset=utf-8"
	noStorePolicy   = "no-store"
	successCode     = "success"
	successMessage  = "ok"
)

type envelope struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

// WriteSuccess writes a successful JSON response.
func WriteSuccess(writer http.ResponseWriter, status int, data any) {
	write(writer, status, envelope{Code: successCode, Msg: successMessage, Data: data})
}

// WriteError writes an error response with null data.
func WriteError(writer http.ResponseWriter, status int, code, message string) {
	write(writer, status, envelope{Code: code, Msg: message, Data: nil})
}

func write(writer http.ResponseWriter, status int, response envelope) {
	writer.Header().Set("Content-Type", jsonContentType)
	writer.Header().Set("Cache-Control", noStorePolicy)
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(response)
}
