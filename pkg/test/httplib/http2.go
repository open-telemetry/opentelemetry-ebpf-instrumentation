package httplib

import (
	"crypto/tls"
	"net/http"
)

// NewHTTP2Transport creates an HTTP transport configured
// to use HTTP/2 with TLS verification disabled.
func NewHTTP2Transport() *http.Transport {
	protocols := &http.Protocols{}
	protocols.SetHTTP2(true)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Protocols = protocols
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return tr
}
