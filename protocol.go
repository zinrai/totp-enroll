package main

// google-authenticator(1) writes the seed before asking for a code, and takes
// -1 as an answer, which leaves a user holding a seed their phone never
// received. Nothing is written here until a code comes back
type offer struct {
	QR    string `json:"qr"`
	URI   string `json:"uri"`
	Error string `json:"error,omitempty"`
}

type answer struct {
	Code string `json:"code"`
}

type result struct {
	Error string `json:"error,omitempty"`
}
