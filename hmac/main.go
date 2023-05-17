package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
)

func getCode(data string) string {
	h := hmac.New(sha256.New, []byte("ourkey"))
	io.WriteString(h, data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session-id")
		// cookie is not set
		if err != nil {
			//id, _ := uuid.NewV4()
			cookie = &http.Cookie{
				Name: "session-id",
			}
		}

		if r.FormValue("email") != "" {
			cookie.Value = r.FormValue("email")
		}

		code := getCode(cookie.Value)
		cookie.Value = code + "|" + cookie.Value

		// this does not run
		// need to complete code
		// shown as example of how to authenticate with HMAC

		http.SetCookie(w, cookie)

	})
}
