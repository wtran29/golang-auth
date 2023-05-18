package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	http.HandleFunc("/", foo)
	http.HandleFunc("/submit", bar)
	http.ListenAndServe(":8080", nil)

}

func getJWT(msg string) (string, error) {
	myKey := "secret key that no one knows 4242 long random words"

	type UserClaims struct {
		jwt.RegisteredClaims
		Email string
	}

	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		Email: msg,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	ss, err := token.SignedString([]byte(myKey))
	if err != nil {
		return "", fmt.Errorf("could not signed string %w", err)
	}
	return ss, nil

}

func bar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	email := r.FormValue("email")
	if email == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	ss, err := getJWT(email)
	if err != nil {
		http.Error(w, "could not getJWT", http.StatusInternalServerError)
		return
	}
	// "hash / message digest / hash value" | "what we stored"
	c := http.Cookie{
		Name:  "session-id",
		Value: ss,
	}

	http.SetCookie(w, &c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func foo(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session-id")
	if err != nil {
		c = &http.Cookie{}
	}

	// isEqual := true
	// xs := strings.SplitN(c.Value, "|", 2)
	// if len(xs) == 2 {
	// 	cCode := xs[0]
	// 	cEmail := xs[1]

	// 	code := getCode(cEmail)
	// 	isEqual = hmac.Equal([]byte(cCode), []byte(code))
	// }
	message := "Not logged in"
	if isEqual {
		message = "Logged in"
	}
	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>HMAC Example</title>
	</head>
	<body>
		<p>Cookie value: ` + c.Value + `</p>
		<p>` + message + `</p>
		<form action="/submit" method="post">
			<input type="email" name="email" />
			<input type="submit" />
		</form>
	</body>
	</html>`
	io.WriteString(w, html)
}
