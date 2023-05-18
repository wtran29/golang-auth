package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/crypto/bcrypt"
)

var db = map[string][]byte{}

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/register", register)
	http.ListenAndServe(":8080", nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	errMsg := r.FormValue("errormsg")

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Home</title>
	</head>
	<body>
		<p>If there was any ERROR, it is:` + errMsg + `</p>
		<form action="/register" method="post">
			<input type="username" name="username" />
			<input type="password" name="password" />
			<input type="submit" />
		</form>
	</body>
	</html>`
	fmt.Fprint(w, html)
}

func register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		errorMsg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?errormsg="+errorMsg, http.StatusSeeOther)
		return
	}

	un := r.FormValue("username")
	if un == "" {
		errorMsg := url.QueryEscape("your username can not be empty")
		http.Redirect(w, r, "/?errormsg="+errorMsg, http.StatusSeeOther)
		return
	}
	pw := r.FormValue("password")
	if pw == "" {
		errorMsg := url.QueryEscape("your password can not be empty")
		http.Redirect(w, r, "/?errormsg="+errorMsg, http.StatusSeeOther)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		errorMsg := url.QueryEscape("internal server error")
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	log.Println("password", un)
	log.Println("bcrypt", hash)
	db[un] = hash

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
