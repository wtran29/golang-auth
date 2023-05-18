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
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	errMsg := r.FormValue("msg")

	html := `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Home</title>
	</head>
	<body>
		<p>` + errMsg + `</p>
		<h1>Register</h1>
		<form action="/register" method="post">
			<input type="username" name="username" />
			<input type="password" name="password" />
			<input type="submit" />
		</form>
		<h1>Login</h1>
		<form action="/login" method="post">
			<label name="username">Username: </label>
			<input type="username" name="username" />
			<label name="password">Password: </label>
			<input type="password" name="password" />
			<input type="submit" />
		</form>
	</body>
	</html>`
	fmt.Fprint(w, html)
}

func register(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	un := r.FormValue("username")
	if un == "" {
		msg := url.QueryEscape("your username can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	pw := r.FormValue("password")
	if pw == "" {
		msg := url.QueryEscape("your password can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		errorMsg := url.QueryEscape("internal server error")
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	log.Println("password", pw)
	log.Println("bcrypt", hash)
	db[un] = hash

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	un := r.FormValue("username")
	if un == "" {
		msg := url.QueryEscape("your username can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	pw := r.FormValue("password")
	if pw == "" {
		msg := url.QueryEscape("your password can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	if _, ok := db[un]; !ok {
		msg := url.QueryEscape("username and password do not match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err := bcrypt.CompareHashAndPassword(db[un], []byte(pw))
	if err != nil {
		msg := url.QueryEscape("username and password do not match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	msg := url.QueryEscape("you logged in " + un)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}
