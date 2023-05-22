package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

func setClientSecret() string {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}
	return os.Getenv("AWS_ClientSecret")
}

var AWS_CLIENTSECRET = os.Getenv("AWS_ClientSecret")
var awsOauthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.423e6afe25344a2da431d15c6a0cf647",
	ClientSecret: setClientSecret(),
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth/amazon/receive",
	Scopes:       []string{"profile"},
}

type user struct {
	password []byte
	email    string
	name     string
	// username string
}

// temporary set for test
var db = map[string]user{}

var sessions = map[string]string{}

// key is uuid from oauth login, value is expiry time
var oAuthExp = map[string]time.Time{}

var oAuthConn = map[string]string{}

func main() {
	http.HandleFunc("/", home)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/oauth/amazon/login", oAuthAmznLogin)
	http.HandleFunc("/oauth/amazon/receive", oAuthAmznReceive)
	http.HandleFunc("/partial-register", partialRegister)
	http.HandleFunc("/oauth/amazon/register", oAuthAmznRegister)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":8080", nil)
}

func home(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session-id")
	if err != nil {
		c = &http.Cookie{
			Name:  "session-id",
			Value: "",
		}
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}
	var un string
	if sid != "" {
		un = sessions[sid]
	}
	var e string
	if user, ok := db[un]; ok {
		e = user.email
	}

	errMsg := r.FormValue("msg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Home</title>
	</head>
	<body>
		<p>User: %s Email: %s </p>
		<p>%s</p>
		<h1>Register</h1>
		<form action="/register" method="POST">
			<label for="username">Username: </label>
			<input type="text" name="username" />
			<label for="email">Email: </label>
			<input type="email" name="email" />
			<label for="password">Password: </label>
			<input type="password" name="password" />
			<input type="submit" value="Register" />
		</form>
		<h1>Login</h1>
		<form action="/login" method="POST">
			<label for="username">Username: </label>
			<input type="text" name="username" />
			<label for="password">Password: </label>
			<input type="password" name="password" />
			<input type="submit" value="Login" />
		</form>
		<h1>Login with Amazon</h1>
		<form action="/oauth/amazon/login" method="POST">
			<input type="image" src="https://images-na.ssl-images-amazon.com/images/G/01/lwa/btnLWA_gold_156x32.png"
			alt="Login with Amazon" width="156" height="32"/>
		</form>
		<h1>Logout</h1>
		<form action="/logout" method="POST">
			<input type="submit" value="Logout" />
		</form>
	</body>
	</html>`, un, e, errMsg)
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

	e := r.FormValue("email")
	if e == "" {
		msg := url.QueryEscape("your email can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	hashedPW, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		errorMsg := url.QueryEscape("internal server error")
		http.Error(w, errorMsg, http.StatusInternalServerError)
		return
	}
	log.Println("password", pw)
	log.Println("bcrypt", hashedPW)
	db[un] = user{
		email:    e,
		password: hashedPW,
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
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

	err := bcrypt.CompareHashAndPassword(db[un].password, []byte(pw))
	if err != nil {
		msg := url.QueryEscape("username and password do not match")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	err = createSession(un, w)
	if err != nil {
		log.Println("could not createSession in login", err)
		msg := url.QueryEscape("token not created. internal server error.")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + un)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func createSession(un string, w http.ResponseWriter) error {
	sUUID := uuid.New().String()
	sessions[sUUID] = un
	token, err := createToken(sUUID)
	if err != nil {
		return fmt.Errorf("could not create token in createSession %w", err)
	}

	c := http.Cookie{
		Name:  "session-id",
		Value: token,
		Path:  "/",
	}

	http.SetCookie(w, &c)
	return nil
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	c, err := r.Cookie("session-id")
	if err != nil {
		c = &http.Cookie{
			Name:  "session-id",
			Value: "",
		}
	}

	sid, err := parseToken(c.Value)
	if err != nil {
		log.Println("index parseToken", err)
	}
	delete(sessions, sid)
	c.MaxAge = -1
	http.SetCookie(w, c)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// func getJWT(sid string) (string, error) {
// 	claims := UserClaims{
// 		RegisteredClaims: jwt.RegisteredClaims{
// 			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
// 		},
// 		SessionID: sid,
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodES256, &claims)
// 	ss, err := token.SignedString([]byte(key))
// 	if err != nil {
// 		return "", fmt.Errorf("SignedString failed %w", err)
// 	}
// 	return ss, nil
// }

func oAuthAmznLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	id := uuid.New().String()
	oAuthExp[id] = time.Now().Add(time.Hour)

	// redirect to amazon at the AuthURL endpoint
	// adds state, scope, client id
	http.Redirect(w, r, awsOauthConfig.AuthCodeURL(id), http.StatusSeeOther)

}

func oAuthAmznReceive(w http.ResponseWriter, r *http.Request) {

	// code is given by amazon
	code := r.FormValue("code")
	if code == "" {
		msg := url.QueryEscape("code was empty in oAuthAmznReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	state := r.FormValue("state")
	if state == "" {
		msg := url.QueryEscape("state was empty in oAuthAmznReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	expiry := oAuthExp[state]
	if time.Now().After(expiry) {
		msg := url.QueryEscape("oauth time expired in oAuthAmznReceive")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	// exchange the amazon code for a token
	// uses the client secret and TokenURL is called
	// we get back a token
	token, err := awsOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		msg := url.QueryEscape("could not do oauth exchange: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	// will look for an access token or refresh token and return a token source
	// which has method token()
	ts := awsOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)

	res, err := client.Get("https://api.amazon.com/user/profile")
	if err != nil {
		msg := url.QueryEscape("could not get amazon data: " + err.Error())
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	defer res.Body.Close()

	// bs, err := io.ReadAll(res.Body)
	// if err != nil {
	// 	msg := url.QueryEscape("could not read amazon information: " + err.Error())
	// 	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
	// 	return
	// }

	if res.StatusCode < 200 || res.StatusCode > 299 {
		msg := url.QueryEscape("not status 200: " + res.Status)
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	// fmt.Println(string(bs))

	// io.WriteString(w, string(bs))

	type AmazonProfile struct {
		Email  string `json:"email"`
		Name   string `json:"name"`
		UserID string `json:"user_id"`
	}

	var ap AmazonProfile

	err = json.NewDecoder(res.Body).Decode(&ap)
	if err != nil {
		msg := url.QueryEscape("not able to decode json response")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	user, ok := oAuthConn[ap.UserID]
	if !ok {
		signedToken, err := createToken(ap.UserID)
		if err != nil {
			log.Println("could not createToken in oAuthAmznReceive", err)
			msg := url.QueryEscape("token not created. internal server error.")
			http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
			return
		}

		uv := url.Values{}
		uv.Add("sst", signedToken)
		uv.Add("name", ap.Name)
		uv.Add("email", ap.Email)
		http.Redirect(w, r, "/partial-register?"+uv.Encode(), http.StatusSeeOther)
		return
	}

	err = createSession(user, w)
	if err != nil {
		log.Println("could not createSession in oAuthAmznReceive", err)
		msg := url.QueryEscape("session not created. internal server error.")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	msg := url.QueryEscape("you logged in " + user)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)

}

func partialRegister(w http.ResponseWriter, r *http.Request) {
	sst := r.FormValue("sst")
	name := r.FormValue("name")
	email := r.FormValue("email")

	if sst == "" {
		log.Println("could not get sst in partialRegister")
		msg := url.QueryEscape("could not get sst. internal server error.")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}
	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Document</title>
	</head>
	<body>
		<form action="/oauth/amazon/register" method="post">
			<label for="name">Full Name</label>
			<input type="text" name="name" id="name" value="%s">
			<label for="username">Username</label>
			<input type="text" name="username" id="username">
			<label for="email">Email</label>
			<input type="text" name="email" id="email" value="%s">
			<input type="hidden" value="%s" name="oauthID">
			<input type="submit">
		</form>
	</body>
	</html>`, name, email, sst)
}

func oAuthAmznRegister(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		msg := url.QueryEscape("your method was not post")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	e := r.FormValue("email")
	if e == "" {
		msg := url.QueryEscape("your email can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		msg := url.QueryEscape("your name can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	un := r.FormValue("username")
	if un == "" {
		msg := url.QueryEscape("your username can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	oauthID := r.FormValue("oauthID")
	if oauthID == "" {
		log.Println("oauthID came through as empty at oAuthAmznRegister")
		msg := url.QueryEscape("your oauthID can not be empty")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	amznUID, err := parseToken(oauthID)
	if err != nil {
		log.Println("could not parseToken to set amznID at oAuthAmznRegister")
		msg := url.QueryEscape("there was an issue")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	db[un] = user{
		name:  name,
		email: e,
	}

	oAuthConn[amznUID] = e

	err = createSession(un, w)
	if err != nil {
		log.Println("could not createSession in oAuthAmznRegister", err)
		msg := url.QueryEscape("token not created. internal server error.")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
