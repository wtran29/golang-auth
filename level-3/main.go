package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}
}

var AWS_CLIENTSECRET = os.Getenv("AWS_ClientSecret")

var awsOauthConfig = &oauth2.Config{
	ClientID:     "amzn1.application-oa2-client.423e6afe25344a2da431d15c6a0cf647",
	ClientSecret: AWS_CLIENTSECRET,
	Endpoint:     amazon.Endpoint,
	RedirectURL:  "http://localhost:8080/oauth2/receive",
	Scopes:       []string{"profile"},
}

type user struct {
	password []byte
	email    string
}

type UserClaims struct {
	jwt.RegisteredClaims
	SessionID string
}

var db = map[string]user{}
var sessions = map[string]string{}

// key is uuid from oauth login, value is expiry time
var oAuthExp = map[string]time.Time{}

const key = "this is some secret key example 42 dont stop wont stop"

func main() {

	http.HandleFunc("/", home)
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.HandleFunc("/oauth/amazon/login", oAuthAmznLogin)
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

	errMsg := r.URL.Query().Get("msg")

	fmt.Fprintf(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Home</title>
	</head>
	<body>
		<p>User: `+un+` Email: `+e+`</p>
		<p>`+errMsg+`</p>
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
		<h1>Login</h1>
		<form action="/logout" method="POST">
			<input type="submit" value="Logout" />
		</form>
	</body>
	</html>`)
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

	sUUID := uuid.New().String()
	sessions[sUUID] = un
	token, err := createToken(sUUID)
	if err != nil {
		log.Println("could not create token in login", err)
		msg := url.QueryEscape("token not created. internal server error.")
		http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
		return
	}

	c := http.Cookie{
		Name:  "session-id",
		Value: token,
	}

	http.SetCookie(w, &c)

	msg := url.QueryEscape("you logged in " + un)
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

func createToken(sid string) (string, error) {
	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		SessionID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	ss, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("could not sign token in createToken %w", err)
	}
	return ss, nil

	// mac := hmac.New(sha256.New, []byte(key))
	// _, err := mac.Write([]byte(sid))
	// if err != nil {
	// 	return "", fmt.Errorf("Error while trying to hash the session id", err)
	// }
	// hex
	// signedMac := fmt.Sprintf("%x", mac.Sum(nil))

	// base64
	// signedMac := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	// return signedMac + "|" + sid, nil

}

func parseToken(signedToken string) (string, error) {

	token, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims invalid signing algorithm")
		}
		return []byte(key), nil
	})
	if err != nil {
		return "", fmt.Errorf("could not ParseWithClaims in parseToken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parseToken")
	}

	return token.Claims.(*UserClaims).SessionID, nil
	// xs := strings.SplitN(signedToken, "|", 2)
	// if len(xs) != 2 {
	// 	return "", fmt.Errorf("stop hacking me wrong number of items in string parseToken")
	// }

	// b64 := xs[0]
	// xb, err := base64.StdEncoding.DecodeString(b64)
	// if err != nil {
	// 	return "", fmt.Errorf("could not parseToken decodestring %w", err)
	// }

	// mac := hmac.New(sha256.New, []byte(key))
	// mac.Write([]byte(xs[1]))

	// ok := hmac.Equal(xb, mac.Sum(nil))
	// if !ok {
	// 	return "", fmt.Errorf("could not parseToken not equal signed sig and sid")
	// }
	// return xs[1], nil
}

func getJWT(sid string) (string, error) {
	claims := UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		SessionID: sid,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, &claims)
	ss, err := token.SignedString([]byte(key))
	if err != nil {
		return "", fmt.Errorf("SignedString failed %w", err)
	}
	return ss, nil
}

func oAuthAmznLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	id := uuid.New().String()
	oAuthExp[id] = time.Now().Add(time.Hour)

	// redirect to amazon at the AuthURL endpoint
	http.Redirect(w, r, awsOauthConfig.AuthCodeURL(id), http.StatusSeeOther)
	return
}
