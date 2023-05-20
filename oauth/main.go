package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Key is github id, value is user id
var githubConnections map[string]string

// {"data":{"viewer":{"id":"MDQ6VXNlcjE3Mjg3NjM2"}}}
type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json: "viewer"`
	} `json: "data"`
}

var githubOauthConfig = &oauth2.Config{
	ClientID:     "98f0d23316387503378b",
	ClientSecret: getClientSecret(),
	Endpoint:     github.Endpoint,
}

func getClientSecret() string {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file")
	}
	return os.Getenv("GH_ClientSecret")
}

func main() {

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/github", startGithubOauth)
	http.HandleFunc("/oauth2/receive", completeGithubOauth)
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Document</title>
	</head>
	<body>
		<form action="/oauth/github" method="post">
			<input type="submit" value="Login with Github">
		</form>
	</body>
	</html>`)
}

func startGithubOauth(w http.ResponseWriter, r *http.Request) {
	redirectURL := githubOauthConfig.AuthCodeURL("0000")
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func completeGithubOauth(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	if state != "0000" {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	token, err := githubOauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Could not login", http.StatusInternalServerError)
		return
	}

	ts := githubOauthConfig.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), ts)

	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	resp, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "could not get user", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// BELOW CODE WAS USED TO GET THE JSON RESPONSE from requestBody
	// bs, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	http.Error(w, "could not read github information", http.StatusInternalServerError)
	// 	return
	// }
	// log.Println(string(bs))

	var gr githubResponse
	err = json.NewDecoder(resp.Body).Decode(&gr)
	if err != nil {
		http.Error(w, "Github invalid response", http.StatusInternalServerError)
		return
	}
	githubID := gr.Data.Viewer.ID
	userID, ok := githubConnections[githubID]
	if !ok {
		// New user, create account
	}
	// Login to account userID using JWT
}
