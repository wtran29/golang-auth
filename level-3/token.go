package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
	jwt.RegisteredClaims
	SessionID string
}

const key = "this is some secret key example 42 dont stop wont stop"

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
