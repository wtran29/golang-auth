package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type userClaims struct {
	jwt.RegisteredClaims
	SessionID int64
}

func (c *userClaims) Valid() error {
	zeroTime := time.Time{}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(zeroTime) {
		return fmt.Errorf("Token has expired")
	}
	if c.SessionID == 0 {
		return fmt.Errorf("Invalid session id")
	}
	return nil
}

var key = []byte{}

func main() {
	for i := 1; i <= 64; i++ {
		key = append(key, byte(i))
	}
	pass := "123456789"

	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}

	err = comparePassword(pass, hashedPass)
	if err != nil {
		log.Fatalln("Not logged in")
	}

	log.Println("logged in!")

	// fmt.Println(base64.StdEncoding.EncodeToString([]byte("user:pass")))
}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error) {
	h := hmac.New(sha512.New, key)
	_, err := h.Write(msg)
	if err != nil {
		return nil, fmt.Errorf("Error signMessage while hashing message: %w", err)
	}
	signature := h.Sum(nil)
	return signature, nil

}

func checkSig(msg, sig []byte) (bool, error) {
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSig while getting signature of message %w", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}

func createToken(c *userClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token: %w", err)
	}
	return signedToken, nil
}
