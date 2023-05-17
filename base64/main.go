package main

import (
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	msg := "This is a really, really long message to show how base64 works."
	encoded := encode(msg)
	fmt.Println("Encoded msg:", encoded)

	s, err := decode(encoded)
	if err != nil {
		log.Println(err)
	}

	fmt.Println("Decoded msg:", s)
}

func encode(msg string) string {
	return base64.URLEncoding.EncodeToString([]byte(msg))
}

func decode(encoded string) (string, error) {
	s, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("could not decode string %w", err)
	}
	return string(s), nil
}
