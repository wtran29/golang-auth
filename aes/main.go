package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func main() {

	msg := "Testing with a really, really long message for aes encryption as an example."
	password := "abcd1234"
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		log.Fatalln("could not bcrypt password", err)
	}
	bs = bs[:16]

	result, err := encryptDecode(bs, msg)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("before base64", string(result))

	result2, err := encryptDecode(bs, string(result))
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(result2))

	// key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	// encrypted, err := encrypt([]byte("Hello World!"), key)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println(string(encrypted))

	// decrypted, err := encrypt(encrypted, key)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(string(decrypted))

}

func encrypt(message, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Error in encryption: %w", err)
	}

	stream := cipher.NewOFB(block, make([]byte, aes.BlockSize))
	buf := &bytes.Buffer{}
	wtr := cipher.StreamWriter{
		S: stream,
		W: buf,
	}

	_, err = wtr.Write(message)
	if err != nil {
		return nil, fmt.Errorf("Error in encryption: %w", err)
	}

	return buf.Bytes(), err
}

func encryptDecode(key []byte, input string) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not NewCipher %w", err)
	}

	// initialization vector
	iv := make([]byte, aes.BlockSize)

	s := cipher.NewCTR(b, iv)

	buff := &bytes.Buffer{}
	sw := cipher.StreamWriter{
		S: s,
		W: buff,
	}

	_, err = sw.Write([]byte(input))
	if err != nil {
		return nil, fmt.Errorf("could not sw.Write to StreamWriter %w", err)
	}
	return buff.Bytes(), nil
}
