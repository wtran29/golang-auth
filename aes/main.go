package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	f, err := os.Open("aes/sample-file.txt")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	h := sha256.New()

	_, err = io.Copy(h, f)
	if err != nil {
		log.Fatalln("could not io.copy", err)
	}

	fmt.Printf("here is the type BEFORE h.Sum: %T\n", h)
	fmt.Printf("%v\n", h)
	xb := h.Sum(nil)
	fmt.Printf("here is the type AFTER h.Sum: %T\n", xb)
	fmt.Printf("%x\n", xb)

	xb = h.Sum(nil)
	fmt.Printf("here is the type AFTER second h.Sum: %T\n", xb)
	fmt.Printf("%x\n", xb)

	xb = h.Sum(xb)
	fmt.Printf("here is the type AFTER third h.Sum: %T\n", xb)
	fmt.Printf("%x\n", xb)
}
