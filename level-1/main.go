package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type person struct {
	First string
}

func main() {

	http.HandleFunc("/encode", encodeSlice)
	http.HandleFunc("/decode", decodeSlice)
	http.ListenAndServe(":8080", nil)
}

func encodeSlice(w http.ResponseWriter, r *http.Request) {

	p1 := person{
		First: "Jimmy",
	}
	p2 := person{
		First: "John",
	}
	people := []person{p1, p2}

	err := json.NewEncoder(w).Encode(people)
	if err != nil {
		log.Println("encoded bad data", err)
	}
}

func decodeSlice(w http.ResponseWriter, r *http.Request) {
	people := []person{}
	err := json.NewDecoder(r.Body).Decode(&people)
	if err != nil {
		log.Println("decoded bad data", err)
	}
	fmt.Println("Person:", people)
}
