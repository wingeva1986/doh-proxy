package main

import (
	handler "fengqi/vercel-go-query/api"
	"net/http"
)

func main() {
	http.HandleFunc("/", handler.Handler)
	http.ListenAndServe(":5353", nil)
}
