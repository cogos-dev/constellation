// cmd/constellation/main.go — Thin entry point for go install support.
//
//	go install github.com/myrgic/constellation/cmd/constellation@latest
package main

import "github.com/myrgic/constellation"

func main() {
	constellation.Run()
}
