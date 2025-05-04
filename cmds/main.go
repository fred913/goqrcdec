package main

import (
	"fmt"
	"os"

	"github.com/fred913/goqrcdec"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: qrcdec <file>")
		os.Exit(1)
	}

	result, err := goqrcdec.DecodeFile(os.Args[1])
	if err != nil {
		fmt.Println("Error decoding:", err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}
