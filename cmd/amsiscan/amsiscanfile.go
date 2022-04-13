// The amsiscanfile command is a simple example on how to use the amsi package to scan arbitrary files.
package main

import (
	"fmt"
	"os"

	"github.com/jonas-koeritz/go-amsi/amsi"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <filename>\n", os.Args[0])
		return
	}

	// Read the file contents into a byte slice
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Failed to read input file: %s\n", err)
		return
	}

	// Initialize an AMSI context
	amsiContext, err := amsi.Initialize("amsiscan")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer amsiContext.Close()

	// Provide the data to AMSI through ScanBuffer
	result, err := amsiContext.ScanBuffer(data, os.Args[1], nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Check if the result considers the data to be malware
	if result.IsMalware() {
		fmt.Printf("\"%s\" contains malware. AMSI result: %d\n", os.Args[1], result)
	} else {
		fmt.Printf("\"%s\" seems to be clean. AMSI result: %d\n", os.Args[1], result)
	}
}
