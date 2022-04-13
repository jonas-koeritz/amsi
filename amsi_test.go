package amsi_test

import (
	"fmt"
	"os"

	"github.com/jonas-koeritz/amsi"
)

func Example_scanBuffer() {
	// Read the file contents into a byte slice
	data, err := os.ReadFile("test.exe")
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

	// Open an AMSI session, this is not needed and the context can be used to scan data already
	amsiSession, err := amsiContext.OpenSession()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer amsiSession.Close()

	// Provide the data to AMSI through ScanBuffer
	result, err := amsiSession.ScanBuffer(data, "Content name")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Check if the result considers the data to be malware
	if result.IsMalware() {
		fmt.Printf("File contains malware. AMSI result: %d\n", result)
	} else {
		fmt.Printf("File seems to be clean. AMSI result: %d\n", result)
	}
}

func Example_scanString() {
	// Initialize an AMSI context
	amsiContext, err := amsi.Initialize("amsiscan")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer amsiContext.Close()

	// Open an AMSI session
	amsiSession, err := amsiContext.OpenSession()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer amsiSession.Close()

	// Scan a string for malware through ScanString
	result, err := amsiSession.ScanString("<string to be scanned for malware>", "It's just a string")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Check if the result considers the data to be malware
	if result.IsMalware() {
		fmt.Printf("File contains malware. AMSI result: %d\n", result)
	} else {
		fmt.Printf("File seems to be clean. AMSI result: %d\n", result)
	}
}

func Example_withoutSession() {
	// Initialize an AMSI context
	amsiContext, err := amsi.Initialize("amsiscan")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer amsiContext.Close()

	// Scan a string for malware through ScanString
	result, err := amsiContext.ScanString("<string to be scanned for malware>", "It's just a string", nil)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Check if the result considers the data to be malware
	if result.IsMalware() {
		fmt.Printf("File contains malware. AMSI result: %d\n", result)
	} else {
		fmt.Printf("File seems to be clean. AMSI result: %d\n", result)
	}
}
