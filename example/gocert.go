package main

import (
	"fmt"
	"gocert"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <config> <name>\n", os.Args[0])
		os.Exit(1)
	}

	configPath, outputName := os.Args[1], os.Args[2]

	conf, err := gocert.LoadCertConfig(configPath)
	if err != nil {
		fmt.Printf("Cannot load cert config from '%s': %v\n", configPath, err)
		os.Exit(1)
	}

	cert, key, err := gocert.CreateCertificate(conf)
	if err != nil {
		fmt.Printf("Cannot create cert: %v\n", err)
		os.Exit(1)
	}

	exitCode := 0
	certPath, keyPath := outputName+".pem", outputName+".key"
	if err := os.WriteFile(certPath, cert, 0644); err != nil {
		fmt.Printf("Cannot save cert to '%s': %v\n", certPath, err)
		exitCode = 1
	} else {
		fmt.Printf("Cert saved to '%s'\n", certPath)
	}

	if err := os.WriteFile(keyPath, key, 0644); err != nil {
		fmt.Printf("Cannot save key to '%s': %v\n", keyPath, err)
		exitCode = 1
	} else {
		fmt.Printf("Key saved to '%s'\n", keyPath)
	}

	os.Exit(exitCode)
}
