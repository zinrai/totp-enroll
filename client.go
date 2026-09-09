package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

func enrol(path string) error {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return err
	}
	defer conn.Close()

	dec := json.NewDecoder(conn)
	var o offer
	if err := dec.Decode(&o); err != nil {
		return err
	}
	if o.Error != "" {
		return fmt.Errorf("%s", o.Error)
	}

	fmt.Print(o.QR)
	fmt.Printf("\nScan the code, or enter the address by hand:\n\n  %s\n\n", o.URI)
	fmt.Print("Code from the app: ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}

	if err := json.NewEncoder(conn).Encode(answer{Code: strings.TrimSpace(line)}); err != nil {
		return err
	}

	var r result
	if err := dec.Decode(&r); err != nil {
		return err
	}
	if r.Error != "" {
		return fmt.Errorf("%s", r.Error)
	}

	fmt.Println("\nEnrolled. The next login will ask for a code.")
	return nil
}
