package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/relay"
)

// runFill fills a sealed request from a terminal, without the web page's
// JavaScript (threat model T-13). It never prints the secret.
//
//	secrethandoff fill <link>
//	secrethandoff fill --stdin --code XXXXX-XXXXX <link>
func runFill(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var link, wantCode string
	fromStdin := false
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--stdin":
			fromStdin = true
		case args[i] == "--code" && i+1 < len(args):
			wantCode = strings.ToUpper(args[i+1])
			i++
		default:
			link = args[i]
		}
	}
	if link == "" {
		fmt.Fprintln(stderr, "usage: secrethandoff fill [--stdin --code XXXXX-XXXXX] <link>")
		return 2
	}
	if err := fill(link, wantCode, fromStdin, stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "secrethandoff fill:", err)
		return 1
	}
	return 0
}

func fill(link, wantCode string, fromStdin bool, stdin io.Reader, stdout io.Writer) error {
	l, err := relay.ParseLink(link)
	if err != nil {
		return err
	}
	client, err := relay.NewClient(l.Base)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	v, err := client.Fetch(ctx, l)
	if err != nil {
		return err
	}
	if v.State != "pending" {
		return fmt.Errorf("this request is %s", v.State)
	}
	var raw policy.Policy
	if err := json.Unmarshal([]byte(v.Policy), &raw); err != nil {
		return errors.New("the request has an invalid policy")
	}
	p, err := policy.Parse(raw)
	if err != nil {
		return fmt.Errorf("the request has an invalid policy: %v", err)
	}
	code := relay.PairingCode(l.PublicKey)
	// Requester text is cleaned of control and direction characters, and
	// the pairing code comes last, so that text cannot fake or hide it.
	fmt.Fprintf(stdout, "An agent asks for a secret.\n\nReason, written by the requester:\n  %s\n\nWhere the secret can go:\n  %s\n\nPairing code: %s\n",
		strings.ReplaceAll(relay.CleanText(v.Reason), "\n", "\n  "), relay.CleanText(p.Describe()), code)

	var value []byte
	if fromStdin {
		if wantCode != code {
			return errors.New("with --stdin, pass --code with the pairing code that your own computer shows")
		}
		value, err = io.ReadAll(io.LimitReader(stdin, 48*1024))
		if err != nil {
			return err
		}
		value = []byte(strings.TrimRight(string(value), "\r\n"))
	} else {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return errors.New("no terminal: use --stdin with --code")
		}
		fmt.Fprint(stdout, "\nContinue only if your own computer shows this code. Continue? [y/N] ")
		answer, _ := bufio.NewReader(stdin).ReadString('\n')
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return errors.New("cancelled; nothing was sent")
		}
		fmt.Fprint(stdout, "Secret (not shown as you type): ")
		value, err = term.ReadPassword(fd)
		fmt.Fprintln(stdout)
		if err != nil {
			return err
		}
	}
	defer func() {
		for i := range value {
			value[i] = 0
		}
	}()
	if len(value) == 0 {
		return errors.New("the secret is empty; nothing was sent")
	}
	if err := client.Fill(ctx, l, v, value); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nSecret sent. It is encrypted for the program that asked, and the service cannot read it.\nConfirmation code: %s\nYour agent may ask you for this code before it uses the secret.\n", client.LastConfirmation)
	return nil
}
