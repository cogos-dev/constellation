// run.go — Constellation Protocol PoC CLI entry point.
//
// Subcommands:
//   node    — Start a constellation node
//   inject  — Inject an event into a running node
//   tamper  — Corrupt an event in a node's git store
//   status  — Query a node's state and peer trust
package constellation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Run is the CLI entry point for the constellation binary.
func Run() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "node":
		cmdNode()
	case "inject":
		cmdInject()
	case "tamper":
		cmdTamper()
	case "status":
		cmdStatus()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: constellation-poc <command> [flags]

Commands:
  node    --name NAME --port PORT [--peers HOST:PORT,...]  Start a node
  inject  --target URL --event JSON                        Inject an event
  tamper  --target URL                                     Corrupt an event
  status  --target URL                                     Query node state
`)
}

func cmdNode() {
	var name string
	var port int
	var peersStr string
	var dataDir string
	var hostname string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			i++
			name = args[i]
		case "--port":
			i++
			_, _ = fmt.Sscanf(args[i], "%d", &port)
		case "--peers":
			i++
			peersStr = args[i]
		case "--data-dir":
			i++
			dataDir = args[i]
		case "--hostname":
			i++
			hostname = args[i]
		}
	}

	if name == "" {
		name = fmt.Sprintf("node-%d", port)
	}
	if port == 0 {
		port = 8100
	}

	var peers []string
	if peersStr != "" {
		peers = strings.Split(peersStr, ",")
	}

	node, err := NewNode(name, port, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create node: %v\n", err)
		os.Exit(1)
	}
	if hostname != "" {
		node.Hostname = hostname
	}

	// Graceful shutdown.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		node.Stop()
		os.Exit(0)
	}()

	if err := node.Start(peers); err != nil {
		fmt.Fprintf(os.Stderr, "node error: %v\n", err)
		os.Exit(1)
	}
}

func cmdInject() {
	var target, eventJSON string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			i++
			target = args[i]
		case "--event":
			i++
			eventJSON = args[i]
		}
	}

	if target == "" || eventJSON == "" {
		fmt.Fprintln(os.Stderr, "usage: constellation-poc inject --target URL --event JSON")
		os.Exit(1)
	}

	// Send as a custom event via heartbeat-like injection.
	url := fmt.Sprintf("%s/challenge", target)
	resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(eventJSON)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "inject failed: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		fmt.Fprintf(os.Stderr, "read response failed: %v\n", err)
	}
	fmt.Println()
}

func cmdTamper() {
	var target string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			i++
			target = args[i]
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: constellation-poc tamper --target URL")
		os.Exit(1)
	}

	// Get current state to find the latest seq.
	resp, err := http.Get(fmt.Sprintf("%s/state", target))
	if err != nil {
		fmt.Fprintf(os.Stderr, "get state failed: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = resp.Body.Close() }()

	var state struct {
		State struct {
			Seq int64 `json:"seq"`
		} `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		fmt.Fprintf(os.Stderr, "decode state failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Node has %d events. Tampering is done via docker exec (see test scripts).\n", state.State.Seq)
}

func cmdStatus() {
	var target string

	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			i++
			target = args[i]
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: constellation-poc status --target URL")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Get state.
	stateResp, err := client.Get(fmt.Sprintf("%s/state", target))
	if err != nil {
		fmt.Fprintf(os.Stderr, "get state failed: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = stateResp.Body.Close() }()

	var stateData json.RawMessage
	if err := json.NewDecoder(stateResp.Body).Decode(&stateData); err != nil {
		fmt.Fprintf(os.Stderr, "decode state failed: %v\n", err)
		os.Exit(1)
	}

	// Get health.
	healthResp, err := client.Get(fmt.Sprintf("%s/health", target))
	if err != nil {
		fmt.Fprintf(os.Stderr, "get health failed: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = healthResp.Body.Close() }()

	var healthData json.RawMessage
	if err := json.NewDecoder(healthResp.Body).Decode(&healthData); err != nil {
		fmt.Fprintf(os.Stderr, "decode health failed: %v\n", err)
		os.Exit(1)
	}

	output := map[string]json.RawMessage{
		"state":  stateData,
		"health": healthData,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "encode output failed: %v\n", err)
		os.Exit(1)
	}
}
