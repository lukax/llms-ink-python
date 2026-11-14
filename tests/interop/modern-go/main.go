package main

import (
	"context"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"os"
	"os/exec"
	"strings"
	"time"
)

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	forms := 0
	client := mcp.NewClient(&mcp.Implementation{Name: "llms-ink-interop", Version: "1"}, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			forms++
			if !strings.Contains(req.Params.Message, "Arguments (JSON)") || !strings.Contains(req.Params.Message, "policySha256") {
				return nil, fmt.Errorf("incomplete approval review")
			}
			if forms == 1 {
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
			}
			return &mcp.ElicitResult{Action: "decline"}, nil
		}})
	cmd := exec.Command(os.Args[1], "-m", "llms_ink.guard", "gateway", "--config", os.Args[2], "--client-protocol", "2026-07-28")
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, &mcp.ClientSessionOptions{ProtocolVersion: "2026-07-28"})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		return err
	}
	if len(listed.Tools) != 2 {
		return fmt.Errorf("wrong tool count")
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "mail__act", Arguments: map[string]any{"destination": "safe"}})
	if err != nil {
		return fmt.Errorf("approved call: %w", err)
	}
	if result.IsError || forms != 1 {
		return fmt.Errorf("approved call failed")
	}
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "docs__act", Arguments: map[string]any{"destination": "safe"}})
	if err == nil || forms != 2 {
		return fmt.Errorf("decline did not deny")
	}
	_, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "mail__act", Arguments: map[string]any{"destination": "outside"}})
	if err == nil || forms != 2 {
		return fmt.Errorf("policy refusal failed")
	}
	fmt.Println("Official MCP Go SDK: modern discovery, automatic approval continuation, accepted call, decline and exact-policy denial passed.")
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
