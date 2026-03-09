package mcpserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/alperen/opsfix/adapter"
	"github.com/alperen/opsfix/internal/dispatch"
)

const protocolVersion = "2024-11-05"

// MCPDispatcher is the interface the Server requires from its dispatcher.
type MCPDispatcher interface {
	Dispatch(req dispatch.Request) dispatch.Response
	AllTools() []adapter.ToolDefinition
}

type Server struct {
	dispatcher MCPDispatcher
	reader     *bufio.Reader
	encoder    *json.Encoder
}

func New(dispatcher MCPDispatcher) *Server {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	return &Server{
		dispatcher: dispatcher,
		reader:     bufio.NewReader(os.Stdin),
		encoder:    enc,
	}
}

// Run starts the JSON-RPC 2.0 loop over stdio.
func (s *Server) Run() error {
	fmt.Fprintln(os.Stderr, "[opsfix] MCP server started, listening on stdio")

	for {
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Fprintln(os.Stderr, "[opsfix] stdin closed, shutting down")
				return nil
			}
			return fmt.Errorf("read stdin: %w", err)
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, ErrCodeParseError, "parse error: "+err.Error())
			continue
		}

		if req.JSONRPC != "2.0" {
			s.sendError(req.ID, ErrCodeInvalidRequest, "jsonrpc must be '2.0'")
			continue
		}

		s.handle(req)
	}
}

func (s *Server) handle(req Request) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)

	case "notifications/initialized":
		// No response needed for notifications
		fmt.Fprintln(os.Stderr, "[opsfix] client initialized")

	case "tools/list":
		s.handleToolsList(req)

	case "tools/call":
		s.handleToolCall(req)

	case "ping":
		s.sendResult(req.ID, map[string]any{})

	default:
		s.sendError(req.ID, ErrCodeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) handleInitialize(req Request) {
	result := InitializeResult{
		ProtocolVersion: protocolVersion,
		ServerInfo: ServerInfo{
			Name:    "opsfix",
			Version: "0.2.0",
		},
		Capabilities: Capabilities{
			Tools: map[string]any{},
		},
	}
	s.sendResult(req.ID, result)
}

func (s *Server) handleToolsList(req Request) {
	adapterTools := s.dispatcher.AllTools()
	mcpTools := make([]ToolDefinition, 0, len(adapterTools))
	for _, t := range adapterTools {
		mcpTools = append(mcpTools, ToolDefinition{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	s.sendResult(req.ID, ToolsListResult{Tools: mcpTools})
}

func (s *Server) handleToolCall(req Request) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, ErrCodeInvalidParams, "invalid tool call params: "+err.Error())
		return
	}

	if params.Name == "" {
		s.sendError(req.ID, ErrCodeInvalidParams, "tool name is required")
		return
	}

	fmt.Fprintf(os.Stderr, "[opsfix] tool call: %s\n", params.Name)

	// Extract server and confirmed from arguments
	server, _ := params.Arguments["server"].(string)
	confirmed, _ := params.Arguments["confirmed"].(bool)

	dispResp := s.dispatcher.Dispatch(dispatch.Request{
		Tool:      params.Name,
		Server:    server,
		Params:    params.Arguments,
		Confirmed: confirmed,
	})

	// Format as MCP ToolResult
	var text string
	if dispResp.Error != "" {
		s.sendResult(req.ID, ToolResult{
			Content: []ContentBlock{{Type: "text", Text: dispResp.Error}},
			IsError: true,
		})
		return
	}
	if dispResp.Blocked {
		text = fmt.Sprintf("BLOCKED: %s\nRisk: %s\nAudit ID: %s", dispResp.Error, dispResp.Risk, dispResp.AuditID)
		s.sendResult(req.ID, ToolResult{
			Content: []ContentBlock{{Type: "text", Text: text}},
			IsError: true,
		})
		return
	}
	if dispResp.PendingApproval {
		text = fmt.Sprintf("Risk: %s\nTool: %s on server %q\nRe-call with confirmed=true to execute.", dispResp.Risk, params.Name, server)
		if dispResp.AuditID != "" {
			text += "\nAudit ID: " + dispResp.AuditID
		}
		s.sendResult(req.ID, ToolResult{
			Content: []ContentBlock{{Type: "text", Text: text}},
		})
		return
	}

	text = dispResp.Output
	if dispResp.AuditID != "" {
		text += "\n\nAudit ID: " + dispResp.AuditID
	}
	s.sendResult(req.ID, ToolResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
	})
}

func (s *Server) sendResult(id any, result any) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	if err := s.encoder.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "[opsfix] encode response: %v\n", err)
	}
}

func (s *Server) sendError(id any, code int, message string) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	}
	if err := s.encoder.Encode(resp); err != nil {
		fmt.Fprintf(os.Stderr, "[opsfix] encode error response: %v\n", err)
	}
}
