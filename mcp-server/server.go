package mcpserver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const protocolVersion = "2024-11-05"

type Server struct {
	dispatcher *Dispatcher
	reader     *bufio.Reader
	encoder    *json.Encoder
}

func New(dispatcher *Dispatcher) *Server {
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
			Version: "0.1.0",
		},
		Capabilities: Capabilities{
			Tools: map[string]any{},
		},
	}
	s.sendResult(req.ID, result)
}

func (s *Server) handleToolsList(req Request) {
	s.sendResult(req.ID, ToolsListResult{Tools: allTools()})
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

	result := s.dispatcher.Dispatch(params)
	s.sendResult(req.ID, result)
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
