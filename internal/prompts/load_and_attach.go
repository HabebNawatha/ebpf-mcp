package prompts

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sameehj/ebpf-mcp/internal/tools"
	"github.com/sameehj/ebpf-mcp/pkg/types"
)

func init() {
	RegisterPrompt(types.Prompt{
		ID:          "load_and_attach",
		Description: "Loads an eBPF program and attaches it to a kernel hook with comprehensive error handling and validation.",
		Arguments: []mcp.PromptOption{
			// Required arguments
			mcp.WithArgument("source_type",
				mcp.ArgumentDescription("Source type: 'file', 'url', or 'data' (for base64)"),
				mcp.RequiredArgument()),
			mcp.WithArgument("source_value",
				mcp.ArgumentDescription("Path, URL, or base64 blob of the eBPF object"),
				mcp.RequiredArgument()),
			mcp.WithArgument("program_type",
				mcp.ArgumentDescription("eBPF program type: XDP, KPROBE, TRACEPOINT, or CGROUP_SKB"),
				mcp.RequiredArgument()),
			mcp.WithArgument("attach_type",
				mcp.ArgumentDescription("Attach type: xdp, kprobe, kretprobe, tracepoint, or cgroup"),
				mcp.RequiredArgument()),
			mcp.WithArgument("target",
				mcp.ArgumentDescription("Target interface (for XDP), function name (for kprobe), or cgroup path"),
				mcp.RequiredArgument()),
			// Optional arguments
			mcp.WithArgument("section",
				mcp.ArgumentDescription("Optional: Specific section name in the eBPF object")),
			mcp.WithArgument("btf_path",
				mcp.ArgumentDescription("Optional: Path to BTF file for enhanced debugging")),
			mcp.WithArgument("pin_path",
				mcp.ArgumentDescription("Optional: Path to pin the link object for persistence")),
			mcp.WithArgument("checksum",
				mcp.ArgumentDescription("Optional: SHA256 checksum for source validation (format: sha256:hash)")),
			mcp.WithArgument("flags",
				mcp.ArgumentDescription("Optional: Attachment flags as integer")),
			mcp.WithArgument("priority",
				mcp.ArgumentDescription("Optional: Attachment priority as integer")),
			mcp.WithArgument("verify_only",
				mcp.ArgumentDescription("Optional: Set to 'true' to only verify without loading (default: false)")),
		},
		Handler: func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			args := req.Params.Arguments

			// Validate required arguments
			requiredArgs := []string{"source_type", "source_value", "program_type", "attach_type", "target"}
			for _, arg := range requiredArgs {
				if _, exists := args[arg]; !exists {
					return nil, fmt.Errorf("missing required argument: %s", arg)
				}
			}

			// Validate source_type
			sourceType := args["source_type"]
			if !isValidSourceType(sourceType) {
				return nil, fmt.Errorf("invalid source_type '%s'. Must be 'file', 'url', or 'data'", sourceType)
			}

			// Validate program_type
			programType := args["program_type"]
			if !isValidProgramType(programType) {
				return nil, fmt.Errorf("invalid program_type '%s'. Must be XDP, KPROBE, TRACEPOINT, or CGROUP_SKB", programType)
			}

			// Validate attach_type
			attachType := args["attach_type"]
			if !isValidAttachType(attachType) {
				return nil, fmt.Errorf("invalid attach_type '%s'. Must be xdp, kprobe, kretprobe, tracepoint, or cgroup", attachType)
			}

			// Build source object based on type
			sourceObj := buildSourceObject(sourceType, args["source_value"], args)

			// Build load program request
			loadRequest := map[string]interface{}{
				"source":       sourceObj,
				"program_type": programType,
			}

			// Add optional parameters for loading
			if section, exists := args["section"]; exists && section != "" {
				loadRequest["section"] = section
			}
			if btfPath, exists := args["btf_path"]; exists && btfPath != "" {
				loadRequest["btf_path"] = btfPath
			}

			// Add constraints if verify_only is specified
			if verifyOnly, exists := args["verify_only"]; exists && verifyOnly == "true" {
				loadRequest["constraints"] = map[string]interface{}{
					"verify_only": true,
				}
			}

			// Step 1: Load the eBPF program
			loadResp, err := tools.CallRaw("load_program", loadRequest)
			if err != nil {
				return createErrorResult(fmt.Sprintf("Failed to load eBPF program: %v", err))
			}

			// Extract program ID from load response
			programID, err := extractProgramID(loadResp)
			if err != nil {
				return createErrorResult(fmt.Sprintf("Failed to extract program ID: %v", err))
			}

			// If verify_only was true, we stop here
			if verifyOnly, exists := args["verify_only"]; exists && verifyOnly == "true" {
				return mcp.NewGetPromptResult("eBPF program verified successfully", []mcp.PromptMessage{
					mcp.NewPromptMessage(mcp.RoleUser,
						mcp.NewTextContent("Verify eBPF program")),
					mcp.NewPromptMessage(mcp.RoleAssistant,
						mcp.NewTextContent(fmt.Sprintf("✅ eBPF program verified successfully!\n\nProgram Type: %s\nSource: %s (%s)\nVerification completed without errors.", 
							programType, args["source_value"], sourceType))),
				}), nil
			}

			// Step 2: Build attach request
			attachRequest := map[string]interface{}{
				"program_id":  programID,
				"attach_type": attachType,
				"target":      args["target"],
			}

			// Add optional pin_path
			if pinPath, exists := args["pin_path"]; exists && pinPath != "" {
				attachRequest["pin_path"] = pinPath
			}

			// Add optional flags and priority
			options := make(map[string]interface{})
			if flags, exists := args["flags"]; exists && flags != "" {
				if flagsInt, err := parseIntArg(flags); err == nil {
					options["flags"] = flagsInt
				}
			}
			if priority, exists := args["priority"]; exists && priority != "" {
				if priorityInt, err := parseIntArg(priority); err == nil {
					options["priority"] = priorityInt
				}
			}
			if len(options) > 0 {
				attachRequest["options"] = options
			}

			// Step 3: Attach the program
			attachResp, err := tools.CallRaw("attach_program", attachRequest)
			if err != nil {
				return createErrorResult(fmt.Sprintf("Program loaded (ID: %d) but failed to attach: %v", programID, err))
			}

			// Build success message
			successMsg := buildSuccessMessage(args, programID, loadResp, attachResp)

			return mcp.NewGetPromptResult("eBPF program loaded and attached successfully", []mcp.PromptMessage{
				mcp.NewPromptMessage(mcp.RoleUser,
					mcp.NewTextContent("Load and attach eBPF program")),
				mcp.NewPromptMessage(mcp.RoleAssistant,
					mcp.NewTextContent(successMsg)),
			}), nil
		},
	})
}

// Helper functions

func isValidSourceType(sourceType string) bool {
	validTypes := []string{"file", "url", "data"}
	for _, valid := range validTypes {
		if sourceType == valid {
			return true
		}
	}
	return false
}

func isValidProgramType(programType string) bool {
	validTypes := []string{"XDP", "KPROBE", "TRACEPOINT", "CGROUP_SKB"}
	for _, valid := range validTypes {
		if programType == valid {
			return true
		}
	}
	return false
}

func isValidAttachType(attachType string) bool {
	validTypes := []string{"xdp", "kprobe", "kretprobe", "tracepoint", "cgroup"}
	for _, valid := range validTypes {
		if attachType == valid {
			return true
		}
	}
	return false
}

func buildSourceObject(sourceType, sourceValue string, args map[string]string) map[string]interface{} {
	sourceObj := map[string]interface{}{
		"type": sourceType,
	}

	switch sourceType {
	case "file":
		sourceObj["path"] = sourceValue
	case "url":
		sourceObj["url"] = sourceValue
	case "data":
		sourceObj["blob"] = sourceValue
	}

	// Add checksum if provided
	if checksum, exists := args["checksum"]; exists && checksum != "" {
		sourceObj["checksum"] = checksum
	}

	return sourceObj
}

func extractProgramID(response map[string]interface{}) (int, error) {
	// Try to extract program_id from the response
	if progID, exists := response["program_id"]; exists {
		switch id := progID.(type) {
		case int:
			return id, nil
		case float64:
			return int(id), nil
		case string:
			return parseIntArg(id)
		}
	}

	// If not found in root, try to find in nested result
	if result, exists := response["result"]; exists {
		if resultMap, ok := result.(map[string]interface{}); ok {
			if progID, exists := resultMap["program_id"]; exists {
				switch id := progID.(type) {
				case int:
					return id, nil
				case float64:
					return int(id), nil
				case string:
					return parseIntArg(id)
				}
			}
		}
	}

	return 0, fmt.Errorf("program_id not found in response: %+v", response)
}

func parseIntArg(s string) (int, error) {
	var result int
	if _, err := fmt.Sscanf(s, "%d", &result); err != nil {
		return 0, fmt.Errorf("invalid integer: %s", s)
	}
	return result, nil
}

func createErrorResult(errorMsg string) (*mcp.GetPromptResult, error) {
	return mcp.NewGetPromptResult("eBPF operation failed", []mcp.PromptMessage{
		mcp.NewPromptMessage(mcp.RoleUser,
			mcp.NewTextContent("Load and attach eBPF program")),
		mcp.NewPromptMessage(mcp.RoleAssistant,
			mcp.NewTextContent(fmt.Sprintf("❌ %s", errorMsg))),
	}), nil
}

func buildSuccessMessage(args map[string]string, programID int, loadResp, attachResp map[string]interface{}) string {
	var msgBuilder strings.Builder
	msgBuilder.WriteString("✅ eBPF program loaded and attached successfully!\n\n")
	
	// Program details
	msgBuilder.WriteString(fmt.Sprintf("📋 Program Details:\n"))
	msgBuilder.WriteString(fmt.Sprintf("  • Program ID: %d\n", programID))
	msgBuilder.WriteString(fmt.Sprintf("  • Type: %s\n", args["program_type"]))
	msgBuilder.WriteString(fmt.Sprintf("  • Source: %s (%s)\n", args["source_value"], args["source_type"]))
	
	// Attachment details
	msgBuilder.WriteString(fmt.Sprintf("\n🔗 Attachment Details:\n"))
	msgBuilder.WriteString(fmt.Sprintf("  • Attach Type: %s\n", args["attach_type"]))
	msgBuilder.WriteString(fmt.Sprintf("  • Target: %s\n", args["target"]))
	
	// Extract link ID if available
	if linkID := extractLinkID(attachResp); linkID != 0 {
		msgBuilder.WriteString(fmt.Sprintf("  • Link ID: %d\n", linkID))
	}
	
	// Pin path if specified
	if pinPath, exists := args["pin_path"]; exists && pinPath != "" {
		msgBuilder.WriteString(fmt.Sprintf("  • Pinned at: %s\n", pinPath))
	}
	
	// Optional details
	if section, exists := args["section"]; exists && section != "" {
		msgBuilder.WriteString(fmt.Sprintf("  • Section: %s\n", section))
	}
	
	msgBuilder.WriteString("\n🎉 The eBPF program is now active and monitoring kernel events!")
	
	return msgBuilder.String()
}

func extractLinkID(response map[string]interface{}) int {
	if linkID, exists := response["link_id"]; exists {
		switch id := linkID.(type) {
		case int:
			return id
		case float64:
			return int(id)
		}
	}
	
	// Try nested result
	if result, exists := response["result"]; exists {
		if resultMap, ok := result.(map[string]interface{}); ok {
			if linkID, exists := resultMap["link_id"]; exists {
				switch id := linkID.(type) {
				case int:
					return id
				case float64:
					return int(id)
				}
			}
		}
	}
	
	return 0
}