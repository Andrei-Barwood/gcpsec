package scanner

import (
	"context"
	"encoding/json"
	"fmt"
)

func (s *Scanner) gcloudJSON(ctx context.Context, args ...string) ([]map[string]any, error) {
	cmdCtx, cancel := s.cmdCtx(ctx)
	defer cancel()

	full := append(args, "--format=json")
	out, err := s.runner.Run(cmdCtx, "gcloud", full...)
	if err != nil {
		return nil, err
	}

	var list []map[string]any
	if err := json.Unmarshal(out, &list); err == nil {
		return list, nil
	}

	var single map[string]any
	if err := json.Unmarshal(out, &single); err != nil {
		return nil, fmt.Errorf("invalid gcloud json output: %w", err)
	}
	return []map[string]any{single}, nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}
