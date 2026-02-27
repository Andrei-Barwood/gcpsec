package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Andrei-Barwood/gcpsec/internal/model"
)

func Save(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("output path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func LoadScan(path string) (model.ScanResult, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return model.ScanResult{}, err
	}
	var scan model.ScanResult
	if err := json.Unmarshal(buf, &scan); err != nil {
		return model.ScanResult{}, err
	}
	return scan, nil
}
