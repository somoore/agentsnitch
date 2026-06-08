package inspect

import (
	"os"
	"path/filepath"
	"strings"
)

type Paths struct {
	BaseDir    string `json:"base_dir"`
	CAPath     string `json:"ca_path"`
	KeyPath    string `json:"key_path"`
	BundlePath string `json:"bundle_path"`
	LeafDir    string `json:"leaf_dir"`
	DataDir    string `json:"data_dir"`
}

func DefaultPaths() Paths {
	base := strings.TrimSpace(os.Getenv("AGENTSNITCH_INSPECT_DIR"))
	if base == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			base = filepath.Join(home, "Library", "Application Support", "AgentSnitch", "inspect")
		} else {
			base = filepath.Join(os.TempDir(), "AgentSnitch", "inspect")
		}
	}
	return Paths{
		BaseDir:    base,
		CAPath:     filepath.Join(base, "ca.pem"),
		KeyPath:    filepath.Join(base, "ca-key.pem"),
		BundlePath: filepath.Join(base, "process-scoped-ca-bundle.pem"),
		LeafDir:    filepath.Join(base, "leaf-cache"),
		DataDir:    filepath.Join(base, "payloads"),
	}
}

func EnsureDirs(paths Paths) error {
	for _, dir := range []string{paths.BaseDir, paths.LeafDir, paths.DataDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
