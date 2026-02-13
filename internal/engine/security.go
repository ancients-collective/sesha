package engine

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Security constants for input validation and resource limits.
const (
	// MaxFileReadBytes is the maximum number of bytes we'll read from any file (10 MB).
	MaxFileReadBytes int64 = 10 * 1024 * 1024

	// MaxRegexLength is the maximum allowed length for user-supplied regex patterns.
	MaxRegexLength = 1024

	// MaxServiceNameLength is the maximum allowed length for service/module names.
	MaxServiceNameLength = 256
)

// Validation patterns for security-sensitive inputs.
var (
	sysctlKeyPattern    = regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)
	serviceNamePattern  = regexp.MustCompile(`^[a-zA-Z0-9_@.\-]+$`)
	kernelModulePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
)

// validatePath checks that a file path is safe to operate on.
// Rejects path traversal sequences and non-absolute paths.
func validatePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path must not be empty")
	}

	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute, got %q", path)
	}

	cleaned := filepath.Clean(path)
	for _, part := range strings.Split(cleaned, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("path traversal (..) not allowed in %q", path)
		}
	}

	return cleaned, nil
}

// readFileLimited reads a regular file with safety checks:
//   - path traversal prevention
//   - follows symlinks (system files like /etc/os-release are commonly symlinks)
//   - regular-file-only after resolution (no devices, pipes, sockets)
//   - bounded read (MaxFileReadBytes)
//
// Uses open-then-fstat to avoid TOCTOU races between stat and open.
func readFileLimited(path string) ([]byte, error) {
	cleaned, err := validatePath(path)
	if err != nil {
		return nil, err
	}

	// Open first, then fstat the fd — eliminates TOCTOU window.
	f, err := os.Open(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("cannot open file %q: %w", cleaned, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat file %q: %w", cleaned, err)
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to read non-regular file %q (mode: %s)", cleaned, info.Mode().Type())
	}

	if info.Size() > MaxFileReadBytes {
		return nil, fmt.Errorf("file %q too large: %d bytes (max: %d)", cleaned, info.Size(), MaxFileReadBytes)
	}

	limited := io.LimitReader(f, MaxFileReadBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("error reading file %q: %w", cleaned, err)
	}

	if int64(len(data)) > MaxFileReadBytes {
		return nil, fmt.Errorf("file %q exceeded size limit during read", cleaned)
	}

	return data, nil
}

// readProcFileLimited reads a file under /proc with bounded read.
// Skips symlink checks because kernel symlinks are expected.
// Cleans the path before the prefix check to prevent traversal (e.g., "/proc/../etc/shadow").
func readProcFileLimited(path string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	if !strings.HasPrefix(cleaned, "/proc/") {
		return nil, fmt.Errorf("readProcFileLimited: path must be under /proc/, got %q (cleaned: %q)", path, cleaned)
	}
	path = cleaned

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", path, err)
	}
	defer f.Close()

	limited := io.LimitReader(f, MaxFileReadBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("error reading %q: %w", path, err)
	}

	if int64(len(data)) > MaxFileReadBytes {
		return nil, fmt.Errorf("file %q exceeded size limit during read", path)
	}

	return data, nil
}

// validateRegexPattern compiles a regex pattern with length and safety checks.
func validateRegexPattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("pattern must not be empty")
	}

	if len(pattern) > MaxRegexLength {
		return nil, fmt.Errorf("pattern too long: %d chars (max: %d)", len(pattern), MaxRegexLength)
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}

	return re, nil
}

// validateSysctlKey checks that a sysctl key contains only safe characters.
func validateSysctlKey(key string) error {
	if key == "" {
		return fmt.Errorf("sysctl key must not be empty")
	}

	if !sysctlKeyPattern.MatchString(key) {
		return fmt.Errorf("invalid sysctl key %q: must contain only alphanumeric, dots, and underscores", key)
	}

	if strings.Contains(key, "..") {
		return fmt.Errorf("sysctl key %q contains '..', which is not allowed", key)
	}

	return nil
}

// validateServiceName checks that a service name contains only safe characters.
func validateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name must not be empty")
	}

	if len(name) > MaxServiceNameLength {
		return fmt.Errorf("service name too long: %d chars (max: %d)", len(name), MaxServiceNameLength)
	}

	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("service name %q must not start with '-'", name)
	}

	if !serviceNamePattern.MatchString(name) {
		return fmt.Errorf("invalid service name %q: only alphanumeric, underscores, dots, hyphens, @ allowed", name)
	}

	return nil
}

// validateKernelModuleName checks that a kernel module name is safe.
func validateKernelModuleName(name string) error {
	if name == "" {
		return fmt.Errorf("kernel module name must not be empty")
	}

	if len(name) > MaxServiceNameLength {
		return fmt.Errorf("kernel module name too long: %d chars (max: %d)", len(name), MaxServiceNameLength)
	}

	if !kernelModulePattern.MatchString(name) {
		return fmt.Errorf("invalid kernel module name %q: only alphanumeric, underscores, hyphens allowed", name)
	}

	return nil
}

// VerifyChecksDirectory checks if the checks directory has safe ownership and permissions.
// Returns a list of warnings (empty = directory is secure).
func VerifyChecksDirectory(dir string) []string {
	warnings, info := verifyDirEntry(dir)
	if info == nil {
		return warnings
	}

	warnings = append(warnings, checkDirPermissions(dir, info.Mode().Perm())...)

	absDir, err := filepath.Abs(dir)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("cannot resolve absolute path for %q: %v", dir, err))
		return warnings
	}

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("error accessing %q during walk: %v", path, err))
			return nil
		}
		warnings = append(warnings, verifyWalkEntry(path, d, absDir)...)
		return nil
	})
	if walkErr != nil {
		warnings = append(warnings, fmt.Sprintf("walk error in checks directory: %v", walkErr))
	}

	return warnings
}

// verifyDirEntry checks that the checks directory exists, is not a symlink, and is a directory.
// Returns accumulated warnings and the FileInfo (nil if the directory is invalid).
func verifyDirEntry(dir string) ([]string, os.FileInfo) {
	info, err := os.Lstat(dir)
	if err != nil {
		return []string{fmt.Sprintf("cannot stat checks directory %q: %v", dir, err)}, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return []string{fmt.Sprintf("checks directory %q is a symlink — this could be exploited", dir)}, nil
	}
	if !info.IsDir() {
		return []string{fmt.Sprintf("checks path %q is not a directory", dir)}, nil
	}
	return nil, info
}

// checkDirPermissions returns warnings if the directory is world-writable or group-writable.
func checkDirPermissions(dir string, perm os.FileMode) []string {
	var warnings []string
	if perm&0002 != 0 {
		warnings = append(warnings, fmt.Sprintf("checks directory %q is world-writable (%04o) — anyone can inject checks", dir, perm))
	}
	if perm&0020 != 0 {
		warnings = append(warnings, fmt.Sprintf("checks directory %q is group-writable (%04o) — group members can inject checks", dir, perm))
	}
	return warnings
}

// verifyWalkEntry checks a single entry during the directory walk for symlinks
// pointing outside the checks directory and world-writable check files.
func verifyWalkEntry(path string, d os.DirEntry, absDir string) []string {
	var warnings []string

	if d.Type()&os.ModeSymlink != 0 {
		target, resolveErr := filepath.EvalSymlinks(path)
		if resolveErr != nil {
			return []string{fmt.Sprintf("symlink %q cannot be resolved: %v", path, resolveErr)}
		}
		absTarget, _ := filepath.Abs(target)
		if !strings.HasPrefix(absTarget, absDir+string(filepath.Separator)) && absTarget != absDir {
			warnings = append(warnings, fmt.Sprintf("symlink %q points outside checks directory (→ %s)", path, absTarget))
		}
	}

	ext := strings.ToLower(filepath.Ext(path))
	if (ext == ".yaml" || ext == ".yml") && !d.IsDir() {
		fi, fiErr := d.Info()
		if fiErr != nil {
			return warnings
		}
		if fi.Mode().Perm()&0002 != 0 {
			warnings = append(warnings, fmt.Sprintf("check file %q is world-writable (%04o)", path, fi.Mode().Perm()))
		}
	}

	return warnings
}
