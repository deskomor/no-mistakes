package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The default ACP command needs the configured acpx package closure and exact
// node/omp executables. Never expose an enclosing home or temporary directory.
func (a *acpxAgent) factoryRuntimePaths(env []string) ([]string, error) {
	executable, err := factoryExecutable(a.bin, env)
	if err != nil {
		return nil, err
	}
	paths := []string{executable}
	real, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	validatedPackage := false
	for dir := filepath.Dir(real); filepath.Dir(dir) != dir; dir = filepath.Dir(dir) {
		metadata, readErr := factoryPackageMetadata(dir)
		if os.IsNotExist(readErr) {
			continue
		}
		if readErr != nil {
			return nil, readErr
		}
		if metadata.Name != "acpx" {
			return nil, fmt.Errorf("controlled executable belongs to unsupported package %q", metadata.Name)
		}
		if metadata.Name == "acpx" {
			closure, err := factoryPackageClosure(dir)
			if err != nil {
				return nil, err
			}
			paths = append(paths, closure...)
			validatedPackage = true
			break
		}
	}
	if !validatedPackage {
		return nil, fmt.Errorf("controlled executable is not inside a validated acpx package: %s", executable)
	}
	for _, name := range []string{"node", "omp"} {
		path, err := factoryExecutable(name, env)
		if err != nil {
			return nil, fmt.Errorf("controlled ACP runtime requires %s on its explicit PATH: %w", name, err)
		}
		paths = append(paths, path)
	}
	if a.overlayPath != "" {
		paths = append(paths, a.overlayPath)
	}
	return paths, nil
}

func factoryExecutable(name string, env []string) (string, error) {
	path := os.Getenv("PATH")
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			path = strings.TrimPrefix(entry, "PATH=")
		}
	}
	candidates := []string{name}
	if !strings.ContainsRune(name, filepath.Separator) {
		candidates = nil
		for _, dir := range filepath.SplitList(path) {
			if !filepath.IsAbs(dir) {
				continue
			}
			candidates = append(candidates, filepath.Join(dir, name))
		}
	}
	for _, candidate := range candidates {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(absolute)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return absolute, nil
		}
	}
	return "", fmt.Errorf("executable %q not found in the controlled runtime", name)
}

type factoryNPMPackage struct {
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func factoryPackageMetadata(root string) (factoryNPMPackage, error) {
	var metadata factoryNPMPackage
	path := filepath.Join(root, "package.json")
	info, err := os.Stat(path)
	if err != nil {
		return metadata, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return metadata, fmt.Errorf("invalid controlled package metadata: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return metadata, err
	}
	err = json.Unmarshal(data, &metadata)
	return metadata, err
}

// Resolve only declared, installed dependencies. An unrelated sibling package
// never becomes readable merely because it shares node_modules with acpx.
func factoryPackageClosure(root string) ([]string, error) {
	var paths []string
	seen := map[string]bool{}
	var visit func(string) error
	visit = func(path string) error {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if path != real {
			paths = append(paths, path)
		}
		if seen[real] {
			return nil
		}
		seen[real] = true
		paths = append(paths, real)
		metadata, err := factoryPackageMetadata(real)
		if err != nil {
			return err
		}
		dependencies := map[string]bool{}
		for name := range metadata.Dependencies {
			dependencies[name] = true
		}
		for name := range metadata.OptionalDependencies {
			dependencies[name] = false
		}
		for name, required := range dependencies {
			parts := strings.Split(name, "/")
			valid := len(parts) == 1 || (len(parts) == 2 && strings.HasPrefix(parts[0], "@"))
			for _, part := range parts {
				valid = valid && part != "" && part != "." && part != ".." && !strings.ContainsRune(part, '\\') && !strings.ContainsRune(part, 0)
			}
			if !valid {
				return fmt.Errorf("invalid controlled dependency name %q", name)
			}
			found := ""
			for dir := real; ; dir = filepath.Dir(dir) {
				candidate := filepath.Join(dir, "node_modules", filepath.FromSlash(name))
				if _, err := os.Stat(filepath.Join(candidate, "package.json")); err == nil {
					found = candidate
					break
				} else if !os.IsNotExist(err) {
					return err
				}
				if filepath.Dir(dir) == dir {
					break
				}
			}
			if found == "" {
				if required {
					return fmt.Errorf("controlled acpx dependency %q is not installed", name)
				}
				continue
			}
			if err := visit(found); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	return paths, nil
}
