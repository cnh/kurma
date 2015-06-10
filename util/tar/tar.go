// Copyright 2015 Apcera Inc. All rights reserved.

package tar

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/apcera/util/tarhelper"
	"github.com/appc/spec/schema"
)

// FindManifest retrieves the manifest from the provided reader and unmarshals
// it.
func FindManifest(r io.Reader) (*schema.ImageManifest, error) {
	arch, err := tarhelper.DetectArchiveCompression(r)
	if err != nil {
		return nil, err
	}

	for {
		header, err := arch.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("failed to locate manifest file")
		}
		if err != nil {
			return nil, err
		}

		if filepath.Clean(header.Name) != "manifest" {
			continue
		}

		var manifest *schema.ImageManifest
		if err := json.NewDecoder(arch).Decode(&manifest); err != nil {
			return nil, err
		}
		return manifest, nil
	}
}
