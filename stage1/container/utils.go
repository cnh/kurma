// Copyright 2015 Apcera Inc. All rights reserved.

package container

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/apcera/kurma/util/tar"
	"github.com/apcera/util/aciremote"
	"github.com/apcera/util/hashutil"
	"github.com/apcera/util/proc"
	"github.com/apcera/util/tarhelper"
	"github.com/appc/spec/discovery"
	"github.com/appc/spec/schema"
)

func (c *Container) imageManifestPath() string {
	return filepath.Join(c.directory, "manifest")
}

func (c *Container) containerManifestPath() string {
	return filepath.Join(c.directory, "container")
}

func (c *Container) stage2LogPath() string {
	return filepath.Join(c.directory, "stage2.log")
}

func (c *Container) stage3Path() string {
	return filepath.Join(c.directory, "rootfs")
}

func (c *Container) socketPath() string {
	return filepath.Join(c.directory, "socket")
}

func mkdirs(dirs []string, mode os.FileMode, existOk bool) error {
	for i := range dirs {
		// Make sure that this directory doesn't currently exist if existOk
		// is false.
		if stat, err := os.Lstat(dirs[i]); err == nil {
			if !existOk {
				return fmt.Errorf("lstat: path already exists: %s", dirs[i])
			} else if !stat.IsDir() {
				return fmt.Errorf("lstat: %s is not a directory.", dirs[i])
			}
		} else if !os.IsNotExist(err) {
			return err
		} else if err := os.Mkdir(dirs[i], mode); err != nil {
			return fmt.Errorf("mkdir: %s", err)
		}

		// Ensure that the mode is applied by running chmod against it. We
		// need to do this because Mkdir will apply umask which might screw
		// with the permissions.
		if err := os.Chmod(dirs[i], mode); err != nil {
			return fmt.Errorf("chmod: %s", err)
		}
	}
	return nil
}

func chowns(paths []string, uid, gid int) error {
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf("chown: %q - %v", p, err)
		}
	}
	return nil
}

func unmountDirectories(path string) error {
	// Get the list of mount points that are under this container's directory
	// and then attempt to unmount them in reverse order. This is required
	// so that all mounts are unmounted before a parent is unmounted.
	mountPoints := make([]string, 0, 100)
	root := path + string(os.PathSeparator)
	err := proc.ParseSimpleProcFile(
		proc.MountProcFile,
		nil,
		func(line int, index int, elem string) error {
			switch {
			case index != 1:
			case elem == path:
				mountPoints = append(mountPoints, elem)
			case strings.HasPrefix(elem, root):
				mountPoints = append(mountPoints, elem)
			}
			return nil
		})
	if err != nil {
		return err
	}

	// Now walk the list in reverse order unmounting each point one at a time.
	for i := len(mountPoints) - 1; i >= 0; i-- {
		if err := syscall.Unmount(mountPoints[i], syscall.MNT_FORCE); err != nil {
			return fmt.Errorf("failed to unmount %q: %v", mountPoints[i], err)
		}
	}

	return nil
}

// ensureContainerPathExists ensures that the specified path within the
// container exists. It will create any missing directories and walk the
// filesystem to ensure any portions that are symlinks are resolved. It returns
// the full host path to the directory.
func (c *Container) ensureContainerPathExists(name string) (string, error) {
	parts := strings.Split(name, string(os.PathSeparator))
	resolvedPath := c.stage3Path()
	containerPath := ""

	for _, p := range parts {
		if p == "" {
			continue
		}
		containerPath = filepath.Join(containerPath, p)

		// resolve this segment
		newResolvedPath, err := c.resolveSymlinkDir(containerPath)
		if err != nil {
			if os.IsNotExist(err) {
				// create it if it doesn't exist
				resolvedPath = filepath.Join(resolvedPath, p)
				if err := os.Mkdir(resolvedPath, os.FileMode(0755)); err != nil {
					return "", err
				}
				continue
			}
			return "", err
		}

		// preserve the resolved path for the next iteration
		resolvedPath = newResolvedPath
	}

	return resolvedPath, nil
}

// Resolves a given directory name relative to the container into a directory
// name relative to the instance manager. This will attempt to follow symlinks
// as best as possible, ensuring that the destination stays inside of the
// container directory.
func (c *Container) resolveSymlinkDir(name string) (string, error) {
	// This is used to compare paths to ensure that they are exactly contained
	// completely within s.RootDirectory()
	root := c.stage3Path()
	checkList := func(fn string) (string, bool) {
		fnPath := filepath.Join(root, fn)
		if len(fnPath) < len(root) {
			return "", false
		} else if fnPath == root {
			return fnPath, true
		} else if strings.HasPrefix(fnPath, root+string(os.PathSeparator)) {
			return fnPath, true
		} else {
			return "", false
		}
	}

	// Loop until we have either walked too far, or we resolve the symlink. This
	// protects us from simple symlink loops.
	checkRecurse := func(name string) (string, error) {
		for depth := 0; depth < 64; depth++ {
			// Get the real path for the file.
			if newName, ok := checkList(name); !ok {
				return "", fmt.Errorf("Name resolved to an unsafe path: %s", name)
			} else if fi, err := os.Lstat(newName); err != nil {
				return "", err
			} else if fi.Mode()&os.ModeSymlink != 0 {
				// If the destination is a symlink then we need to resolve it in order to
				// walk down the chain.
				var err error
				if name, err = os.Readlink(newName); err != nil {
					return "", err
				}
				continue
			} else if !fi.IsDir() {
				return "", fmt.Errorf("Resolved path is not a directory: %s", newName)
			} else {
				return newName, nil
			}
		}
		return "", fmt.Errorf("Symlink depth too excessive.")
	}

	// Loop over the portions of the path to see where they resolve to
	containerPath := ""
	parts := strings.Split(name, string(os.PathSeparator))
	for _, p := range parts {
		if p == "" {
			continue
		}
		containerPath = filepath.Join(containerPath, p)
		newName, allowed := checkList(containerPath)
		if !allowed {
			return "", fmt.Errorf("Name resolved to an unsafe path: %s", name)
		}
		fi, err := os.Lstat(newName)
		if err != nil {
			return "", err
		}

		// if the portion is a symlink, we'll read it and then resolve it out
		if fi.Mode()&os.ModeSymlink != 0 {
			name, err := os.Readlink(newName)
			if err != nil {
				return "", err
			}

			// handle if the path is not absolute, such as "../dir" or just "dir".
			if !filepath.IsAbs(name) {
				name = filepath.Join(filepath.Dir(newName), name)
				name = filepath.Clean(name)
			}
			containerPath = strings.Replace(name, root+string(os.PathSeparator), "", -1)

			// recurse the link to check for additional layers of links
			name, err = checkRecurse(containerPath)
			if err != nil {
				return "", err
			}
			containerPath = strings.Replace(name, root+string(os.PathSeparator), "", -1)
		}
	}

	return filepath.Join(root, containerPath), nil
}

// processDependencies takes an ImageManifest and will look over its
// dependencies, discovering them, downloading them, and applying them to the
// current container's filesystem. This is done depth first, so the lowest
// dependency will get resolved and extracted before higher up ones. It will
// return any error if locating, retrieving, or extracting any dependencies
// fails.
func (c *Container) processDependencies(image *schema.ImageManifest, resolvedList map[string]bool) error {
	for _, dep := range image.Dependencies {
		// Check to see if the mentioned dependency has already been resolved. This
		// is currently based upon the base name only. Circular dependency handling
		// isn't called out in the AppC spec, and generally most of the edge cases
		// you can get with this are around nefarious uses. App name should be safe
		// enough, and not erroring but just continuing handles base cases where it
		// actually is used and ok.
		if resolvedList[dep.ImageName.String()] {
			continue
		}

		app, err := discovery.NewApp(dep.ImageName.String(), dep.Labels.ToMap())
		if err != nil {
			return err
		}

		endpoints, _, err := discovery.DiscoverEndpoints(*app, true)
		if err != nil {
			return err
		}

		if len(endpoints.ACIEndpoints) == 0 {
			return fmt.Errorf("failed to locate any endpoints for %q", dep.ImageName.String())
		}

		for _, endpoint := range endpoints.ACIEndpoints {
			// FIXME handle signature too
			reader, err := aciremote.RetrieveImage(endpoint.ACI, true)
			if err != nil {
				continue
			}

			// extract the ImageManifest from it
			depImage, err := tar.FindManifest(reader)
			if err != nil {
				return err
			}
			if _, err := reader.Seek(0, 0); err != nil {
				return err
			}

			// We have downloaded and extracted the manifest, count it as resolved
			resolvedList[dep.ImageName.String()] = true

			// Process the dependencies on the child image as well.
			if err := c.processDependencies(depImage, resolvedList); err != nil {
				return err
			}

			// Extract the image and calculate its sha.
			sr := hashutil.NewSha512(reader)
			if err := c.extractImage(depImage, sr); err != nil {
				return err
			}

			// Compare the hash in the ImageID, if one was provided.
			if dep.ImageID != nil {
				if dep.ImageID.Val != sr.Sha512() {
					return fmt.Errorf("download image hash did not match the provided hash: %s != %s", dep.ImageID.Val, sr.Sha512())
				}
			}

			break
		}
	}
	return nil
}

// extractImage handles extracting the tarball from the provided reader. It will
// honor any PathWhitelist settings on the image manifest when applying to the
// current container's filesystem. This helper is used both to extract the
// actual container image's filesystem, as well as is used to handle extracting
// dependent images.
func (c *Container) extractImage(image *schema.ImageManifest, reader io.ReadCloser) error {
	defer reader.Close()

	whitelist := image.PathWhitelist
	if len(whitelist) == 0 {
		whitelist = []string{"/rootfs/"}
	} else {
		for i := range whitelist {
			whitelist[i] = filepath.Join("/rootfs", whitelist[i])
		}
	}

	// untar the file
	tarfile := tarhelper.NewUntar(reader, c.directory)
	tarfile.PreserveOwners = true
	tarfile.PreservePermissions = true
	tarfile.Compression = tarhelper.DETECT
	tarfile.AbsoluteRoot = c.directory
	tarfile.PathWhitelist = whitelist
	if err := tarfile.Extract(); err != nil {
		return fmt.Errorf("failed to extract stage2 image filesystem: %v", err)
	}

	// // put the hash on the pod manifest
	// for i, app := range c.pod.Apps {
	// 	if app.Image.Name.Equals(c.image.Name) {
	// 		if err := app.Image.ID.Set(fmt.Sprintf("sha512-%s", sr.Sha512())); err != nil {
	// 			return err
	// 		}
	// 		c.pod.Apps[i] = app
	// 	}
	// }

	return nil
}
