package nb8

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

type FS interface {
	// Open opens the named file.
	Open(name string) (fs.File, error)

	// OpenReaderFrom opens an io.ReaderFrom that represents an instance of a
	// file that can read from an io.Reader. The parent directory must exist.
	// If the file doesn't exist, it should be created. If the file exists, its
	// should be truncated.
	OpenReaderFrom(name string, perm fs.FileMode) (io.ReaderFrom, error)

	// ReadDir reads the named directory and returns a list of directory
	// entries sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error)

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error

	// Remove removes the named file or directory.
	Remove(name string) error

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error
}

type LocalFS struct {
	RootDir string
	TempDir string
}

var _ FS = (*LocalFS)(nil)

func (localFS *LocalFS) String() string {
	return localFS.RootDir
}

func (localFS *LocalFS) Open(name string) (fs.File, error) {
	name = filepath.FromSlash(name)
	return os.Open(filepath.Join(localFS.RootDir, name))
}

func (localFS *LocalFS) OpenReaderFrom(name string, perm fs.FileMode) (io.ReaderFrom, error) {
	return &localFile{
		localFS: localFS,
		name:    name,
		perm:    perm,
	}, nil
}

func (localFS *LocalFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = filepath.FromSlash(name)
	return os.ReadDir(filepath.Join(localFS.RootDir, name))
}

func (localFS *LocalFS) Mkdir(name string, perm fs.FileMode) error {
	name = filepath.FromSlash(name)
	return os.Mkdir(filepath.Join(localFS.RootDir, name), perm)
}

func (localFS *LocalFS) MkdirAll(name string, perm fs.FileMode) error {
	name = filepath.FromSlash(name)
	return os.MkdirAll(filepath.Join(localFS.RootDir, name), perm)
}

func (localFS *LocalFS) Remove(name string) error {
	name = filepath.FromSlash(name)
	return os.Remove(filepath.Join(localFS.RootDir, name))
}

func (localFS *LocalFS) RemoveAll(name string) error {
	name = filepath.FromSlash(name)
	return os.RemoveAll(filepath.Join(localFS.RootDir, name))
}

func (localFS *LocalFS) Rename(oldname, newname string) error {
	oldname = filepath.FromSlash(oldname)
	newname = filepath.FromSlash(newname)
	return os.Rename(filepath.Join(localFS.RootDir, oldname), filepath.Join(localFS.RootDir, newname))
}

type localFile struct {
	localFS *LocalFS
	name    string
	perm    fs.FileMode
}

func (localFile *localFile) ReadFrom(r io.Reader) (n int64, err error) {
	tempDir := localFile.localFS.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	tempFile, err := os.CreateTemp(tempDir, "__notebrewtemp*__")
	if err != nil {
		return 0, err
	}
	defer tempFile.Close()
	tempFileInfo, err := tempFile.Stat()
	if err != nil {
		return 0, err
	}
	tempFileName := filepath.Join(tempDir, tempFileInfo.Name())
	defer os.Remove(tempFileName)
	n, err = io.Copy(tempFile, r)
	if err != nil {
		return 0, err
	}
	err = tempFile.Close()
	if err != nil {
		return 0, err
	}
	destFileName := filepath.Join(localFile.localFS.RootDir, localFile.name)
	destFileInfo, err := os.Stat(destFileName)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	mode := localFile.perm
	if destFileInfo != nil {
		mode = destFileInfo.Mode()
	}
	err = os.Rename(tempFileName, destFileName)
	if err != nil {
		return 0, err
	}
	_ = os.Chmod(destFileName, mode)
	return n, nil
}

// RemoveAll removes the root item from the FS (whether it is a file or a
// directory).
func RemoveAll(fsys FS, root string) error {
	type Item struct {
		Path             string // relative to root
		IsFile           bool   // whether item is file or directory
		MarkedForRemoval bool   // if true, remove item unconditionally
	}
	root = filepath.FromSlash(root)
	fileInfo, err := fs.Stat(fsys, root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	// If root is a file, we can remove it immediately and return.
	if !fileInfo.IsDir() {
		return fsys.Remove(root)
	}
	// If root is an empty directory, we can remove it immediately and return.
	dirEntries, err := fsys.ReadDir(root)
	if len(dirEntries) == 0 {
		return fsys.Remove(root)
	}
	// If the filesystem supports RemoveAll(), we can call that instead and
	// return.
	if fsys, ok := fsys.(interface{ RemoveAll(name string) error }); ok {
		return fsys.RemoveAll(root)
	}
	// Otherwise, we need to recursively delete its child items one by one.
	var item Item
	items := make([]Item, 0, len(dirEntries))
	for i := len(dirEntries) - 1; i >= 0; i-- {
		dirEntry := dirEntries[i]
		items = append(items, Item{
			Path:   dirEntry.Name(),
			IsFile: !dirEntry.IsDir(),
		})
	}
	for len(items) > 0 {
		// Pop item from stack.
		item, items = items[len(items)-1], items[:len(items)-1]
		// If item has been marked for removal or it is a file, we can remove
		// it immediately.
		if item.MarkedForRemoval || item.IsFile {
			err = fsys.Remove(filepath.Join(root, item.Path))
			if err != nil {
				return err
			}
			continue
		}
		// Mark directory item for removal and put it back in the stack (when
		// we get back to it, its child items would already have been removed).
		item.MarkedForRemoval = true
		items = append(items, item)
		// Push directory item's child items onto the stack.
		dirEntries, err := fsys.ReadDir(filepath.Join(root, item.Path))
		if err != nil {
			return err
		}
		for i := len(dirEntries) - 1; i >= 0; i-- {
			dirEntry := dirEntries[i]
			items = append(items, Item{
				Path:   filepath.Join(item.Path, dirEntry.Name()),
				IsFile: !dirEntry.IsDir(),
			})
		}
	}
	return nil
}

func MkdirAll(fsys FS, dir string, perm fs.FileMode) error {
	fileInfo, err := fs.Stat(fsys, dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if fileInfo != nil {
		if fileInfo.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "mkdir", Path: dir, Err: syscall.ENOTDIR}
	}

	isPathSeparator := func(char byte) bool {
		return char == '/' || char == '\\'
	}

	fixRootDirectory := func(p string) string {
		if runtime.GOOS != "windows" {
			return p
		}
		if len(p) == len(`\\?\c:`) {
			if isPathSeparator(p[0]) && isPathSeparator(p[1]) && p[2] == '?' && isPathSeparator(p[3]) && p[5] == ':' {
				return p + `\`
			}
		}
		return p
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(dir)
	for i > 0 && isPathSeparator(dir[i-1]) { // Skip trailing path separator.
		i--
	}
	j := i
	for j > 0 && !isPathSeparator(dir[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = MkdirAll(fsys, fixRootDirectory(dir[:j-1]), perm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = fsys.Mkdir(dir, perm)
	if err != nil {
		// I don't know why this is sometimes needed, but it is.
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return err
	}
	return nil
}
