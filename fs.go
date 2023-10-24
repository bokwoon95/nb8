package nb8

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type FS interface {
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)

	// OpenWriter opens an io.WriteCloser that represents an instance of a
	// file. The parent directory must exist. If the file doesn't exist, it
	// should be created. If the file exists, its should be truncated.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)

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
	ctx     context.Context // NOTE: not used for now.
	rootDir string
	tempDir string
}

var _ FS = (*LocalFS)(nil)

func (localFS *LocalFS) String() string {
	return localFS.rootDir
}

func NewLocalFS(rootDir, tempDir string) *LocalFS {
	return &LocalFS{
		ctx:     context.Background(),
		rootDir: rootDir,
		tempDir: tempDir,
	}
}

func (localFS *LocalFS) WithContext(ctx context.Context) FS {
	return &LocalFS{
		ctx:     ctx,
		rootDir: localFS.rootDir,
		tempDir: localFS.tempDir,
	}
}

func (localFS *LocalFS) Open(name string) (fs.File, error) {
	name = filepath.FromSlash(name)
	return os.Open(filepath.Join(localFS.rootDir, name))
}

func (localFS *LocalFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	file := &LocalFile{
		ctx:     localFS.ctx,
		rootDir: localFS.rootDir,
		tempDir: localFS.tempDir,
		name:    name,
		perm:    perm,
	}
	if file.tempDir == "" {
		file.tempDir = os.TempDir()
	}
	tempFile, err := os.CreateTemp(file.tempDir, "__notebrewtemp*__")
	if err != nil {
		return nil, err
	}
	file.tempFile = tempFile
	return file, nil
}

func (localFS *LocalFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = filepath.FromSlash(name)
	return os.ReadDir(filepath.Join(localFS.rootDir, name))
}

func (localFS *LocalFS) Mkdir(name string, perm fs.FileMode) error {
	name = filepath.FromSlash(name)
	return os.Mkdir(filepath.Join(localFS.rootDir, name), perm)
}

func (localFS *LocalFS) MkdirAll(name string, perm fs.FileMode) error {
	name = filepath.FromSlash(name)
	return os.MkdirAll(filepath.Join(localFS.rootDir, name), perm)
}

func (localFS *LocalFS) Remove(name string) error {
	name = filepath.FromSlash(name)
	return os.Remove(filepath.Join(localFS.rootDir, name))
}

func (localFS *LocalFS) RemoveAll(name string) error {
	name = filepath.FromSlash(name)
	return os.RemoveAll(filepath.Join(localFS.rootDir, name))
}

func (localFS *LocalFS) Rename(oldname, newname string) error {
	oldname = filepath.FromSlash(oldname)
	newname = filepath.FromSlash(newname)
	return os.Rename(filepath.Join(localFS.rootDir, oldname), filepath.Join(localFS.rootDir, newname))
}

type LocalFile struct {
	ctx      context.Context
	rootDir  string
	tempDir  string
	name     string
	perm     fs.FileMode
	tempFile *os.File
}

func (localFile *LocalFile) Write(p []byte) (n int, err error) {
	err = localFile.ctx.Err()
	if err != nil {
		return 0, err
	}
	return localFile.tempFile.Write(p)
}

func (localFile *LocalFile) Close() error {
	fileInfo, err := localFile.tempFile.Stat()
	if err != nil {
		return err
	}
	err = localFile.tempFile.Close()
	if err != nil {
		return err
	}
	tempFilePath := filepath.Join(localFile.tempDir, fileInfo.Name())
	destFilePath := filepath.Join(localFile.rootDir, localFile.name)
	mode := localFile.perm
	fileInfo, err = os.Stat(destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		mode = fileInfo.Mode()
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		return err
	}
	_ = os.Chmod(destFilePath, mode)
	return nil
}

func IsStoredInDB(filePath string) bool {
	ext := path.Ext(filePath)
	head, tail, _ := strings.Cut(filePath, "/")
	switch head {
	case "notes":
		if ext == ".txt" {
			return true
		}
	case "pages":
		if ext == ".html" {
			return true
		}
	case "posts":
		if ext == ".markdown" || ext == ".md" {
			return true
		}
	case "output":
		next, _, _ := strings.Cut(tail, "/")
		if next == "themes" && (ext == ".html" || ext == ".css" || ext == ".js") {
			return true
		}
	}
	return false
}

type RemoteFS struct {
	ctx     context.Context
	db      *sql.DB
	dialect string
	storage Storage
}

func NewRemoteFS(dialect string, db *sql.DB, storage Storage) *RemoteFS {
	return &RemoteFS{
		ctx:     context.Background(),
		db:      db,
		dialect: dialect,
		storage: storage,
	}
}

// fs.File
// io.ReaderFrom
// fs.DirEntry
// fs.FileInfo

type remoteFileInfo struct {
	fileID   [16]byte
	parentID [16]byte
	filePath string
	isDir    bool
	data     string
	size     int64
	modTime  time.Time
	mode     fs.FileMode
}

func (fileInfo *remoteFileInfo) Name() string {
	return path.Base(fileInfo.filePath)
}

func (fileInfo *remoteFileInfo) Size() int64 {
	if IsStoredInDB(fileInfo.filePath) {
		return int64(len(fileInfo.data))
	}
	return fileInfo.size
}

func (fileInfo *remoteFileInfo) Mode() fs.FileMode {
	if fileInfo.isDir {
		return fileInfo.mode | fs.ModeDir
	}
	return fileInfo.mode &^ fs.ModeDir
}

func (fileInfo *remoteFileInfo) ModTime() time.Time { return fileInfo.modTime }

func (fileInfo *remoteFileInfo) IsDir() bool { return fileInfo.isDir }

func (fileInfo *remoteFileInfo) Sys() any { return nil }

func (fileInfo *remoteFileInfo) Type() fs.FileMode { return fileInfo.Mode().Type() }

func (fileInfo *remoteFileInfo) FileInfo() (fs.FileInfo, error) { return fileInfo, nil }

type remoteFile struct {
	fileInfo   *remoteFileInfo
	readCloser io.ReadCloser
}

func (remoteFS *RemoteFS) Open(name string) (fs.File, error) {
	// TODO: pull remoteFileInfo from the database.
	fileInfo := &remoteFileInfo{}
	if IsStoredInDB(fileInfo.filePath) {
		fileReader := &remoteFile{
			fileInfo:   fileInfo,
			readCloser: io.NopCloser(strings.NewReader(fileInfo.data)),
		}
		return fileReader, nil
	}
	readCloser, err := remoteFS.storage.Get(context.Background(), fileInfo.filePath)
	if err != nil {
		return nil, err
	}
	fileReader := &remoteFile{
		fileInfo:   fileInfo,
		readCloser: readCloser,
	}
	return fileReader, nil
}

func (file *remoteFile) Read(p []byte) (n int, err error) {
	return file.readCloser.Read(p)
}

func (file *remoteFile) Close() error {
	return file.readCloser.Close()
}

func (file *remoteFile) Stat() (fs.FileInfo, error) {
	return file.fileInfo, nil
}

type remoteFileWriter struct {
	ctx  context.Context
	file *remoteFileInfo

	db      *sql.DB
	dialect string
	storage Storage
}

// func (fileWriter *remoteFileWriter) ReadFrom(r io.Reader) (n int64, err error) {
// 	if fileWriter.file.isDir {
// 		return 0, fmt.Errorf("%s is a directory", fileWriter.file.filePath)
// 	}
// 	// TODO: don't update, upsert.
// 	if isStoredInDB(fileWriter.file.filePath) {
// 		data, err := io.ReadAll(r)
// 		if err != nil {
// 			return int64(len(data)), err
// 		}
// 		_, err = sq.ExecContext(fileWriter.ctx, fileWriter.file.db, sq.CustomQuery{
// 			Dialect: fileWriter.file.dialect,
// 			Format:  "UPDATE files SET data = {data} WHERE file_id = {fileID}",
// 			Values: []any{
// 				sq.BytesParam("data", data),
// 				sq.UUIDParam("fileID", fileWriter.file.fileID),
// 			},
// 		})
// 		if err != nil {
// 			return 0, err
// 		}
// 		return int64(len(data)), nil
// 	}
// 	err = fileWriter.file.storage.Put(fileWriter.ctx, fileWriter.file.filePath, r)
// 	return 0, nil
// }

// Open(name string) (fs.File, error)
// OpenReaderFrom(name string, perm fs.FileMode) (io.ReaderFrom, error)
// ReadDir(name string) ([]fs.DirEntry, error)
// Mkdir(name string, perm fs.FileMode) error
// Remove(name string) error
// Rename(oldname, newname string) error
// RemoveAll
// MkdirAll
// (fs.FileInfo).GetSize()
// (fs.DirEntry).GetSize()

type Storage interface {
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Put(ctx context.Context, key string, reader io.Reader) error
	Delete(ctx context.Context, key string) error
}

type S3Storage struct {
	Client *s3.Client
	Bucket string
}

var _ Storage = (*S3Storage)(nil)

type S3StorageConfig struct {
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	AccessKeyID     string `json:"accessKeyID,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

func NewS3Storage(ctx context.Context, config S3StorageConfig) (*S3Storage, error) {
	storage := &S3Storage{
		Client: s3.New(s3.Options{
			BaseEndpoint: aws.String(config.Endpoint),
			Region:       config.Region,
			Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(config.AccessKeyID, config.SecretAccessKey, "")),
		}),
		Bucket: config.Bucket,
	}
	_, err := storage.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  &storage.Bucket,
		MaxKeys: 1,
	})
	if err != nil {
		return nil, err
	}
	return storage, nil
}

func (storage *S3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	key = strings.Trim(path.Clean(key), "/")
	output, err := storage.Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	return output.Body, nil
}

func (storage *S3Storage) Put(ctx context.Context, key string, reader io.Reader) error {
	key = strings.Trim(path.Clean(key), "/")
	_, err := storage.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
		Body:   reader,
	})
	if err != nil {
		return err
	}
	return nil
}

func (storage *S3Storage) Delete(ctx context.Context, key string) error {
	key = strings.Trim(path.Clean(key), "/")
	_, err := storage.Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &storage.Bucket,
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	return nil
}

type InMemoryStorage struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

var _ Storage = (*InMemoryStorage)(nil)

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		mu:      sync.RWMutex{},
		entries: make(map[string][]byte),
	}
}

func (storage *InMemoryStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	key = strings.Trim(path.Clean(key), "/")
	storage.mu.RLock()
	entry, ok := storage.entries[key]
	storage.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("entry does not exist for key %q", key)
	}
	return io.NopCloser(bytes.NewReader(entry)), nil
}

func (storage *InMemoryStorage) Put(ctx context.Context, key string, reader io.Reader) error {
	key = strings.Trim(path.Clean(key), "/")
	value, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	storage.mu.Lock()
	storage.entries[key] = value
	storage.mu.Unlock()
	return nil
}

func (storage *InMemoryStorage) Delete(ctx context.Context, key string) error {
	key = strings.Trim(path.Clean(key), "/")
	storage.mu.Lock()
	delete(storage.entries, key)
	storage.mu.Unlock()
	return nil
}

// RemoveAll removes the root item from the FS (whether it is a file or a
// directory).
func RemoveAll(fsys FS, root string) error {
	type Item struct {
		Path             string // relative to root
		IsFile           bool   // whether item is file or directory
		MarkedForRemoval bool   // if true, remove item unconditionally
	}
	// If the filesystem supports RemoveAll(), we can call that instead and
	// return.
	if fsys, ok := fsys.(interface{ RemoveAll(name string) error }); ok {
		return fsys.RemoveAll(root)
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
	// If the filesystem supports MkdirAll(), we can call that instead and
	// return.
	if fsys, ok := fsys.(interface {
		MkdirAll(dir string, perm fs.FileMode) error
	}); ok {
		return fsys.MkdirAll(dir, perm)
	}
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

func GetFileSize(fsys fs.FS, root string) (int64, error) {
	type Item struct {
		Path     string // relative to root
		DirEntry fs.DirEntry
	}
	fileInfo, err := fs.Stat(fsys, root)
	if err != nil {
		return 0, err
	}
	if !fileInfo.IsDir() {
		return fileInfo.Size(), nil
	}
	if s, ok := fileInfo.(interface{ GetSize() (int64, error) }); ok {
		n, err := s.GetSize()
		if err != nil {
			return 0, err
		}
		return n, nil
	}
	var size int64
	var item Item
	var items []Item
	dirEntries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return 0, err
	}
	for i := len(dirEntries) - 1; i >= 0; i-- {
		items = append(items, Item{
			Path:     dirEntries[i].Name(),
			DirEntry: dirEntries[i],
		})
	}
	for len(items) > 0 {
		item, items = items[len(items)-1], items[:len(items)-1]
		if !item.DirEntry.IsDir() {
			fileInfo, err = item.DirEntry.Info()
			if err != nil {
				return 0, fmt.Errorf("%s: %w", path.Join(root, item.Path), err)
			}
			size += fileInfo.Size()
			continue
		}
		if s, ok := item.DirEntry.(interface{ GetSize() (int64, error) }); ok {
			n, err := s.GetSize()
			if err != nil {
				return 0, fmt.Errorf("%s: %w", path.Join(root, item.Path), err)
			}
			size += n
			continue
		}
		dirEntries, err = fs.ReadDir(fsys, path.Join(root, item.Path))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", path.Join(root, item.Path), err)
		}
		for i := len(dirEntries) - 1; i >= 0; i-- {
			items = append(items, Item{
				Path:     path.Join(item.Path, dirEntries[i].Name()),
				DirEntry: dirEntries[i],
			})
		}
	}
	return size, nil
}
