package nb8

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
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
	"github.com/bokwoon95/sq"
)

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

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

func NewLocalFS(rootDir, tempDir string) *LocalFS {
	return &LocalFS{
		ctx:     context.Background(),
		rootDir: filepath.FromSlash(rootDir),
		tempDir: filepath.FromSlash(tempDir),
	}
}

func (fsys *LocalFS) String() string { return fsys.rootDir }

func (fsys *LocalFS) WithContext(ctx context.Context) FS {
	return &LocalFS{
		ctx:     ctx,
		rootDir: fsys.rootDir,
		tempDir: fsys.tempDir,
	}
}

func (fsys *LocalFS) Open(name string) (fs.File, error) {
	name = filepath.FromSlash(name)
	return os.Open(filepath.Join(fsys.rootDir, name))
}

type LocalFileWriter struct {
	ctx      context.Context
	rootDir  string
	tempDir  string
	name     string
	perm     fs.FileMode
	tempFile *os.File
}

func (fsys *LocalFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	file := &LocalFileWriter{
		ctx:     fsys.ctx,
		rootDir: fsys.rootDir,
		tempDir: fsys.tempDir,
		name:    filepath.FromSlash(name),
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

func (file *LocalFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		return 0, err
	}
	return file.tempFile.Write(p)
}

func (file *LocalFileWriter) Close() error {
	fileInfo, err := file.tempFile.Stat()
	if err != nil {
		return err
	}
	err = file.tempFile.Close()
	if err != nil {
		return err
	}
	tempFilePath := filepath.Join(file.tempDir, fileInfo.Name())
	destFilePath := filepath.Join(file.rootDir, file.name)
	fileInfo, err = os.Stat(destFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		defer os.Chmod(destFilePath, file.perm)
	}
	err = os.Rename(tempFilePath, destFilePath)
	if err != nil {
		return err
	}
	return nil
}

func (fsys *LocalFS) ReadDir(name string) ([]fs.DirEntry, error) {
	name = filepath.FromSlash(name)
	return os.ReadDir(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Mkdir(name string, perm fs.FileMode) error {
	name = filepath.FromSlash(name)
	return os.Mkdir(filepath.Join(fsys.rootDir, name), perm)
}

func (fsys *LocalFS) MkdirAll(name string, perm fs.FileMode) error {
	name = filepath.FromSlash(name)
	return os.MkdirAll(filepath.Join(fsys.rootDir, name), perm)
}

func (fsys *LocalFS) Remove(name string) error {
	name = filepath.FromSlash(name)
	return os.Remove(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) RemoveAll(name string) error {
	name = filepath.FromSlash(name)
	return os.RemoveAll(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Rename(oldname, newname string) error {
	oldname = filepath.FromSlash(oldname)
	newname = filepath.FromSlash(newname)
	return os.Rename(filepath.Join(fsys.rootDir, oldname), filepath.Join(fsys.rootDir, newname))
}

type RemoteFS struct {
	ctx     context.Context
	db      *sql.DB
	dialect string
	storage Storage
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

func NewRemoteFS(dialect string, db *sql.DB, storage Storage) *RemoteFS {
	return &RemoteFS{
		ctx:     context.Background(),
		db:      db,
		dialect: dialect,
		storage: storage,
	}
}

func (fsys *RemoteFS) WithContext(ctx context.Context) FS {
	return &RemoteFS{
		ctx:     ctx,
		db:      fsys.db,
		dialect: fsys.dialect,
		storage: fsys.storage,
	}
}

type RemoteFileInfo struct {
	fileID   [16]byte
	parentID [16]byte
	filePath string
	isDir    bool
	data     string
	size     int64
	modTime  time.Time
	perm     fs.FileMode
}

func (fileInfo *RemoteFileInfo) Name() string {
	return path.Base(fileInfo.filePath)
}

func (fileInfo *RemoteFileInfo) Size() int64 {
	if IsStoredInDB(fileInfo.filePath) {
		return int64(len(fileInfo.data))
	}
	return fileInfo.size
}

func (fileInfo *RemoteFileInfo) Mode() fs.FileMode {
	if fileInfo.isDir {
		return fileInfo.perm | fs.ModeDir
	}
	return fileInfo.perm &^ fs.ModeDir
}

func (fileInfo *RemoteFileInfo) ModTime() time.Time { return fileInfo.modTime }

func (fileInfo *RemoteFileInfo) IsDir() bool { return fileInfo.isDir }

func (fileInfo *RemoteFileInfo) Sys() any { return nil }

func (fileInfo *RemoteFileInfo) Type() fs.FileMode { return fileInfo.Mode().Type() }

func (fileInfo *RemoteFileInfo) Info() (fs.FileInfo, error) { return fileInfo, nil }

type RemoteFile struct {
	fileInfo   *RemoteFileInfo
	readCloser io.ReadCloser
}

func (fsys *RemoteFS) Open(name string) (fs.File, error) {
	// TODO: handle name == "."
	fileInfo, err := sq.FetchOneContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) *RemoteFileInfo {
		var fileInfo RemoteFileInfo
		row.UUID(&fileInfo.fileID, "file_id")
		row.UUID(&fileInfo.parentID, "parent_id")
		fileInfo.filePath = row.String("file_path")
		fileInfo.isDir = row.Bool("is_dir")
		fileInfo.data = row.String("data")
		fileInfo.size = row.Int64("size")
		fileInfo.modTime = row.Time("mod_time")
		fileInfo.perm = fs.FileMode(row.Int("perm"))
		return &fileInfo
	})
	var readCloser io.ReadCloser
	if !fileInfo.isDir {
		if IsStoredInDB(fileInfo.filePath) {
			readCloser = io.NopCloser(strings.NewReader(fileInfo.data))
		} else {
			readCloser, err = fsys.storage.Get(context.Background(), fileInfo.filePath)
			if err != nil {
				return nil, err
			}
		}
	}
	file := &RemoteFile{
		fileInfo:   fileInfo,
		readCloser: readCloser,
	}
	return file, nil
}

func (file *RemoteFile) Read(p []byte) (n int, err error) {
	if file.readCloser == nil {
		return 0, fmt.Errorf("%q is a directory", file.fileInfo.filePath)
	}
	return file.readCloser.Read(p)
}

func (file *RemoteFile) Close() error {
	if file.readCloser == nil {
		return nil
	}
	return file.readCloser.Close()
}

func (file *RemoteFile) Stat() (fs.FileInfo, error) {
	return file.fileInfo, nil
}

type RemoteFileWriter struct {
	ctx      context.Context
	db       *sql.DB
	dialect  string
	storage  Storage
	fileID   any // either nil or [16]byte
	parentID any // either nil or [16]byte
	name     string
	perm     fs.FileMode
	buf      *bytes.Buffer
}

func (fsys *RemoteFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	// TODO: handle name == "."
	file := &RemoteFileWriter{
		ctx:     fsys.ctx,
		db:      fsys.db,
		dialect: fsys.dialect,
		storage: fsys.storage,
		name:    name,
		perm:    perm,
		buf:     bufPool.Get().(*bytes.Buffer),
	}
	file.buf.Reset()
	filePaths := []string{name}
	parentDir := path.Dir(name)
	if parentDir != "." {
		filePaths = append(filePaths, parentDir)
	}
	results, err := sq.FetchAllContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path IN ({filePaths})",
		Values: []any{
			sq.Param("filePaths", filePaths),
		},
	}, func(row *sq.Row) (result struct {
		fileID   [16]byte
		filePath string
		isDir    bool
	}) {
		row.UUID(&result.fileID, "file_id")
		result.filePath = row.String("file_path")
		result.isDir = row.Bool("is_dir")
		return result
	})
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		switch result.filePath {
		case name:
			if result.isDir {
				return nil, fmt.Errorf("%q exists and is a directory", name)
			}
			file.fileID = result.fileID
		case parentDir:
			if !result.isDir {
				return nil, fmt.Errorf("parent %q exists but is not a directory", parentDir)
			}
			file.parentID = result.fileID
		}
	}
	if parentDir != "." && file.parentID == nil {
		return nil, fmt.Errorf("parent dir %q does not exist", parentDir)
	}
	return file, nil
}

func (file *RemoteFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		return 0, err
	}
	return file.buf.Write(p)
}

func (file *RemoteFileWriter) Close() error {
	defer bufPool.Put(file.buf)
	modTime := sq.NewTimestamp(time.Now().UTC())
	fileID, _ := file.fileID.([16]byte)

	// fileID exists, just have to update the file entry in the database.
	if fileID != [16]byte{} {
		if IsStoredInDB(file.name) {
			_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
				Dialect: file.dialect,
				Format:  "UPDATE files SET data = {data}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.BytesParam("data", file.buf.Bytes()),
					sq.Param("modTime", modTime),
					sq.UUIDParam("fileID", fileID),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
				Dialect: file.dialect,
				Format:  "UPDATE files SET size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.IntParam("size", file.buf.Len()),
					sq.Param("modTime", modTime),
					sq.UUIDParam("fileID", fileID),
				},
			})
			if err != nil {
				return err
			}
			err = file.storage.Put(file.ctx, hex.EncodeToString(fileID[:]), file.buf)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// fileID doesn't exist, generate a new one and insert a file entry into
	// the database.
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
	copy(fileID[:5], timestamp[len(timestamp)-5:])
	_, err := rand.Read(fileID[5:])
	if err != nil {
		return err
	}
	if IsStoredInDB(file.name) {
		_, err = sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, data, mod_time, perm)" +
				" VALUES ({fileID}, {parentID}, {name}, {isDir}, {data}, {modTime}, {perm})",
			Values: []any{
				sq.UUIDParam("fileID", fileID),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("name", file.name),
				sq.BoolParam("isDir", true),
				sq.BytesParam("data", file.buf.Bytes()),
				sq.Param("modTime", modTime),
				sq.Param("perm", file.perm),
			},
		})
		if err != nil {
			return err
		}
	} else {
		_, err = sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, size, mod_time, perm)" +
				" VALUES ({fileID}, {parentID}, {name}, {isDir}, {size}, {modTime}, {perm})",
			Values: []any{
				sq.UUIDParam("fileID", fileID),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("name", file.name),
				sq.BoolParam("isDir", true),
				sq.IntParam("size", file.buf.Len()),
				sq.Param("modTime", modTime),
				sq.Param("perm", file.perm),
			},
		})
		if err != nil {
			return err
		}
		err = file.storage.Put(file.ctx, hex.EncodeToString(fileID[:]), file.buf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (fsys *RemoteFS) ReadDir(name string) ([]fs.DirEntry, error) {
	// TODO: handle name == "."
	// TODO: SELECT * FROM files LEFT JOIN files AS child instead, so that no
	// rows signals no such dir, and one row with null child.file_id signals no
	// children.
	cursor, err := sq.FetchCursorContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format: "SELECT {*}" +
			" FROM files" +
			" JOIN files AS parents ON parents.file_id = files.parent_id" +
			" WHERE parents.file_path = {name}" +
			" ORDER BY files.file_path",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (result struct {
		RemoteFileInfo
		ParentIsDir bool
	}) {
		row.UUID(&result.fileID, "files.file_id")
		row.UUID(&result.parentID, "files.parent_id")
		result.filePath = row.String("files.file_path")
		result.isDir = row.Bool("files.is_dir")
		result.size = row.Int64("files.size")
		result.modTime = row.Time("files.mod_time")
		result.perm = fs.FileMode(row.Int("files.perm"))
		result.ParentIsDir = row.Bool("parents.is_dir")
		return result
	})
	if err != nil {
		return nil, err
	}
	var dirEntries []fs.DirEntry
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return nil, err
		}
		if !result.ParentIsDir {
			return nil, fmt.Errorf("%q is not a directory", name)
		}
		dirEntries = append(dirEntries, &result.RemoteFileInfo)
	}
	return dirEntries, cursor.Close()
}

func (fsys *RemoteFS) Mkdir(name string, perm fs.FileMode) error {
	return nil
}

func (fsys *RemoteFS) Remove(name string) error {
	return nil
}

func (fsys *RemoteFS) Rename(oldname, newname string) error {
	return nil
}

// TODO: what would a directory pagination interface look like?

// Open(name string) (fs.File, error)
// OpenReaderFrom(name string, perm fs.FileMode) (io.ReaderFrom, error)
// ReadDir(name string) ([]fs.DirEntry, error)
// Mkdir(name string, perm fs.FileMode) error
// Remove(name string) error
// Rename(oldname, newname string) error
// RemoveAll
// MkdirAll
// WalkDir
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
