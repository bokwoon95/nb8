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
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/bokwoon95/sq"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"golang.org/x/sync/errgroup"
)

var bufPool = sync.Pool{
	New: func() any { return &bytes.Buffer{} },
}

type FS interface {
	// WithContext returns a new FS with the given context.
	WithContext(context.Context) FS

	// Open opens the named file.
	Open(name string) (fs.File, error)
	// - fs.ErrInvalid
	// - fs.ErrNotExist
	// - syscall.EISDIR (read file)

	// OpenWriter opens an io.WriteCloser that represents an instance of a
	// file. The parent directory must exist. If the file doesn't exist, it
	// should be created. If the file exists, its should be truncated.
	OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error)
	// - fs.ErrInvalid
	// - syscall.EISDIR
	// - syscall.ENOTDIR (parent)
	// - fs.ErrNotExist (parent)

	// ReadDir reads the named directory and returns a list of directory
	// entries sorted by filename.
	ReadDir(name string) ([]fs.DirEntry, error)
	// - fs.ErrInvalid
	// - fs.ErrNotExist
	// - syscall.ENOTDIR

	// Mkdir creates a new directory with the specified name.
	Mkdir(name string, perm fs.FileMode) error
	// - fs.ErrInvalid
	// - fs.ErrNotExist (parent)
	// - fs.ErrExist

	// Remove removes the named file or directory.
	Remove(name string) error
	// - fs.ErrInvalid
	// - fs.ErrNotExist (parent)
	// - syscall.ENOTEMPTY

	// Rename renames (moves) oldname to newname. If newname already exists and
	// is not a directory, Rename replaces it.
	Rename(oldname, newname string) error
	// - fs.ErrInvalid
	// - fs.ErrNotExist (oldname)
	// - syscall.EISDIR (newname)
}

type LocalFS struct {
	rootDir string
	tempDir string
}

func NewLocalFS(rootDir, tempDir string) *LocalFS {
	return &LocalFS{
		rootDir: filepath.FromSlash(rootDir),
		tempDir: filepath.FromSlash(tempDir),
	}
}

func (fsys *LocalFS) String() string { return fsys.rootDir }

func (fsys *LocalFS) WithContext(ctx context.Context) FS {
	// NOTE: LocalFS does not yet respect context. For the local filesystem I
	// think it's fine to ignore context since that's what the default *os.File
	// does, but if it proves necessary we can add the file wrappers around
	// *os.File that respect context (only if it proves necessary).
	return &LocalFS{
		rootDir: fsys.rootDir,
		tempDir: fsys.tempDir,
	}
}

func (fsys *LocalFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Open(filepath.Join(fsys.rootDir, name))
}

type LocalFileWriter struct {
	ctx         context.Context
	rootDir     string
	tempDir     string
	name        string
	perm        fs.FileMode
	tempFile    *os.File
	writeFailed bool
}

func (fsys *LocalFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	file := &LocalFileWriter{
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
		file.writeFailed = true
		return 0, err
	}
	n, err = file.tempFile.Write(p)
	if err != nil {
		file.writeFailed = true
		return n, err
	}
	return n, nil
}

func (file *LocalFileWriter) Close() error {
	fileInfo, err := file.tempFile.Stat()
	if err != nil {
		return err
	}
	tempFilePath := filepath.Join(file.tempDir, fileInfo.Name())
	destFilePath := filepath.Join(file.rootDir, file.name)
	defer os.Remove(tempFilePath)
	err = file.tempFile.Close()
	if err != nil {
		return err
	}
	if file.writeFailed {
		return nil
	}
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
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.ReadDir(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Mkdir(name string, perm fs.FileMode) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Mkdir(filepath.Join(fsys.rootDir, name), perm)
}

func (fsys *LocalFS) MkdirAll(name string, perm fs.FileMode) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.MkdirAll(filepath.Join(fsys.rootDir, name), perm)
}

func (fsys *LocalFS) Remove(name string) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.Remove(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) RemoveAll(name string) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	name = filepath.FromSlash(name)
	return os.RemoveAll(filepath.Join(fsys.rootDir, name))
}

func (fsys *LocalFS) Rename(oldname, newname string) error {
	if !fs.ValidPath(oldname) || strings.Contains(oldname, "\\") {
		return &fs.PathError{Op: "rename", Path: oldname, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newname) || strings.Contains(newname, "\\") {
		return &fs.PathError{Op: "rename", Path: newname, Err: fs.ErrInvalid}
	}
	oldname = filepath.FromSlash(oldname)
	newname = filepath.FromSlash(newname)
	return os.Rename(filepath.Join(fsys.rootDir, oldname), filepath.Join(fsys.rootDir, newname))
}

type RemoteFS struct {
	ctx       context.Context
	db        *sql.DB
	dialect   string
	errorcode func(error) string
	storage   Storage
}

var textExtensions = map[string]struct{}{
	".html": {}, ".css": {}, ".js": {}, ".md": {}, ".txt": {}, ".json": {},
	".toml": {}, ".yaml": {}, ".yml": {}, ".xml": {},
}

func isStoredInDB(filePath string) bool {
	var ext string
	if strings.HasSuffix(filePath, ".gzip") {
		ext = path.Ext(strings.TrimSuffix(filePath, ".gzip"))
	} else if strings.HasSuffix(filePath, ".gz") {
		ext = path.Ext(strings.TrimSuffix(filePath, ".gz"))
	} else {
		ext = path.Ext(filePath)
	}
	_, ok := textExtensions[ext]
	return ok
}

func isFulltextIndexed(filePath string) bool {
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
		if ext == ".txt" || ext == ".md" {
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

func NewRemoteFS(dialect string, db *sql.DB, errorcode func(error) string, storage Storage) *RemoteFS {
	return &RemoteFS{
		ctx:       context.Background(),
		db:        db,
		dialect:   dialect,
		errorcode: errorcode,
		storage:   storage,
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
	size     int64
	modTime  time.Time
	perm     fs.FileMode
}

func (fileInfo *RemoteFileInfo) Name() string {
	return path.Base(fileInfo.filePath)
}

func (fileInfo *RemoteFileInfo) Size() int64 {
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
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &RemoteFile{
			fileInfo: &RemoteFileInfo{
				filePath: ".",
				isDir:    true,
			},
		}, nil
	}
	result, err := sq.FetchOneContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (result struct {
		RemoteFileInfo
		text string
		data []byte
	}) {
		row.UUID(&result.fileID, "file_id")
		row.UUID(&result.parentID, "parent_id")
		result.filePath = row.String("file_path")
		result.isDir = row.Bool("is_dir")
		result.size = row.Int64("size")
		var modTime sq.Timestamp
		row.Scan(&modTime, "mod_time")
		result.modTime = modTime.Time
		result.perm = fs.FileMode(row.Int("perm"))
		result.text = row.String("text")
		result.data = row.Bytes("data")
		return result
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
		return nil, err
	}
	file := &RemoteFile{
		fileInfo: &result.RemoteFileInfo,
	}
	if !result.isDir {
		if isStoredInDB(result.filePath) {
			if isFulltextIndexed(result.filePath) {
				file.readCloser = io.NopCloser(strings.NewReader(result.text))
				file.fileInfo.size = int64(len(result.text))
			} else {
				file.readCloser = io.NopCloser(bytes.NewReader(result.data))
				file.fileInfo.size = int64(len(result.data))
			}
		} else {
			file.readCloser, err = fsys.storage.Get(context.Background(), file.fileInfo.filePath)
			if err != nil {
				var apiErr smithy.APIError
				if errors.As(err, &apiErr) {
					if apiErr.ErrorCode() == "NoSuchKey" {
						return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
					}
				}
				return nil, err
			}
		}
	}
	return file, nil
}

func (file *RemoteFile) Read(p []byte) (n int, err error) {
	if file.fileInfo.isDir {
		return 0, &fs.PathError{Op: "read", Path: file.fileInfo.filePath, Err: syscall.EISDIR}
	}
	return file.readCloser.Read(p)
}

func (file *RemoteFile) Close() error {
	if file.fileInfo.isDir {
		return nil
	}
	return file.readCloser.Close()
}

func (file *RemoteFile) Stat() (fs.FileInfo, error) {
	return file.fileInfo, nil
}

type RemoteFileWriter struct {
	ctx            context.Context
	db             *sql.DB
	dialect        string
	storage        Storage
	fileID         [16]byte
	parentID       any // either nil or [16]byte
	filePath       string
	perm           fs.FileMode
	buf            *bytes.Buffer
	storageWriter  *io.PipeWriter
	storageWritten int
	storageResult  chan error
	writeFailed    bool
}

func (fsys *RemoteFS) OpenWriter(name string, perm fs.FileMode) (io.WriteCloser, error) {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
	}
	file := &RemoteFileWriter{
		ctx:      fsys.ctx,
		db:       fsys.db,
		dialect:  fsys.dialect,
		storage:  fsys.storage,
		filePath: name,
		perm:     perm,
	}
	filePaths := []string{file.filePath}
	parentDir := path.Dir(file.filePath)
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
				return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.EISDIR}
			}
			file.fileID = result.fileID
		case parentDir:
			if !result.isDir {
				return nil, &fs.PathError{Op: "openwriter", Path: name, Err: syscall.ENOTDIR}
			}
			file.parentID = result.fileID
		}
	}
	if parentDir != "." && file.parentID == nil {
		return nil, &fs.PathError{Op: "openwriter", Path: name, Err: fs.ErrNotExist}
	}
	if isFulltextIndexed(file.filePath) {
		file.buf = bufPool.Get().(*bytes.Buffer)
		file.buf.Reset()
	} else {
		pipeReader, pipeWriter := io.Pipe()
		file.storageWriter = pipeWriter
		file.storageResult = make(chan error, 1)
		go func() {
			file.storageResult <- fsys.storage.Put(file.ctx, hex.EncodeToString(file.fileID[:]), pipeReader)
		}()
	}
	return file, nil
}

func (file *RemoteFileWriter) Write(p []byte) (n int, err error) {
	err = file.ctx.Err()
	if err != nil {
		file.writeFailed = true
		return 0, err
	}
	if isFulltextIndexed(file.filePath) {
		n, err = file.buf.Write(p)
		if err != nil {
			file.writeFailed = true
		}
		return n, err
	} else {
		n, err = file.storageWriter.Write(p)
		file.storageWritten += n
		if err != nil {
			file.writeFailed = true
		}
		return n, err
	}
}

func (file *RemoteFileWriter) Close() error {
	if isFulltextIndexed(file.filePath) {
		defer bufPool.Put(file.buf)
	} else {
		file.storageWriter.Close()
		err := <-file.storageResult
		if err != nil {
			return err
		}
	}
	if file.writeFailed {
		return nil
	}

	// if file exists, just have to update the file entry in the database.
	if file.fileID != [16]byte{} {
		if isStoredInDB(file.filePath) {
			if isFulltextIndexed(file.filePath) {
				_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = {text}, data = NULL, size = NULL, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("text", file.buf.Bytes()),
						sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			} else {
				_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
					Dialect: file.dialect,
					Format:  "UPDATE files SET text = NULL, data = {data}, size = NULL, mod_time = {modTime} WHERE file_id = {fileID}",
					Values: []any{
						sq.BytesParam("data", file.buf.Bytes()),
						sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
						sq.UUIDParam("fileID", file.fileID),
					},
				})
				if err != nil {
					return err
				}
			}
		} else {
			_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
				Dialect: file.dialect,
				Format:  "UPDATE files SET text = NULL, data = NULL, size = {size}, mod_time = {modTime} WHERE file_id = {fileID}",
				Values: []any{
					sq.IntParam("size", file.storageWritten),
					sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
					sq.UUIDParam("fileID", file.fileID),
				},
			})
			if err != nil {
				return err
			}
		}
		return nil
	}

	// file doesn't exist, insert a new file entry into the database.
	if isStoredInDB(file.filePath) {
		if isFulltextIndexed(file.filePath) {
			_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, text, mod_time, perm)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {isDir}, {text}, {modTime}, {perm})",
				Values: []any{
					sq.UUIDParam("fileID", NewID()),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.BoolParam("isDir", false),
					sq.BytesParam("text", file.buf.Bytes()),
					sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
					sq.Param("perm", file.perm),
				},
			})
			if err != nil {
				return err
			}
		} else {
			_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
				Dialect: file.dialect,
				Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, data, mod_time, perm)" +
					" VALUES ({fileID}, {parentID}, {filePath}, {isDir}, {data}, {modTime}, {perm})",
				Values: []any{
					sq.UUIDParam("fileID", NewID()),
					sq.UUIDParam("parentID", file.parentID),
					sq.StringParam("filePath", file.filePath),
					sq.BoolParam("isDir", false),
					sq.BytesParam("data", file.buf.Bytes()),
					sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
					sq.Param("perm", file.perm),
				},
			})
			if err != nil {
				return err
			}
		}
	} else {
		_, err := sq.ExecContext(file.ctx, file.db, sq.CustomQuery{
			Dialect: file.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, size, mod_time, perm)" +
				" VALUES ({fileID}, {parentID}, {filePath}, {isDir}, {size}, {modTime}, {perm})",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.UUIDParam("parentID", file.parentID),
				sq.StringParam("filePath", file.filePath),
				sq.BoolParam("isDir", false),
				sq.IntParam("size", file.storageWritten),
				sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
				sq.Param("perm", file.perm),
			},
		})
		if err != nil {
			go file.storage.Delete(context.Background(), hex.EncodeToString(file.fileID[:]))
			return err
		}
	}
	return nil
}

func (fsys *RemoteFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	// Special case: if name is ".", ReadDir returns all top-level files in
	// the root directory (identified by a NULL parent_id).
	if name == "." {
		dirEntries, err := sq.FetchAllContext(fsys.ctx, fsys.db, sq.CustomQuery{
			Dialect: fsys.dialect,
			Format:  "SELECT {*} FROM files WHERE parent_id IS NULL ORDER BY file_path",
			Values: []any{
				sq.StringParam("name", name),
			},
		}, func(row *sq.Row) fs.DirEntry {
			var fileInfo RemoteFileInfo
			row.UUID(&fileInfo.fileID, "file_id")
			fileInfo.filePath = row.String("file_path")
			fileInfo.isDir = row.Bool("is_dir")
			fileInfo.size = row.Int64("size")
			var modTime sq.Timestamp
			row.Scan(&modTime, "mod_time")
			fileInfo.modTime = modTime.Time
			fileInfo.perm = fs.FileMode(row.Int("perm"))
			return &fileInfo
		})
		if err != nil {
			return nil, err
		}
		return dirEntries, nil
	}
	cursor, err := sq.FetchCursorContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format: "SELECT {*}" +
			" FROM files AS parent" +
			" LEFT JOIN files AS child ON child.parent_id = parent.file_id" +
			" WHERE parent.file_path = {name}" +
			" ORDER BY child.file_path",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (result struct {
		RemoteFileInfo
		ParentIsDir bool
	}) {
		row.UUID(&result.fileID, "child.file_id")
		row.UUID(&result.parentID, "child.parent_id")
		result.filePath = row.String("child.file_path")
		result.isDir = row.Bool("child.is_dir")
		result.size = row.Int64("child.size")
		var modTime sq.Timestamp
		row.Scan(&modTime, "child.mod_time")
		result.modTime = modTime.Time
		result.perm = fs.FileMode(row.Int("child.perm"))
		result.ParentIsDir = row.Bool("parent.is_dir")
		return result
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var dirEntries []fs.DirEntry
	for cursor.Next() {
		result, err := cursor.Result()
		if err != nil {
			return nil, err
		}
		if !result.ParentIsDir {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: syscall.ENOTDIR}
		}
		// file_id is a primary key, it must always exist. If it doesn't exist,
		// it means the left join failed to match any child entries i.e. the
		// directory is empty, so we return no entries.
		if result.fileID == [16]byte{} {
			return nil, cursor.Close()
		}
		dirEntries = append(dirEntries, &result.RemoteFileInfo)
	}
	if len(dirEntries) == 0 {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	return dirEntries, cursor.Close()
}

func (fsys *RemoteFS) Mkdir(name string, perm fs.FileMode) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	parentDir := path.Dir(name)
	if parentDir == "." {
		_, err := sq.ExecContext(fsys.ctx, fsys.db, sq.CustomQuery{
			Dialect: fsys.dialect,
			Format: "INSERT INTO files (file_id, file_path, is_dir, mod_time, perm)" +
				" VALUES ({fileID}, {filePath}, {isDir}, {modTime}, {perm})",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("filePath", name),
				sq.BoolParam("isDir", true),
				sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
				sq.Param("perm", perm),
			},
		})
		if err != nil {
			if fsys.errorcode == nil {
				return err
			}
			errcode := fsys.errorcode(err)
			if IsKeyViolation(fsys.dialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return err
		}
	} else {
		_, err := sq.ExecContext(fsys.ctx, fsys.db, sq.CustomQuery{
			Dialect: fsys.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, mod_time, perm)" +
				" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {isDir}, {modTime}, {perm})",
			Values: []any{
				sq.UUIDParam("fileID", NewID()),
				sq.StringParam("parentDir", parentDir),
				sq.StringParam("filePath", name),
				sq.BoolParam("isDir", true),
				sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
				sq.Param("perm", perm),
			},
		})
		if err != nil {
			if fsys.errorcode == nil {
				return err
			}
			errcode := fsys.errorcode(err)
			if IsKeyViolation(fsys.dialect, errcode) {
				return &fs.PathError{Op: "mkdir", Path: name, Err: fs.ErrExist}
			}
			return err
		}
	}
	return nil
}

func (fsys *RemoteFS) MkdirAll(name string, perm fs.FileMode) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return &fs.PathError{Op: "mkdirall", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return nil
	}
	conn, err := fsys.db.Conn(fsys.ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Insert the top level directory (no parent), ignoring duplicates.
	segments := strings.Split(name, "/")
	query := sq.CustomQuery{
		Dialect: fsys.dialect,
		Format: "INSERT INTO files (file_id, file_path, is_dir, mod_time, perm)" +
			" VALUES ({fileID}, {filePath}, {isDir}, {modTime}, {perm})",
		Values: []any{
			sq.UUIDParam("fileID", NewID()),
			sq.StringParam("filePath", segments[0]),
			sq.BoolParam("isDir", true),
			sq.Param("modTime", sq.NewTimestamp(time.Now().UTC())),
			sq.Param("perm", perm),
		},
	}
	switch fsys.dialect {
	case "sqlite", "postgres":
		query = query.Append("ON CONFLICT DO NOTHING")
	case "mysql":
		query = query.Append("ON DUPLICATE KEY UPDATE file_id = file_id")
	}
	_, err = sq.ExecContext(fsys.ctx, conn, query)
	if err != nil {
		return err
	}
	// Insert the rest of the directories, ignoring duplicates.
	if len(segments) > 1 {
		query := sq.CustomQuery{
			Dialect: fsys.dialect,
			Format: "INSERT INTO files (file_id, parent_id, file_path, is_dir, mod_time, perm)" +
				" VALUES ({fileID}, (select file_id FROM files WHERE file_path = {parentDir}), {filePath}, {isDir}, {modTime}, {perm})",
			Values: []any{
				sq.Param("fileID", nil),
				sq.Param("parentDir", nil),
				sq.Param("filePath", nil),
				sq.Param("isDir", nil),
				sq.Param("modTime", nil),
				sq.Param("perm", nil),
			},
		}
		switch fsys.dialect {
		case "sqlite", "postgres":
			query = query.Append("ON CONFLICT DO NOTHING")
		case "mysql":
			query = query.Append("ON DUPLICATE KEY UPDATE file_id = file_id")
		}
		preparedExec, err := sq.PrepareExecContext(fsys.ctx, conn, query)
		if err != nil {
			return err
		}
		defer preparedExec.Close()
		for i := 1; i < len(segments); i++ {
			_, err = preparedExec.ExecContext(fsys.ctx, map[string]any{
				"fileID":    NewID(),
				"parentDir": path.Join(segments[:i]...),
				"filePath":  path.Join(segments[:i+1]...),
				"isDir":     true,
				"modTime":   sq.NewTimestamp(time.Now().UTC()),
				"perm":      perm,
			})
			if err != nil {
				return err
			}
		}
	}
	err = conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (fsys *RemoteFS) Remove(name string) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrInvalid}
	}
	file, err := sq.FetchOneContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	}, func(row *sq.Row) (file struct {
		fileID       [16]byte
		hasChildren  bool
		isStoredInDB bool
	}) {
		row.UUID(&file.fileID, "file_id")
		file.hasChildren = row.Bool("EXISTS (SELECT 1 FROM files WHERE file_path LIKE {pattern} ESCAPE '\\')", sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(name)+"/%"))
		file.isStoredInDB = row.Bool("text IS NOT NULL OR data IS NOT NULL")
		return file
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
		}
		return err
	}
	if file.hasChildren {
		return &fs.PathError{Op: "remove", Path: name, Err: syscall.ENOTEMPTY}
	}
	if !file.isStoredInDB {
		err = fsys.storage.Delete(fsys.ctx, hex.EncodeToString(file.fileID[:]))
		if err != nil {
			return err
		}
	}
	_, err = sq.ExecContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "DELETE FROM files WHERE file_path = {name}",
		Values: []any{
			sq.StringParam("name", name),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (fsys *RemoteFS) RemoveAll(name string) error {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") || name == "." {
		return &fs.PathError{Op: "removeall", Path: name, Err: fs.ErrInvalid}
	}
	pattern := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(name) + "/%"
	fileIDs, err := sq.FetchAllContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\' AND data IS NULL",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	}, func(row *sq.Row) [16]byte {
		var fileID [16]byte
		row.UUID(&fileID, "file_id")
		return fileID
	})
	g, ctx := errgroup.WithContext(fsys.ctx)
	for _, fileID := range fileIDs {
		fileID := fileID
		g.Go(func() error {
			return fsys.storage.Delete(ctx, hex.EncodeToString(fileID[:]))
		})
	}
	err = g.Wait()
	if err != nil {
		return err
	}
	_, err = sq.ExecContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "DELETE FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", pattern),
		},
	})
	if err != nil {
		return err
	}
	return nil
}

func (fsys *RemoteFS) Rename(oldname, newname string) error {
	if !fs.ValidPath(oldname) || strings.Contains(oldname, "\\") {
		return &fs.PathError{Op: "rename", Path: oldname, Err: fs.ErrInvalid}
	}
	if !fs.ValidPath(newname) || strings.Contains(newname, "\\") {
		return &fs.PathError{Op: "rename", Path: newname, Err: fs.ErrInvalid}
	}
	tx, err := fsys.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	oldnameIsDir, err := sq.FetchOneContext(fsys.ctx, tx, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {oldname}",
		Values: []any{
			sq.StringParam("oldname", oldname),
		},
	}, func(row *sq.Row) bool {
		return row.Bool("is_dir")
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return &fs.PathError{Op: "rename", Path: oldname, Err: fs.ErrNotExist}
		}
		return err
	}
	if !oldnameIsDir && isStoredInDB(oldname) != isStoredInDB(newname) {
		return fmt.Errorf("cannot rename file from %q to %q because of incompatible storage locations", oldname, newname)
	}
	_, err = sq.ExecContext(fsys.ctx, tx, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "DELETE FROM files WHERE file_path = {newname} AND NOT is_dir",
		Values: []any{
			sq.StringParam("newname", newname),
		},
	})
	if err != nil {
		return err
	}
	updateTextOrData := sq.Expr("")
	if !oldnameIsDir && isStoredInDB(oldname) && isStoredInDB(newname) {
		if !isFulltextIndexed(oldname) && isFulltextIndexed(newname) {
			switch fsys.dialect {
			case "sqlite":
				updateTextOrData = sq.Expr(", text = data, data = NULL")
			case "postgres":
				updateTextOrData = sq.Expr(", text = convert_from(data, 'UTF8'), data = NULL")
			case "mysql":
				updateTextOrData = sq.Expr(", text = convert(data USING utf8mb4), data = NULL")
			}
		} else if isFulltextIndexed(oldname) && !isFulltextIndexed(newname) {
			switch fsys.dialect {
			case "sqlite":
				updateTextOrData = sq.Expr(", data = text, text = NULL")
			case "postgres":
				updateTextOrData = sq.Expr(", data = convert_to(text, 'UTF8'), text = NULL")
			case "mysql":
				updateTextOrData = sq.Expr(", data = convert(text USING BINARY), text = NULL")
			}
		}
	}
	modTime := sq.NewTimestamp(time.Now().UTC())
	_, err = sq.ExecContext(fsys.ctx, tx, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "UPDATE files SET file_path = {newname}, mod_time = {modTime}{updateTextOrData} WHERE file_path = {oldname}",
		Values: []any{
			sq.StringParam("newname", newname),
			sq.Param("modTime", modTime),
			sq.Param("updateTextOrData", updateTextOrData),
			sq.StringParam("oldname", oldname),
		},
	})
	if err != nil {
		// We weren't able to delete {newname} earlier, which means it is a
		// directory.
		if fsys.errorcode == nil {
			return err
		}
		errcode := fsys.errorcode(err)
		if IsKeyViolation(fsys.dialect, errcode) {
			return &fs.PathError{Op: "rename", Path: newname, Err: syscall.EISDIR}
		}
		return err
	}
	if oldnameIsDir {
		_, err = sq.ExecContext(fsys.ctx, tx, sq.CustomQuery{
			Dialect: fsys.dialect,
			Format:  "UPDATE files SET file_path = {newFilePath}, mod_time = {modTime} WHERE file_path LIKE {pattern} ESCAPE '\\'",
			Values: []any{
				sq.Param("newFilePath", sq.DialectExpression{
					Default: sq.Expr("{} || SUBSTR(file_path, {})", newname, len(oldname)+1),
					Cases: []sq.DialectCase{{
						Dialect: "mysql",
						Result:  sq.Expr("CONCAT({}, SUBSTR(file_path, {}))", newname, len(oldname)+1),
					}},
				}),
				sq.Param("modTime", modTime),
				sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(oldname)+"/%"),
			},
		})
		if err != nil {
			return err
		}
	}
	err = tx.Commit()
	if err != nil {
		return err
	}
	return nil
}

// If ReadDirByX() method exists, then call it
// Else, call ReadDir() as usual
// For both cases, preallocate a separate slice of identical capacity (with len 0) and accumulate all folders into it
// Sort the folders slice in alphabetical ascending order (unconditionally)
// Then do an in-place filter on the old slice removing all folders leaving behind only files
// If we called ReadDir() just now, do the file sorting now using sort and order params
// Then append the files behind the folders in the folders slice and return that slice (files always trail folders)
// If we called PaginateDir, lop off the last item and set it as the next item id
// Build the query string for the [next] link
// TODO: but what about the [previous] link? What's the value of from? 🤔
// "from" change to "after", also add "before"

func (fsys *RemoteFS) ReadDirByName(name string, before, after string, limit int) ([]fs.DirEntry, error) {
	return nil, nil
}

func (fsys *RemoteFS) ReadDirByUpdated(name string, before, after time.Time, limit int) ([]fs.DirEntry, error) {
	return nil, nil
}

func (fsys *RemoteFS) ReadDirByCreated(name string, before, after time.Time, limit int) ([]fs.DirEntry, error) {
	return nil, nil
}

func (fsys *RemoteFS) ReadDirBySize(name string, before, after int64, limit int) ([]fs.DirEntry, error) {
	return nil, nil
}

func (fsys *RemoteFS) Match(name string) /* what return? */ {
}

func (fsys *RemoteFS) GetSize(name string) (int64, error) {
	if !fs.ValidPath(name) || strings.Contains(name, "\\") {
		return 0, &fs.PathError{Op: "getsize", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		size, err := sq.FetchOneContext(fsys.ctx, fsys.db, sq.CustomQuery{
			Dialect: fsys.dialect,
			Format:  "SELECT {*} FROM files",
		}, func(row *sq.Row) int64 {
			return row.Int64Field(sq.DialectExpression{
				Default: sq.Expr("SUM(COALESCE(OCTET_LENGTH(text), OCTET_LENGTH(data), size, 0))"),
				Cases: []sq.DialectCase{{
					Dialect: "sqlite",
					Result:  sq.Expr("SUM(COALESCE(LENGTH(CAST(text AS BLOB)), LENGTH(CAST(data AS BLOB)), size, 0))"),
				}},
			})
		})
		if err != nil {
			return 0, err
		}
		return size, nil
	}
	size, err := sq.FetchOneContext(fsys.ctx, fsys.db, sq.CustomQuery{
		Dialect: fsys.dialect,
		Format:  "SELECT {*} FROM files WHERE file_path = {name} OR file_path LIKE {pattern} ESCAPE '\\'",
		Values: []any{
			sq.StringParam("name", name),
			sq.StringParam("pattern", strings.NewReplacer("%", "\\%", "_", "\\_").Replace(name)+"/%"),
		},
	}, func(row *sq.Row) int64 {
		return row.Int64Field(sq.DialectExpression{
			Default: sq.Expr("SUM(COALESCE(OCTET_LENGTH(text), OCTET_LENGTH(data), size, 0))"),
			Cases: []sq.DialectCase{{
				Dialect: "sqlite",
				Result:  sq.Expr("SUM(COALESCE(LENGTH(CAST(text AS BLOB)), LENGTH(CAST(data AS BLOB)), size, 0))"),
			}},
		})
	})
	if err != nil {
		return 0, err
	}
	return size, nil
}

func MkdirAll(fsys FS, name string, perm fs.FileMode) error {
	// If the filesystem supports MkdirAll(), we can call that instead and
	// return.
	if fsys, ok := fsys.(interface {
		MkdirAll(name string, perm fs.FileMode) error
	}); ok {
		return fsys.MkdirAll(name, perm)
	}
	fileInfo, err := fs.Stat(fsys, name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if fileInfo != nil {
		if fileInfo.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "mkdirall", Path: name, Err: syscall.ENOTDIR}
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
	i := len(name)
	for i > 0 && isPathSeparator(name[i-1]) { // Skip trailing path separator.
		i--
	}
	j := i
	for j > 0 && !isPathSeparator(name[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = MkdirAll(fsys, fixRootDirectory(name[:j-1]), perm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = fsys.Mkdir(name, perm)
	if err != nil {
		// I don't know why this is sometimes needed, but it is.
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return err
	}
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

// TODO: we should be able to scrap this entirely. The localFS can be summed
// using filepath.WalkDir + goroutines + atomic.Int64, while remoteFS can be
// summed using a single SQL query. All this will be locally within the file.go
// function itself.
func GetSize(fsys fs.FS, root string) (int64, error) {
	type Item struct {
		Path     string // relative to root
		DirEntry fs.DirEntry
	}
	if fsys, ok := fsys.(interface {
		GetSize(root string) (int64, error)
	}); ok {
		return fsys.GetSize(root)
	}
	fileInfo, err := fs.Stat(fsys, root)
	if err != nil {
		return 0, err
	}
	if !fileInfo.IsDir() {
		return fileInfo.Size(), nil
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

// TODO: what would a directory pagination interface look like?
// NOTE: rachelbythebay who has been writing since 2011 only has 1153 posts, which comfortably fits within one page. we'll do fine with a batch size of 1000.
// NOTE: sort=name|created|updated order=asc|desc limit=1000 v=value
// NOTE: for each batch size, we'll unconditionally sort it such that directories always rise to the top. no exceptions. and directories are always sorted in alphabetical order because the name is the only thing we can count on being accurate (created, updated and size require additional computation which I'm not willing to spare). this will be done in folder.go, not by PaginateDir itself. The filesystem never has to concern itself with whether or not it has to sort directories to the top.
// No pages I'm afraid. Only keyset pagination, which means you can just to the start or jump to the end very quickly (by ordering asc or desc) but not in the middle.
// for sort=name, v is just the base name (not full path). then on the server side we just assemble the full path using join(sitePrefix, parentDir, v)
// v is matched using greater or equal >=. Whenever we show 1000 items, we always fetch 1000+1 items. The +1 item is not show on the page, but its presence indicates that there is a next page (the template uses this to display the next button conditionally) and the item's name is used as v for the next button.

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
	// Ping the bucket and see if we have access.
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
	storage.mu.RLock()
	value, ok := storage.entries[key]
	storage.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("entry does not exist for key %q", key)
	}
	return io.NopCloser(bytes.NewReader(value)), nil
}

func (storage *InMemoryStorage) Put(ctx context.Context, key string, reader io.Reader) error {
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
	storage.mu.Lock()
	delete(storage.entries, key)
	storage.mu.Unlock()
	return nil
}

// TODO: how do we multiplex? First two significant digits or last 2 digits? Or
// last 3 digits? Assuming a standard image size of 600kB, how many images are
// we looking to store in 1TB and will it fit inside 256 or 4096 buckets? Just
// let people dump *all* images into one directory?
// I'm leaning towards 2 digits. If it's good enough for git it's good enough
// for me.
type LocalStorage struct {
	mu      sync.RWMutex
	entries map[string][]byte
}

func (fsys *LocalFS) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	return fsys.Open(key)
}

func (fsys *LocalFS) Put(ctx context.Context, key string, reader io.Reader) error {
	writer, err := fsys.OpenWriter(key, 0644)
	if err != nil {
		return err
	}
	defer writer.Close()
	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}
	return writer.Close()
}

func (fsys *LocalFS) Delete(ctx context.Context, key string) error {
	return fsys.Remove(key)
}

func NewID() [16]byte {
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], uint64(time.Now().Unix()))
	var id [16]byte
	copy(id[:5], timestamp[len(timestamp)-5:])
	_, err := rand.Read(id[5:])
	if err != nil {
		panic(err)
	}
	return id
}

func IsKeyViolation(dialect string, errcode string) bool {
	switch dialect {
	case "sqlite":
		return errcode == "1555" || errcode == "2067" // SQLITE_CONSTRAINT_PRIMARYKEY, SQLITE_CONSTRAINT_UNIQUE
	case "postgres":
		return errcode == "23505" // unique_violation
	case "mysql":
		return errcode == "1062" // ER_DUP_ENTRY
	case "sqlserver":
		return errcode == "2627"
	default:
		return false
	}
}

func IsForeignKeyViolation(dialect string, errcode string) bool {
	switch dialect {
	case "sqlite":
		return errcode == "787" //  SQLITE_CONSTRAINT_FOREIGNKEY
	case "postgres":
		return errcode == "23503" // foreign_key_violation
	case "mysql":
		return errcode == "1216" // ER_NO_REFERENCED_ROW
	case "sqlserver":
		return errcode == "547"
	default:
		return false
	}
}

var goldmarkMarkdown = func() goldmark.Markdown {
	md := goldmark.New()
	md.Parser().AddOptions(parser.WithAttribute())
	extension.Table.Extend(md)
	return md
}()

func stripMarkdownStyles(src []byte) string {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	var node ast.Node
	nodes := []ast.Node{goldmarkMarkdown.Parser().Parse(text.NewReader(src))}
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		if node == nil {
			continue
		}
		switch node := node.(type) {
		case *ast.Text:
			buf.Write(node.Text(src))
		}
		nodes = append(nodes, node.NextSibling(), node.FirstChild())
	}
	// Manually escape backslashes (goldmark may be able to do this,
	// investigate).
	var b strings.Builder
	str := buf.String()
	// Jump to the location of each backslash found in the string.
	for i := strings.IndexByte(str, '\\'); i >= 0; i = strings.IndexByte(str, '\\') {
		b.WriteString(str[:i])
		if i == len(str)-1 {
			break
		}
		char, width := utf8.DecodeRuneInString(str[i+1:])
		b.WriteRune(char)
		str = str[i+1+width:]
	}
	b.WriteString(str)
	return b.String()
}
