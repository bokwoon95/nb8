CREATE TABLE files (
    file_id UUID
    ,parent_id UUID
    ,file_path TEXT
    ,is_dir BOOLEAN
);

-- Open(name string) (fs.File, error)

-- OpenReaderFrom(name string, perm fs.FileMode) (io.ReaderFrom, error)

-- ReadDir(name string) ([]fs.DirEntry, error)

-- Mkdir(name string, perm fs.FileMode) error

-- Remove(name string) error

-- Rename(oldname, newname string) error
