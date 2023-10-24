package nb8

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"

	"github.com/bokwoon95/sq"
	"github.com/bokwoon95/sqddl/ddl"
)

//go:embed schema.go
var schemaFS embed.FS

func Automigrate(dialect string, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("db is nil")
	}
	automigrateCmd := &ddl.AutomigrateCmd{
		DB:             db,
		Dialect:        dialect,
		DirFS:          schemaFS,
		Filenames:      []string{"schema.go"},
		DropObjects:    true,
		AcceptWarnings: true,
		DryRun:         false,
		Stdout:         io.Discard,
		Stderr:         io.Discard,
	}
	err := automigrateCmd.Run()
	if err != nil {
		var migrationErr *ddl.MigrationError
		if errors.As(err, &migrationErr) {
			return fmt.Errorf("%s\n%w", migrationErr.Contents, migrationErr.Err)
		}
		return err
	}
	return nil
}

type SITE struct {
	sq.TableStruct
	SITE_ID       sq.UUIDField   `ddl:"primarykey"`
	SITE_NAME     sq.StringField `ddl:"notnull len=500 unique"` // only lowercase letters, digits and hyphen
	STORAGE_LIMIT sq.NumberField
	STORAGE_USED  sq.NumberField
}

type USERS struct {
	sq.TableStruct
	USER_ID          sq.UUIDField   `ddl:"primarykey"`
	USERNAME         sq.StringField `ddl:"notnull len=500 unique references={site.site_name onupdate=cascade}"`
	EMAIL            sq.StringField `ddl:"notnull len=500 unique"`
	PASSWORD_HASH    sq.StringField `ddl:"len=500"`
	RESET_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) unique"`
	FAILED_LOGINS    sq.NumberField
}

type IP_LOGIN struct {
	sq.TableStruct
	IP            sq.StringField `ddl:"primarykey len=500"`
	FAILED_LOGINS sq.NumberField
}

type SITE_USER struct {
	sq.TableStruct `ddl:"primarykey=site_id,user_id"`
	SITE_ID        sq.UUIDField `ddl:"references={site onupdate=cascade}"`
	USER_ID        sq.UUIDField `ddl:"references={users onupdate=cascade index}"`
}

type SESSION struct {
	sq.TableStruct
	SESSION_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) primarykey"`
	DATA               sq.JSONField
}

type SIGNUP struct {
	sq.TableStruct
	SIGNUP_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) primarykey"`
}

type AUTHENTICATION struct {
	sq.TableStruct
	AUTHENTICATION_TOKEN_HASH sq.BinaryField `ddl:"mysql:type=BINARY(40) primarykey"`
	USER_ID                   sq.UUIDField   `ddl:"notnull references={users onupdate=cascade index}"`
}

type FILES struct {
	sq.TableStruct
	FILE_ID   sq.UUIDField    `ddl:"primarykey"`
	PARENT_ID sq.UUIDField    `ddl:"references={files.file_id onupdate=cascade index}"`
	FILE_PATH sq.StringField  `ddl:"notnull len=500 unique"`
	IS_DIR    sq.BooleanField `ddl:"notnull"`
	DATA      sq.StringField  `ddl:"mysql:type=MEDIUMTEXT"`
	SIZE      sq.NumberField
	MOD_TIME  sq.TimeField `ddl:"index"`
	PERM      sq.NumberField
}
