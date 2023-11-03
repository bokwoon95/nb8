//go:build !cgo

package main

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"modernc.org/sqlite"
)

var sqliteDriverName = "sqlite"

func sqliteErrorCode(err error) string {
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		return strconv.Itoa(int(sqliteErr.Code()))
	}
	return ""
}

func sqliteQueryString(params map[string]string) string {
	values := make(url.Values)
	for key, value := range params {
		switch key {
		case "auto_vacuum", "busy_timeout", "defer_foreign_keys",
			"foreign_keys", "ignore_check_constraints", "journal_mode",
			"locking_mode", "query_only", "recursive_triggers", "secure_delete",
			"synchronous", "cache_size":
			values.Add("_pragma", fmt.Sprintf("%s(%s)", key, value))
		}
	}
	if _, ok := params["busy_timeout"]; !ok {
		values.Add("_pragma", "busy_timeout(10000)")
	}
	if _, ok := params["foreign_keys"]; !ok {
		values.Add("_pragma", "foreign_keys(ON)")
	}
	if _, ok := params["journal_mode"]; !ok {
		values.Add("_pragma", "journal_mode(WAL)")
	}
	if _, ok := params["synchronous"]; !ok {
		values.Add("_pragma", "synchronous(NORMAL)")
	}
	values.Set("_txlock", "immediate")
	return strings.NewReplacer("%28", "(", "%29", ")").Replace(values.Encode())
}
