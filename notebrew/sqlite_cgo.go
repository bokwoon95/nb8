//go:build cgo

package main

import (
	"errors"
	"net/url"
	"strconv"

	"github.com/mattn/go-sqlite3"
)

var sqliteDriverName = "sqlite3"

func sqliteErrorCode(err error) string {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return strconv.Itoa(int(sqliteErr.ExtendedCode))
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
			values.Set("_"+key, value)
		}
	}
	if _, ok := params["busy_timeout"]; !ok {
		values.Set("_busy_timeout", "10000")
	}
	if _, ok := params["foreign_keys"]; !ok {
		values.Set("_foreign_keys", "ON")
	}
	if _, ok := params["journal_mode"]; !ok {
		values.Set("_journal_mode", "WAL")
	}
	if _, ok := params["synchronous"]; !ok {
		values.Set("_synchronous", "NORMAL")
	}
	values.Set("_txlock", "immediate")
	return values.Encode()
}
