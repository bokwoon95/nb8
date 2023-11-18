package nb8

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	ctx                context.Context
	group              errgroup.Group
	fsys               fs.FS
	sitePrefix         string
	mu                 sync.Mutex
	templates          map[string]*template.Template
	templateErrors     map[string][]string
	templateInProgress map[string]chan struct{}
}

// parent=pages&name=index.html&name=abcd.html&cat.html

// {{ template "/themes/word-up.html" }}
// {{ template "/themes/github.com/bokwoon95/plainsimple/very/long/path/to/file.html" }}

func (siteGenerator *SiteGenerator) Generate(parent string, names []string) {
}

var funcMap = map[string]any{
	"join":             path.Join,
	"base":             path.Base,
	"ext":              path.Ext,
	"trimPrefix":       strings.TrimPrefix,
	"trimSuffix":       strings.TrimSuffix,
	"fileSizeToString": fileSizeToString,
	"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
	"head": func(s string) string {
		head, _, _ := strings.Cut(s, "/")
		return head
	},
	"tail": func(s string) string {
		_, tail, _ := strings.Cut(s, "/")
		return tail
	},
	"list": func(v ...any) []any { return v },
	"dict": func(v ...any) (map[string]any, error) {
		dict := make(map[string]any)
		if len(dict)%2 != 0 {
			return nil, fmt.Errorf("odd number of arguments passed in")
		}
		for i := 0; i+1 < len(dict); i += 2 {
			key, ok := v[i].(string)
			if !ok {
				return nil, fmt.Errorf("value %d (%#v) is not a string", i, v[i])
			}
			value := v[i+1]
			dict[key] = value
		}
		return dict, nil
	},
	"dump": func(a ...any) template.HTML {
		// TODO: convert each argument into json and print each
		// argument out in a <pre style="white-space: pre-wrap"></pre>
		// tag.
		return ""
	},
}
