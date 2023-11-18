package nb8

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"net/url"
	"path"
	"strings"
	"sync"
)

type TemplatParser struct {
	ctx        context.Context
	fsys       fs.FS
	sitePrefix string
	siteURL    string
	mu         *sync.Mutex
	cache      map[string]*template.Template
	errmsgs    map[string][]string
	inProgress map[string]chan struct{}
	funcMap    map[string]any
}

func NewTemplatParser(ctx context.Context, fsys fs.FS, sitePrefix string) (*TemplatParser, error) {
	parser := &TemplatParser{
		ctx:        ctx,
		fsys:       fsys,
		sitePrefix: sitePrefix,
		mu:         &sync.Mutex{},
		cache:      make(map[string]*template.Template),
		errmsgs:    make(url.Values),
		inProgress: make(map[string]chan struct{}),
		funcMap: map[string]any{
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
		},
	}
	return parser, nil
}
