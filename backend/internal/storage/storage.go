package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ObjectStorage interface {
	Put(context.Context, string, io.Reader) error
	Open(context.Context, string) (io.ReadCloser, error)
	Delete(context.Context, string) error
	Exists(context.Context, string) (bool, error)
}

var safeKey = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9/_\-.]{0,511}$`)

type Local struct{ root string }

func NewLocal(root string) (*Local, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	return &Local{root: absolute}, nil
}
func (l *Local) path(key string) (string, error) {
	if !safeKey.MatchString(key) || filepath.IsAbs(key) || hasParentSegment(key) {
		return "", errors.New("invalid storage key")
	}
	p := filepath.Clean(filepath.Join(l.root, filepath.FromSlash(key)))
	rel, err := filepath.Rel(l.root, p)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator) {
		return "", errors.New("storage key escapes root")
	}
	return p, nil
}

func hasParentSegment(key string) bool {
	for _, segment := range strings.Split(key, "/") {
		if segment == ".." || segment == "." {
			return true
		}
	}
	return false
}
func (l *Local) Put(ctx context.Context, key string, source io.Reader) error {
	p, err := l.path(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(source, 10<<30))
	return err
}
func (l *Local) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	return os.Open(p)
}
func (l *Local) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := l.path(key)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
func (l *Local) Exists(ctx context.Context, key string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	p, err := l.path(key)
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}
