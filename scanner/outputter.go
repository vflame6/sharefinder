package scanner

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var mu sync.Mutex

type OutputWriter struct {
	HTML bool
}

// NewOutputWriter creates a new OutputWriter
func NewOutputWriter(html bool) *OutputWriter {
	return &OutputWriter{HTML: html}
}

func (o *OutputWriter) CreateFile(filename string, appendToFile bool) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	dir := filepath.Dir(filename)

	if dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, err
			}
		}
	}

	var file *os.File
	var err error
	if appendToFile {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(filename)
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

func (o *OutputWriter) Write(content string, writer io.Writer) error {
	mu.Lock()
	defer mu.Unlock()

	bufwriter := bufio.NewWriter(writer)

	_, err := bufwriter.WriteString(content)
	if err != nil {
		return err
	}
	return bufwriter.Flush()
}
