package scanner

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var mu sync.Mutex

type OutputWriter struct {
}

// NewOutputWriter creates a new OutputWriter
func NewOutputWriter() *OutputWriter {
	return &OutputWriter{}
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

	bufWriter := bufio.NewWriter(writer)

	_, err := bufWriter.WriteString(content)
	if err != nil {
		return err
	}
	return bufWriter.Flush()
}

func (o *OutputWriter) WriteXMLHeader(commandLine []string, startTime time.Time, writer io.Writer) error {
	cmd := escapeXML(strings.Join(commandLine, " "))

	content := xml.Header
	content += fmt.Sprintf("<SharefinderRun command=\"%s\" timestart=\"%s\">\n", cmd, startTime)
	content += "<Hosts>\n"

	bufWriter := bufio.NewWriter(writer)
	_, err := bufWriter.WriteString(content)
	if err != nil {
		return err
	}
	return bufWriter.Flush()
}

func (o *OutputWriter) WriteXMLHost(host Host, writer io.Writer) error {
	mu.Lock()
	defer mu.Unlock()

	content, err := xml.Marshal(host)
	if err != nil {
		return err
	}

	bufWriter := bufio.NewWriter(writer)

	_, err = bufWriter.WriteString(string(content) + "\n")
	if err != nil {
		return err
	}
	return bufWriter.Flush()
}

func (o *OutputWriter) WriteXMLFooter(timeEnd time.Time, writer io.Writer) error {
	t := &Timestamp{Time: timeEnd}
	marshalledT, err := xml.Marshal(t)
	if err != nil {
		return err
	}
	content := "</Hosts>\n" + string(marshalledT) + "\n" + "</SharefinderRun>"

	bufWriter := bufio.NewWriter(writer)
	_, err = bufWriter.WriteString(content)
	if err != nil {
		return err
	}
	return bufWriter.Flush()
}

//func (o *OutputWriter) OutputHTML(result []SharefinderRun, writer io.Writer) error {
//
//}
