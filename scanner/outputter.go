package scanner

import (
	"bufio"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// HTMLTemplate is just a string copy of template.html to include the template in the tool
//
//go:embed template.html
var HTMLTemplate string

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

func (o *OutputWriter) ReadFile(filename string) ([]byte, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}
	file := filepath.Join(filepath.Dir(filename), filename)
	return ioutil.ReadFile(file)
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

func (o *OutputWriter) WriteXMLHeader(version string, commandLine []string, startTime time.Time, writer io.Writer) error {
	cmd := escapeXML(strings.Join(commandLine, " "))

	content := xml.Header
	content += fmt.Sprintf("<SharefinderRun version=\"%s\" command=\"%s\" time_start=\"%s\" formatted_time_start=\"%s\">\n", version, cmd, startTime.Format("2006-01-02T15:04:05Z07:00"), startTime.Format(dateTimeFormat))
	content += "<hosts>\n"

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
	content := "</hosts>\n"
	content += fmt.Sprintf("<time_end time=\"%s\" formatted_time=\"%s\"></time_end>", timeEnd.Format("2006-01-02T15:04:05Z07:00"), timeEnd.Format(dateTimeFormat)) + "\n"
	content += "</SharefinderRun>"

	bufWriter := bufio.NewWriter(writer)
	_, err := bufWriter.WriteString(content)
	if err != nil {
		return err
	}
	return bufWriter.Flush()
}

func (o *OutputWriter) WriteHTML(result SharefinderRun, writer io.Writer) error {
	t := template.New("HTML")
	tmpl, err := t.Parse(HTMLTemplate)
	if err != nil {
		return err
	}
	err = tmpl.Execute(writer, result)
	if err != nil {
		return err
	}

	return nil
}
