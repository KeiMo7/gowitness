package runner

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	charmlog "github.com/charmbracelet/log"
	"github.com/sensepost/gowitness/pkg/models"
	"github.com/sensepost/gowitness/pkg/writers"
)

type runnerTestDriver struct{}

func (runnerTestDriver) Witness(string, *Runner) (*models.Result, error) {
	return nil, errors.New("not implemented")
}

func (runnerTestDriver) Close() {}

type runnerTestCloser struct {
	closed bool
	err    error
}

func (w *runnerTestCloser) Write(*models.Result) error {
	return nil
}

func (w *runnerTestCloser) CloseRun(err error) error {
	w.closed = true
	w.err = err
	return nil
}

func TestRunnerCloseFinalizesRunClosers(t *testing.T) {
	writer := &runnerTestCloser{}
	runner := &Runner{
		Driver:  runnerTestDriver{},
		writers: []writers.Writer{writer},
	}
	runErr := errors.New("scan failed")
	runner.setRunError(runErr)
	runner.Close()

	if !writer.closed {
		t.Fatal("expected RunCloser to be finalized")
	}
	if !errors.Is(writer.err, runErr) {
		t.Fatalf("CloseRun error = %v, want %v", writer.err, runErr)
	}
}

func TestRunnerLogsSanitizedSARIFErrors(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "missing", "gowitness.sarif")
	sarifWriter, err := writers.NewSarifWriter(destination)
	if err != nil {
		t.Fatal(err)
	}
	sarifWriter.RepositoryRoot = root
	if err := os.RemoveAll(filepath.Dir(destination)); err != nil {
		t.Fatal(err)
	}

	writeErr := sarifWriter.Write(&models.Result{
		URL:          "https://user:pass@example.test/",
		ResponseCode: 200,
	})
	if writeErr == nil {
		t.Fatal("expected a SARIF writer error")
	}

	var logs bytes.Buffer
	runner := &Runner{
		Driver:  runnerTestDriver{},
		writers: []writers.Writer{sarifWriter},
		log:     slog.New(charmlog.New(&logs)),
	}
	runner.Close()

	output := logs.String()
	if output == "" {
		t.Fatal("expected the runner to log the writer failure")
	}
	if strings.Contains(output, root) ||
		strings.Contains(output, "/home/") ||
		strings.Contains(output, "/tmp/") ||
		strings.Contains(output, "user:pass") {
		t.Fatalf("runner log leaked a path or credential: %s", output)
	}
}
