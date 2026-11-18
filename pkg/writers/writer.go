package writers

import "github.com/sensepost/gowitness/pkg/models"

// Writer is a results writer
type Writer interface {
	Write(*models.Result) error
}

// RunCloser is implemented by writers that need to finalize state at the end
// of a scan. The scan error is passed so writers can record failed invocations.
type RunCloser interface {
	CloseRun(error) error
}
