package runner

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/sensepost/gowitness/internal/islazy"
	"github.com/sensepost/gowitness/pkg/dedup"
	"github.com/sensepost/gowitness/pkg/models"
	"github.com/sensepost/gowitness/pkg/writers"
)

// Runner is a runner that probes web targets using a driver
type Runner struct {
	Driver     Driver
	Wappalyzer *wappalyzer.Wappalyze

	// options for the Runner to consider
	options Options
	// writers are the result writers to use
	writers []writers.Writer
	// log handler
	log *slog.Logger

	// Targets to scan.
	// This would typically be fed from a gowitness/pkg/reader.
	Targets chan string

	// targetIndex is the optional canonical target admission table. It is
	// nil when Scan.DedupTargets is false.
	targetIndex *dedup.TargetIndex

	// in case we need to bail
	ctx    context.Context
	cancel context.CancelFunc
}

// targetJob pairs the original, unmodified input with its admission ticket.
type targetJob struct {
	raw    string
	ticket *dedup.Ticket
}

// New gets a new Runner ready for probing.
// It's up to the caller to call Close() on the runner
func NewRunner(logger *slog.Logger, driver Driver, opts Options, writers []writers.Writer) (*Runner, error) {
	// A nil logger is tolerated; fall back to the slog default so all log
	// paths stay safe.
	if logger == nil {
		logger = slog.Default()
	}

	if !opts.Scan.ScreenshotSkipSave {
		screenshotPath, err := islazy.CreateDir(opts.Scan.ScreenshotPath)
		if err != nil {
			return nil, err
		}
		opts.Scan.ScreenshotPath = screenshotPath
		logger.Debug("final screenshot path", "screenshot-path", opts.Scan.ScreenshotPath)
	} else {
		logger.Debug("not saving screenshots to disk")
	}

	// screenshot format check
	if !islazy.SliceHasStr([]string{"jpeg", "png"}, opts.Scan.ScreenshotFormat) {
		return nil, errors.New("invalid screenshot format")
	}

	// javascript file containing javascript to eval on each page.
	// just read it in and set Scan.JavaScript to the value.
	if opts.Scan.JavaScriptFile != "" {
		javascript, err := os.ReadFile(opts.Scan.JavaScriptFile)
		if err != nil {
			return nil, err
		}

		opts.Scan.JavaScript = string(javascript)
	}

	// get a wappalyzer instance
	wap, err := wappalyzer.New()
	if err != nil {
		return nil, err
	}

	var targetIndex *dedup.TargetIndex
	if opts.Scan.DedupTargets {
		maxEntries := opts.Scan.DedupMaxTargets
		if maxEntries <= 0 {
			maxEntries = 200000
		}

		idx, err := dedup.NewTargetIndex(dedup.TargetOptions{
			MaxEntries: maxEntries,
			TTL:        opts.Scan.DedupWindow,
		})
		if err != nil {
			return nil, err
		}
		targetIndex = idx
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Runner{
		Driver:      driver,
		Wappalyzer:  wap,
		options:     opts,
		writers:     writers,
		Targets:     make(chan string),
		targetIndex: targetIndex,
		log:         logger,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// TargetStats returns a snapshot of the target admission index. When target
// deduplication is disabled the zero value is returned.
func (run *Runner) TargetStats() dedup.TargetStats {
	if run.targetIndex == nil {
		return dedup.TargetStats{}
	}

	return run.targetIndex.Stats()
}

// runWriters takes a result and passes it to writers
func (run *Runner) runWriters(result *models.Result) error {
	for _, writer := range run.writers {
		if err := writer.Write(result); err != nil {
			return err
		}
	}

	return nil
}

// checkUrl ensures a url is valid
func (run *Runner) checkUrl(target string) error {
	url, err := url.ParseRequestURI(target)
	if err != nil {
		return err
	}

	if !islazy.SliceHasStr(run.options.Scan.UriFilter, url.Scheme) {
		return errors.New("url contains invalid scheme")
	}

	return nil
}

// Run executes the runner, processing targets as they arrive
// in the Targets channel
func (run *Runner) Run() {
	threads := run.options.Scan.Threads
	if threads < 1 {
		threads = 1
	}

	// Internal work channel. Its capacity matches the worker count. It is
	// closed by the dispatcher once it exits (for example after Targets is
	// closed or the run context is cancelled).
	jobs := make(chan targetJob, threads)

	var dispatcherWG sync.WaitGroup
	dispatcherWG.Add(1)
	go func() {
		defer dispatcherWG.Done()
		run.dispatch(jobs)
	}()

	var workersWG sync.WaitGroup
	for w := 0; w < threads; w++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			run.worker(jobs)
		}()
	}

	// The dispatcher owns closing the jobs channel.
	dispatcherWG.Wait()
	workersWG.Wait()

	// Jobs buffered in the work channel were never claimed by a worker
	// (typically after cancellation). Release their tickets so no inflight
	// entries are left behind. At this point both the dispatcher and all
	// workers have exited and jobs is closed.
	for job := range jobs {
		if run.targetIndex != nil && job.ticket != nil {
			run.targetIndex.Release(job.ticket)
		}
	}

	stats := run.TargetStats()
	run.log.Info("target admission summary",
		"admitted", stats.Admitted,
		"suppressed", stats.Suppressed,
		"released", stats.Released,
		"expired", stats.Expired,
		"evicted", stats.Evicted,
		"inflight", stats.InFlight,
		"done", stats.Done,
	)
}

// dispatch is the single goroutine that reads raw inputs, validates and
// admits them, and hands work to the worker pool. Admission order is thus
// total and deterministic.
func (run *Runner) dispatch(jobs chan<- targetJob) {
	defer close(jobs)

	for {
		select {
		case <-run.ctx.Done():
			// Cancellation (e.g. ChromeNotFoundError) stops admission. We do
			// not block here: Targets is owned and closed by its producer.
			return
		case raw, ok := <-run.Targets:
			if !ok {
				return
			}

			if err := run.checkUrl(raw); err != nil {
				if run.options.Logging.LogScanErrors {
					run.log.Error("invalid target to scan", "target", raw, "err", err)
				}
				continue
			}

			job := targetJob{raw: raw}

			if run.targetIndex != nil {
				key, err := dedup.CanonicalTarget(raw)
				if err != nil {
					if run.options.Logging.LogScanErrors {
						run.log.Error("invalid target to scan", "target", raw, "err", err)
					}
					continue
				}

				ticket, admitted := run.targetIndex.Admit(key)
				if !admitted {
					run.log.Debug("suppressed duplicate target",
						"target", raw, "canonical", key.String())
					continue
				}
				job.ticket = ticket
			}

			// Hand off without ever blocking past cancellation.
			select {
			case jobs <- job:
			case <-run.ctx.Done():
				// The ticket never reached a worker; release it.
				if job.ticket != nil {
					run.targetIndex.Release(job.ticket)
				}
				return
			}
		}
	}
}

// worker processes jobs until the jobs channel closes or the run context is
// cancelled.
func (run *Runner) worker(jobs <-chan targetJob) {
	for {
		select {
		case <-run.ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}

			// A cancellation may have raced the dequeue; do not start new
			// work afterwards. The Run cleanup drains remaining jobs.
			if run.ctx.Err() != nil {
				if run.targetIndex != nil && job.ticket != nil {
					run.targetIndex.Release(job.ticket)
				}
				return
			}

			run.process(job)
		}
	}
}

// process witnesses a single job and resolves its admission ticket exactly
// once: Commit on full success, Release on every other outcome. Release after
// Commit is a token/state no-op, so the deferred call is always safe.
func (run *Runner) process(job targetJob) {
	target := job.raw

	if run.targetIndex != nil && job.ticket != nil {
		defer run.targetIndex.Release(job.ticket)
	}

	result, err := run.Driver.Witness(target, run)
	if err != nil {
		// is this a chrome not found error? Accept both the pointer form
		// returned by the real drivers and the value form.
		var chromeErr *ChromeNotFoundError
		var chromeErrValue ChromeNotFoundError
		if errors.As(err, &chromeErr) || errors.As(err, &chromeErrValue) {
			run.log.Error("no valid chrome installation found", "err", err)
			run.cancel()
			return
		}

		if run.options.Logging.LogScanErrors {
			run.log.Error("failed to witness target", "target", target, "err", err)
		}
		return
	}

	// assume that status code 0 means there was no information, so
	// don't send anything to writers.
	if result.ResponseCode == 0 {
		if run.options.Logging.LogScanErrors {
			run.log.Error("failed to witness target, status code was 0", "target", target)
		}
		return
	}

	if err := run.runWriters(result); err != nil {
		run.log.Error("failed to write result for target", "target", target, "err", err)
		return
	}

	if run.targetIndex != nil && job.ticket != nil {
		run.targetIndex.Commit(job.ticket)
	}

	run.log.Info("result 🤖", "target", target, "status-code", result.ResponseCode,
		"title", result.Title, "have-screenshot", !result.Failed)
}

func (run *Runner) Close() {
	// close the driver
	run.Driver.Close()
}
