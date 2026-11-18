package writers

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sensepost/gowitness/internal/version"
	"github.com/sensepost/gowitness/pkg/models"
)

const (
	sarifVersion          = "2.1.0"
	sarifSchemaURI        = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifColumnKind       = "unicodeCodePoints"
	sarifWriteBufferSize  = 64 * 1024
	sarifMaxURIPathLength = 2048
)

const (
	sarifSeverityHigh   = "high"
	sarifSeverityMedium = "medium"
	sarifSeverityHint   = "hint"
	sarifSeverityInfo   = "info"

	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
	sarifLevelNote    = "note"
)

// SARIFSeverityLevels is the single severity-to-SARIF-level mapping used by
// both rule definitions and emitted results.
var SARIFSeverityLevels = map[string]string{
	sarifSeverityHigh:   sarifLevelError,
	sarifSeverityMedium: sarifLevelWarning,
	sarifSeverityHint:   sarifLevelNote,
	sarifSeverityInfo:   sarifLevelNote,
}

const (
	sarifRuleCaptureFailed  = "gowitness.capture.failed"
	sarifRuleHTTPServerErr  = "gowitness.http.server-error"
	sarifRuleHTTPClientErr  = "gowitness.http.client-error"
	sarifRuleTechnology     = "gowitness.technology.detected"
	sarifRuleInsecureCookie = "gowitness.cookie.insecure"
	sarifRuleConsoleError   = "gowitness.console.error"
	sarifRuleAssetObserved  = "gowitness.asset.observed"
)

// SARIFRule describes a stable gowitness finding rule. Rule IDs must never
// contain scan input, file paths, timestamps, or random values.
type SARIFRule struct {
	ID          string
	Name        string
	Description string
	Severity    string
}

// SARIFRules is the static rule registry emitted in every SARIF document.
var SARIFRules = []SARIFRule{
	{
		ID:          sarifRuleCaptureFailed,
		Name:        "capture-failed",
		Description: "A screenshot could not be captured for a probed asset.",
		Severity:    sarifSeverityHigh,
	},
	{
		ID:          sarifRuleHTTPServerErr,
		Name:        "http-server-error",
		Description: "A probed asset returned an HTTP 5xx response.",
		Severity:    sarifSeverityHigh,
	},
	{
		ID:          sarifRuleHTTPClientErr,
		Name:        "http-client-error",
		Description: "A probed asset returned an HTTP 4xx response.",
		Severity:    sarifSeverityMedium,
	},
	{
		ID:          sarifRuleTechnology,
		Name:        "technology-detected",
		Description: "A technology fingerprint was detected on a probed asset.",
		Severity:    sarifSeverityHint,
	},
	{
		ID:          sarifRuleInsecureCookie,
		Name:        "insecure-cookie",
		Description: "A cookie was observed without the Secure or HttpOnly attribute.",
		Severity:    sarifSeverityMedium,
	},
	{
		ID:          sarifRuleConsoleError,
		Name:        "console-error",
		Description: "An error was logged to the browser console by a probed asset.",
		Severity:    sarifSeverityHint,
	},
	{
		ID:          sarifRuleAssetObserved,
		Name:        "asset-observed",
		Description: "A web asset was observed during the scan.",
		Severity:    sarifSeverityHint,
	},
}

var sarifURLCredentialPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@`)
var sarifCredentialValuePattern = regexp.MustCompile(`(?i)\b(token|api[_-]?key|secret|password|passwd|pass|auth|session|credential)\b\s*[:=]\s*[^\s&,;]+`)
var sarifURLTokenPattern = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s"'<>]+`)
var sarifUnixPathPattern = regexp.MustCompile(`(^|[\s"'=:(])(/[^\s"'<>)]*)`)
var sarifWindowsPathPattern = regexp.MustCompile(`(?i)(^|[\s"'=:(])([a-z]:[\\/][^\s"'<>)]*)`)

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifReportingConfiguration struct {
	Level string `json:"level"`
}

type sarifReportingDescriptor struct {
	ID                   string                      `json:"id"`
	Name                 string                      `json:"name,omitempty"`
	ShortDescription     sarifMessage                `json:"shortDescription"`
	FullDescription      *sarifMessage               `json:"fullDescription,omitempty"`
	DefaultConfiguration sarifReportingConfiguration `json:"defaultConfiguration"`
	HelpURI              string                      `json:"helpUri,omitempty"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	FullName       string                     `json:"fullName,omitempty"`
	Version        string                     `json:"version,omitempty"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifResultProperties struct {
	URL          string `json:"url,omitempty"`
	FinalURL     string `json:"final_url,omitempty"`
	ProbedAt     string `json:"probed_at,omitempty"`
	ResponseCode int    `json:"response_code,omitempty"`
	Screenshot   string `json:"screenshot,omitempty"`
	Severity     string `json:"severity,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties *sarifResultProperties `json:"properties,omitempty"`
}

type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
}

type sarifInvocation struct {
	ExecutionSuccessful        *bool               `json:"executionSuccessful"`
	StartTimeUTC               string              `json:"startTimeUtc,omitempty"`
	EndTimeUTC                 string              `json:"endTimeUtc,omitempty"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifFinding struct {
	Rule     SARIFRule
	Message  string
	Evidence string
}

// SarifWriter streams SARIF 2.1.0 results into a temporary file and publishes
// the completed document atomically when CloseRun succeeds.
type SarifWriter struct {
	FilePath       string
	RepositoryRoot string
	ScreenshotPath string

	finalPath string
	tempPath  string
	file      *os.File
	buffer    *bufio.Writer

	mutex       sync.Mutex
	startTime   time.Time
	now         func() time.Time
	resultCount int
	writeErr    error
	closed      bool
}

// NewSarifWriter creates a SARIF writer. No final output file is created
// until CloseRun performs the atomic publish.
func NewSarifWriter(destination string) (*SarifWriter, error) {
	if strings.TrimSpace(destination) == "" {
		return nil, errors.New("SARIF output filename is empty")
	}

	cleanDestination := filepath.Clean(destination)
	parent := filepath.Dir(cleanDestination)
	if parent != "." {
		if err := os.MkdirAll(parent, 0755); err != nil {
			return nil, fmt.Errorf("could not create SARIF output directory: %s", sanitizeSARIFError(err, ""))
		}
	}

	finalPath, err := filepath.Abs(cleanDestination)
	if err != nil {
		return nil, fmt.Errorf("could not resolve SARIF output path: %s", sanitizeSARIFError(err, ""))
	}

	root, err := sarifRepositoryRoot()
	if err != nil {
		return nil, err
	}

	return &SarifWriter{
		FilePath:       finalPath,
		RepositoryRoot: root,
		ScreenshotPath: filepath.Join(root, "screenshots"),
		finalPath:      finalPath,
		startTime:      time.Now().UTC(),
		now:            time.Now,
	}, nil
}

// Write appends every finding produced by result without retaining previous
// results in memory.
func (sw *SarifWriter) Write(result *models.Result) error {
	if result == nil {
		return errors.New("could not write nil result to SARIF")
	}

	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	if sw.closed {
		return errors.New("could not write to closed SARIF writer")
	}
	if sw.writeErr != nil {
		return sw.writeErr
	}

	if err := sw.ensureTempFile(); err != nil {
		sw.writeErr = err
		sw.abortTempFile()
		return err
	}

	artifactURI := sw.screenshotURI(result)
	findings := sarifFindingsFor(result, artifactURI)
	evidenceCounts := map[string]int{}

	for _, finding := range findings {
		occurrence := evidenceCounts[finding.Evidence]
		evidenceCounts[finding.Evidence] = occurrence + 1

		location := sarifLocation{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: artifactURI},
				Region:           locateSARIFRegion(result.HTML, finding.Evidence, occurrence),
			},
		}

		item := sarifResult{
			RuleID:     finding.Rule.ID,
			RuleIndex:  sarifRuleIndex(finding.Rule.ID),
			Level:      SARIFSeverityLevels[finding.Rule.Severity],
			Message:    sarifMessage{Text: sanitizeSARIFText(finding.Message, sw.RepositoryRoot)},
			Locations:  []sarifLocation{location},
			Properties: sarifResultPropertiesFor(result, artifactURI, finding.Rule.Severity, sw.RepositoryRoot),
		}

		path := fmt.Sprintf("runs[0].results[%d]", sw.resultCount)
		if err := validateSARIFResult(item, path); err != nil {
			sw.writeErr = err
			sw.abortTempFile()
			return err
		}

		encoded, err := json.Marshal(item)
		if err != nil {
			sw.writeErr = fmt.Errorf("%s: could not encode result: %w", path, err)
			sw.abortTempFile()
			return sw.writeErr
		}

		if sw.resultCount > 0 {
			if _, err := sw.buffer.WriteString(","); err != nil {
				sw.writeErr = fmt.Errorf("%s: could not write result separator: %s", path, sanitizeSARIFError(err, sw.RepositoryRoot))
				sw.abortTempFile()
				return sw.writeErr
			}
		}
		if _, err := sw.buffer.Write(encoded); err != nil {
			sw.writeErr = fmt.Errorf("%s: could not write result: %s", path, sanitizeSARIFError(err, sw.RepositoryRoot))
			sw.abortTempFile()
			return sw.writeErr
		}

		sw.resultCount++
	}

	return nil
}

// Close finalizes a successful run.
func (sw *SarifWriter) Close() error {
	return sw.CloseRun(nil)
}

// CloseRun finalizes the document, recording runErr as a failed invocation.
func (sw *SarifWriter) CloseRun(runErr error) error {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	if sw.closed {
		return sw.writeErr
	}
	sw.closed = true

	if sw.writeErr != nil {
		sw.abortTempFile()
		return sw.writeErr
	}

	if err := sw.ensureTempFile(); err != nil {
		sw.abortTempFile()
		return err
	}

	now := time.Now
	if sw.now != nil {
		now = sw.now
	}
	endTime := now().UTC()
	successful := runErr == nil
	invocation := sarifInvocation{
		ExecutionSuccessful: &successful,
		StartTimeUTC:        sw.startTime.Format(time.RFC3339Nano),
		EndTimeUTC:          endTime.Format(time.RFC3339Nano),
	}
	if runErr != nil {
		invocation.ToolExecutionNotifications = []sarifNotification{{
			Level:   sarifLevelError,
			Message: sarifMessage{Text: "gowitness scan failed: " + sanitizeSARIFError(runErr, sw.RepositoryRoot)},
		}}
	}

	invocationJSON, err := json.Marshal(invocation)
	if err != nil {
		sw.abortTempFile()
		return fmt.Errorf("runs[0].invocations[0]: could not encode invocation: %w", err)
	}

	tail := fmt.Sprintf(`],"invocations":[%s],"properties":{"resultCount":%d}}]}`,
		invocationJSON, sw.resultCount)
	if _, err := sw.buffer.WriteString(tail); err != nil {
		sw.abortTempFile()
		return fmt.Errorf("runs[0]: could not finish SARIF document: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}
	if err := sw.buffer.Flush(); err != nil {
		sw.abortTempFile()
		return fmt.Errorf("runs[0]: could not flush SARIF document: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}
	if err := sw.file.Sync(); err != nil {
		sw.abortTempFile()
		return fmt.Errorf("runs[0]: could not sync SARIF document: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}
	if err := sw.file.Close(); err != nil {
		sw.file = nil
		sw.abortTempFile()
		return fmt.Errorf("runs[0]: could not close SARIF document: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}
	sw.file = nil

	if err := validateSARIFDocument(sw.tempPath); err != nil {
		sw.abortTempFile()
		return err
	}

	if err := publishSARIFDocument(sw.tempPath, sw.finalPath); err != nil {
		sw.abortTempFile()
		return fmt.Errorf("could not publish SARIF output: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}
	sw.tempPath = ""

	return nil
}

func (sw *SarifWriter) ensureTempFile() error {
	if sw.tempPath != "" {
		return nil
	}

	parent := filepath.Dir(sw.finalPath)
	prefix := ".gowitness-sarif-"
	file, err := os.CreateTemp(parent, prefix)
	if err != nil {
		return fmt.Errorf("could not create temporary SARIF output: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}

	sw.file = file
	sw.tempPath = file.Name()
	sw.buffer = bufio.NewWriterSize(file, sarifWriteBufferSize)
	if err := file.Chmod(0644); err != nil {
		sw.abortTempFile()
		return fmt.Errorf("could not set SARIF output permissions: %s", sanitizeSARIFError(err, sw.RepositoryRoot))
	}

	if err := sw.writePreamble(); err != nil {
		sw.abortTempFile()
		return err
	}

	return nil
}

func (sw *SarifWriter) writePreamble() error {
	driverJSON, err := json.Marshal(sarifDriver{
		Name:           "gowitness",
		FullName:       "gowitness web screenshot and asset inventory",
		Version:        version.Version,
		InformationURI: "https://github.com/sensepost/gowitness",
		Rules:          sarifRuleDescriptors(),
	})
	if err != nil {
		return fmt.Errorf("runs[0].tool.driver: could not encode driver: %w", err)
	}

	schemaJSON, err := json.Marshal(sarifSchemaURI)
	if err != nil {
		return fmt.Errorf("$schema: could not encode schema URI: %w", err)
	}
	versionJSON, err := json.Marshal(sarifVersion)
	if err != nil {
		return fmt.Errorf("version: could not encode SARIF version: %w", err)
	}

	preamble := fmt.Sprintf(`{"$schema":%s,"version":%s,"runs":[{"tool":{"driver":%s},"columnKind":%q,"results":[`,
		schemaJSON, versionJSON, driverJSON, sarifColumnKind)
	if _, err := sw.buffer.WriteString(preamble); err != nil {
		return fmt.Errorf("runs[0].results: could not write SARIF preamble: %w", err)
	}

	return nil
}

func (sw *SarifWriter) abortTempFile() {
	if sw.file != nil {
		_ = sw.file.Close()
		sw.file = nil
	}
	if sw.tempPath != "" {
		_ = os.Remove(sw.tempPath)
		sw.tempPath = ""
	}
	sw.buffer = nil
}

func (sw *SarifWriter) screenshotURI(result *models.Result) string {
	if result.Filename == "" {
		sum := sha256.Sum256([]byte(sanitizeSARIFURL(result.URL)))
		return "gowitness-artifacts/" + hex.EncodeToString(sum[:])[:16] + ".html"
	}

	screenshotPath := sw.ScreenshotPath
	if screenshotPath == "" {
		screenshotPath = "screenshots"
	}

	path := filepath.Join(screenshotPath, result.Filename)
	uri, err := sarifArtifactURI(path, sw.RepositoryRoot)
	if err != nil {
		sum := sha256.Sum256([]byte(filepath.Clean(path)))
		return "gowitness-external/" + hex.EncodeToString(sum[:]) + ".artifact"
	}

	return uri
}

func sarifRuleDescriptors() []sarifReportingDescriptor {
	rules := make([]sarifReportingDescriptor, len(SARIFRules))
	for i, rule := range SARIFRules {
		description := sarifMessage{Text: rule.Description}
		rules[i] = sarifReportingDescriptor{
			ID:   rule.ID,
			Name: rule.Name,
			ShortDescription: sarifMessage{
				Text: rule.Description,
			},
			FullDescription: &description,
			DefaultConfiguration: sarifReportingConfiguration{
				Level: SARIFSeverityLevels[rule.Severity],
			},
			HelpURI: "https://github.com/sensepost/gowitness",
		}
	}

	return rules
}

func sarifRuleIndex(ruleID string) int {
	for i, rule := range SARIFRules {
		if rule.ID == ruleID {
			return i
		}
	}

	return -1
}

func sarifRuleByID(ruleID string) (SARIFRule, bool) {
	for _, rule := range SARIFRules {
		if rule.ID == ruleID {
			return rule, true
		}
	}

	return SARIFRule{}, false
}

func sarifFindingsFor(result *models.Result, artifactURI string) []sarifFinding {
	displayURL := sanitizeSARIFURL(result.URL)
	if displayURL == "" {
		displayURL = sanitizeSARIFURL(result.FinalURL)
	}
	if displayURL == "" {
		displayURL = artifactURI
	}

	var findings []sarifFinding

	if result.Failed {
		reason := sanitizeSARIFText(result.FailedReason, "")
		if reason == "" {
			reason = "unknown error"
		}
		findings = append(findings, sarifFinding{
			Rule:    mustSARIFRule(sarifRuleCaptureFailed),
			Message: fmt.Sprintf("Screenshot capture failed for %s: %s", displayURL, reason),
		})
	}

	switch {
	case result.ResponseCode >= 500:
		findings = append(findings, sarifFinding{
			Rule:    mustSARIFRule(sarifRuleHTTPServerErr),
			Message: fmt.Sprintf("%s returned HTTP %d", displayURL, result.ResponseCode),
		})
	case result.ResponseCode >= 400:
		findings = append(findings, sarifFinding{
			Rule:    mustSARIFRule(sarifRuleHTTPClientErr),
			Message: fmt.Sprintf("%s returned HTTP %d", displayURL, result.ResponseCode),
		})
	}

	if result.ResponseCode > 0 {
		findings = append(findings, sarifFinding{
			Rule:    mustSARIFRule(sarifRuleAssetObserved),
			Message: fmt.Sprintf("Web asset observed at %s with HTTP %d", displayURL, result.ResponseCode),
		})
	}

	technologies := append([]models.Technology(nil), result.Technologies...)
	sort.SliceStable(technologies, func(i, j int) bool {
		return technologies[i].Value < technologies[j].Value
	})
	for _, technology := range technologies {
		value := sanitizeSARIFText(technology.Value, "")
		if value == "" {
			continue
		}
		findings = append(findings, sarifFinding{
			Rule:     mustSARIFRule(sarifRuleTechnology),
			Message:  fmt.Sprintf("Technology detected on %s: %s", displayURL, value),
			Evidence: technology.Value,
		})
	}

	cookies := append([]models.Cookie(nil), result.Cookies...)
	sort.SliceStable(cookies, func(i, j int) bool {
		if cookies[i].Name == cookies[j].Name {
			return cookies[i].Domain < cookies[j].Domain
		}
		return cookies[i].Name < cookies[j].Name
	})
	for _, cookie := range cookies {
		var missing []string
		if !cookie.Secure {
			missing = append(missing, "Secure")
		}
		if !cookie.HTTPOnly {
			missing = append(missing, "HttpOnly")
		}
		if len(missing) == 0 {
			continue
		}

		name := sanitizeSARIFText(cookie.Name, "")
		if name == "" {
			name = "unnamed"
		}
		domain := sanitizeSARIFText(cookie.Domain, "")
		message := fmt.Sprintf("Cookie %s", name)
		if domain != "" {
			message += " on " + domain
		}
		message += " is missing " + strings.Join(missing, " and ")

		findings = append(findings, sarifFinding{
			Rule:     mustSARIFRule(sarifRuleInsecureCookie),
			Message:  message,
			Evidence: cookie.Name,
		})
	}

	for _, console := range result.Console {
		if !strings.EqualFold(console.Type, "error") && !strings.EqualFold(console.Type, "assert") {
			continue
		}
		findings = append(findings, sarifFinding{
			Rule:     mustSARIFRule(sarifRuleConsoleError),
			Message:  fmt.Sprintf("Console error observed on %s", displayURL),
			Evidence: console.Value,
		})
	}

	return findings
}

func mustSARIFRule(ruleID string) SARIFRule {
	rule, ok := sarifRuleByID(ruleID)
	if !ok {
		panic("unknown SARIF rule: " + ruleID)
	}

	return rule
}

func sarifResultPropertiesFor(result *models.Result, artifactURI, severity, root string) *sarifResultProperties {
	properties := &sarifResultProperties{
		URL:          sanitizeSARIFURL(result.URL),
		FinalURL:     sanitizeSARIFURL(result.FinalURL),
		ResponseCode: result.ResponseCode,
		Screenshot:   artifactURI,
		Severity:     severity,
	}
	if !result.ProbedAt.IsZero() {
		properties.ProbedAt = result.ProbedAt.UTC().Format(time.RFC3339Nano)
	}

	properties.URL = sanitizeSARIFText(properties.URL, root)
	properties.FinalURL = sanitizeSARIFText(properties.FinalURL, root)
	properties.Screenshot = sanitizeSARIFText(properties.Screenshot, root)

	return properties
}

func locateSARIFRegion(text, needle string, occurrence int) sarifRegion {
	found, start, length := findSARIFEvidence(text, needle, occurrence)
	if !found {
		return sarifRegion{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 2}
	}

	before := text[:start]
	startLine := strings.Count(before, "\n") + 1
	lineStart := strings.LastIndex(before, "\n") + 1
	startColumn := utf8.RuneCountInString(text[lineStart:start]) + 1
	match := text[start : start+length]

	if newline := strings.LastIndex(match, "\n"); newline >= 0 {
		endLine := startLine + strings.Count(match, "\n")
		endColumn := utf8.RuneCountInString(match[newline+1:]) + 1
		return sarifRegion{
			StartLine:   startLine,
			StartColumn: startColumn,
			EndLine:     endLine,
			EndColumn:   endColumn,
		}
	}

	return sarifRegion{
		StartLine:   startLine,
		StartColumn: startColumn,
		EndLine:     startLine,
		EndColumn:   startColumn + utf8.RuneCountInString(match),
	}
}

func findSARIFEvidence(text, needle string, occurrence int) (bool, int, int) {
	if text == "" || needle == "" || len(needle) > 2048 {
		return false, 0, 0
	}

	searchFrom := 0
	for i := 0; i <= occurrence; i++ {
		index := strings.Index(text[searchFrom:], needle)
		if index < 0 {
			return false, 0, 0
		}
		searchFrom += index + len(needle)
	}

	start := searchFrom - len(needle)
	return true, start, len(needle)
}

func sanitizeSARIFURL(raw string) string {
	if raw == "" {
		return ""
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return sanitizeSARIFText(redactSARIFURLCredentials(raw), "")
	}

	parsed.User = nil
	parsed.Fragment = ""
	query := parsed.Query()
	for key := range query {
		if sarifSensitiveQueryKey(key) {
			query.Set(key, "REDACTED")
		}
	}
	parsed.RawQuery = query.Encode()

	return sanitizeSARIFText(parsed.String(), "")
}

func redactSARIFURLCredentials(raw string) string {
	parts := strings.SplitN(raw, "://", 2)
	if len(parts) != 2 {
		return raw
	}

	authority := parts[1]
	end := strings.IndexAny(authority, "/?#")
	if end < 0 {
		end = len(authority)
	}
	authorityPart := authority[:end]
	if at := strings.LastIndex(authorityPart, "@"); at >= 0 {
		authority = authority[at+1:]
	}

	return parts[0] + "://" + authority
}

func sarifSensitiveQueryKey(key string) bool {
	key = strings.ToLower(key)
	for _, fragment := range []string{"token", "key", "secret", "pass", "auth", "session", "credential"} {
		if strings.Contains(key, fragment) {
			return true
		}
	}

	return false
}

func sanitizeSARIFError(err error, root string) string {
	if err == nil {
		return ""
	}

	return sanitizeSARIFText(err.Error(), root)
}

func sanitizeSARIFText(text, root string) string {
	text = strings.ToValidUTF8(text, "\uFFFD")
	text = redactSARIFURLCredentialsInText(text)
	text = sarifCredentialValuePattern.ReplaceAllString(text, "$1=REDACTED")
	text = redactSARIFAbsolutePaths(text)

	if root != "" {
		root = filepath.Clean(root)
		text = strings.ReplaceAll(text, root, ".")
		text = strings.ReplaceAll(text, filepath.ToSlash(root), ".")
	}
	if tempDir := os.TempDir(); tempDir != "" {
		text = strings.ReplaceAll(text, filepath.Clean(tempDir), "<temp>")
		text = strings.ReplaceAll(text, filepath.ToSlash(tempDir), "<temp>")
	}
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		text = strings.ReplaceAll(text, filepath.Clean(homeDir), "<home>")
		text = strings.ReplaceAll(text, filepath.ToSlash(homeDir), "<home>")
	}

	text = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, text)

	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) > 4096 {
		runes := []rune(text)
		text = string(runes[:4096]) + "..."
	}

	return text
}

func redactSARIFURLCredentialsInText(text string) string {
	return sarifURLCredentialPattern.ReplaceAllString(text, "$1")
}

func redactSARIFAbsolutePaths(text string) string {
	var builder strings.Builder
	last := 0

	for _, match := range sarifURLTokenPattern.FindAllStringIndex(text, -1) {
		builder.WriteString(redactSARIFPathsOutsideURLs(text[last:match[0]]))
		builder.WriteString(text[match[0]:match[1]])
		last = match[1]
	}
	builder.WriteString(redactSARIFPathsOutsideURLs(text[last:]))

	return builder.String()
}

func redactSARIFPathsOutsideURLs(text string) string {
	text = sarifWindowsPathPattern.ReplaceAllString(text, "$1<path>")
	return sarifUnixPathPattern.ReplaceAllString(text, "$1<path>")
}

func sarifArtifactURI(rawPath, root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("could not resolve repository root: %w", err)
	}

	path, err := filepath.Abs(rawPath)
	if err != nil {
		return "", fmt.Errorf("could not resolve artifact path: %w", err)
	}

	if info, err := os.Lstat(path); err == nil {
		resolved := path
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err = filepath.EvalSymlinks(path)
			if err != nil {
				return sarifExternalURI(path), nil
			}
		}
		path = resolved
	}

	relative, err := filepath.Rel(root, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return sarifExternalURI(rawPath), nil
	}

	uri := encodeSARIFPathURI(filepath.ToSlash(relative))
	if len(uri) > sarifMaxURIPathLength {
		return sarifExternalURI(rawPath), nil
	}

	if err := validateSARIFArtifactURI(uri); err != nil {
		return sarifExternalURI(rawPath), nil
	}

	return uri, nil
}

func sarifExternalURI(value string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(value)))
	return "gowitness-external/" + hex.EncodeToString(sum[:]) + ".artifact"
}

func encodeSARIFPathURI(path string) string {
	var builder strings.Builder
	for i := 0; i < len(path); i++ {
		character := path[i]
		switch {
		case character >= 'a' && character <= 'z':
			builder.WriteByte(character)
		case character >= 'A' && character <= 'Z':
			builder.WriteByte(character)
		case character >= '0' && character <= '9':
			builder.WriteByte(character)
		case character == '-', character == '.', character == '_', character == '~', character == '/':
			builder.WriteByte(character)
		default:
			builder.WriteString(fmt.Sprintf("%%%02X", character))
		}
	}

	return builder.String()
}

func validateSARIFArtifactURI(uri string) error {
	if uri == "" {
		return errors.New("artifact URI is empty")
	}
	if strings.Contains(uri, "\\") {
		return errors.New("artifact URI contains a backslash")
	}
	if strings.HasPrefix(uri, "/") {
		return errors.New("artifact URI is absolute")
	}
	if len(uri) >= 2 && uri[1] == ':' {
		return errors.New("artifact URI contains a drive letter")
	}
	for _, segment := range strings.Split(uri, "/") {
		if segment == ".." {
			return errors.New("artifact URI escapes the repository root")
		}
	}
	for i := 0; i < len(uri); i++ {
		if uri[i] < 0x20 || uri[i] > 0x7E {
			return errors.New("artifact URI contains non-ASCII characters")
		}
	}

	return nil
}

func sarifRepositoryRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("could not determine repository root: %s", sanitizeSARIFError(err, ""))
	}

	root, err := filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("could not resolve repository root: %s", sanitizeSARIFError(err, ""))
	}

	for {
		if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
			return root, nil
		}

		parent := filepath.Dir(root)
		if parent == root {
			break
		}
		root = parent
	}

	cwd, err = filepath.Abs(cwd)
	if err != nil {
		return "", fmt.Errorf("could not resolve repository root: %s", sanitizeSARIFError(err, ""))
	}

	return cwd, nil
}

func validateSARIFResult(result sarifResult, path string) error {
	if result.RuleID == "" {
		return fmt.Errorf("%s.ruleId: must not be empty", path)
	}
	if result.RuleIndex < 0 || result.RuleIndex >= len(SARIFRules) {
		return fmt.Errorf("%s.ruleIndex: must reference a defined rule", path)
	}
	rule := SARIFRules[result.RuleIndex]
	if rule.ID != result.RuleID {
		return fmt.Errorf("%s.ruleId: does not match rules[%d].id", path, result.RuleIndex)
	}
	if expectedLevel, ok := SARIFSeverityLevels[rule.Severity]; !ok || result.Level != expectedLevel {
		return fmt.Errorf("%s.level: must match rules[%d].defaultConfiguration.level", path, result.RuleIndex)
	}
	if strings.TrimSpace(result.Message.Text) == "" {
		return fmt.Errorf("%s.message.text: must not be empty", path)
	}
	if len(result.Locations) == 0 {
		return fmt.Errorf("%s.locations: must contain at least one location", path)
	}

	for i, location := range result.Locations {
		locationPath := fmt.Sprintf("%s.locations[%d].physicalLocation", path, i)
		if err := validateSARIFArtifactURI(location.PhysicalLocation.ArtifactLocation.URI); err != nil {
			return fmt.Errorf("%s.artifactLocation.uri: %w", locationPath, err)
		}

		region := location.PhysicalLocation.Region
		if region.StartLine < 1 {
			return fmt.Errorf("%s.region.startLine: must be at least 1", locationPath)
		}
		if region.StartColumn < 1 {
			return fmt.Errorf("%s.region.startColumn: must be at least 1", locationPath)
		}
		if region.EndLine < region.StartLine {
			return fmt.Errorf("%s.region.endLine: must be greater than or equal to startLine", locationPath)
		}
		if region.EndColumn < region.StartColumn {
			return fmt.Errorf("%s.region.endColumn: must be greater than or equal to startColumn", locationPath)
		}
	}

	return nil
}

func validateSARIFDocument(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("runs[0]: could not open SARIF document for self-check: %s", sanitizeSARIFError(err, ""))
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	token, err := decoder.Token()
	if err != nil {
		return sarifDocumentError("$", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("$: SARIF document must be a JSON object")
	}

	seenSchema := false
	seenVersion := false
	seenRuns := false
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return sarifDocumentError("$", err)
		}
		key, _ := keyToken.(string)

		switch key {
		case "$schema":
			var schema string
			if err := decoder.Decode(&schema); err != nil {
				return sarifDocumentError("$.$schema", err)
			}
			if schema == "" {
				return errors.New("$.$schema: must not be empty")
			}
			seenSchema = true
		case "version":
			var value string
			if err := decoder.Decode(&value); err != nil {
				return sarifDocumentError("$.version", err)
			}
			if value != sarifVersion {
				return fmt.Errorf("$.version: must be %q", sarifVersion)
			}
			seenVersion = true
		case "runs":
			if err := validateSARIFRuns(decoder); err != nil {
				return err
			}
			seenRuns = true
		default:
			if err := skipSARIFJSONValue(decoder); err != nil {
				return sarifDocumentError("$."+key, err)
			}
		}
	}

	if _, err := decoder.Token(); err != nil {
		return sarifDocumentError("$", err)
	}
	if !seenSchema {
		return errors.New("$.$schema: is required")
	}
	if !seenVersion {
		return errors.New("$.version: is required")
	}
	if !seenRuns {
		return errors.New("$.runs: is required")
	}

	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("$: contains trailing JSON data")
		}
		return sarifDocumentError("$", err)
	}

	return nil
}

func validateSARIFRuns(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return sarifDocumentError("$.runs", err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return errors.New("$.runs: must be an array")
	}

	runIndex := 0
	for decoder.More() {
		if err := validateSARIFRun(decoder, fmt.Sprintf("$.runs[%d]", runIndex)); err != nil {
			return err
		}
		runIndex++
	}
	if _, err := decoder.Token(); err != nil {
		return sarifDocumentError("$.runs", err)
	}
	if runIndex == 0 {
		return errors.New("$.runs: must contain at least one run")
	}

	return nil
}

func validateSARIFRun(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return sarifDocumentError(path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s: must be an object", path)
	}

	seenResults := false
	seenInvocations := false
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return sarifDocumentError(path, err)
		}
		key, _ := keyToken.(string)

		switch key {
		case "results":
			if err := validateSARIFResults(decoder, path+".results"); err != nil {
				return err
			}
			seenResults = true
		case "invocations":
			if err := validateSARIFInvocations(decoder, path+".invocations"); err != nil {
				return err
			}
			seenInvocations = true
		default:
			if err := skipSARIFJSONValue(decoder); err != nil {
				return sarifDocumentError(path+"."+key, err)
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return sarifDocumentError(path, err)
	}
	if !seenResults {
		return fmt.Errorf("%s.results: is required", path)
	}
	if !seenInvocations {
		return fmt.Errorf("%s.invocations: is required", path)
	}

	return nil
}

func validateSARIFResults(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return sarifDocumentError(path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("%s: must be an array", path)
	}

	resultIndex := 0
	for decoder.More() {
		var result sarifResult
		if err := decoder.Decode(&result); err != nil {
			return sarifDocumentError(fmt.Sprintf("%s[%d]", path, resultIndex), err)
		}
		if err := validateSARIFResult(result, fmt.Sprintf("%s[%d]", path, resultIndex)); err != nil {
			return err
		}
		resultIndex++
	}
	if _, err := decoder.Token(); err != nil {
		return sarifDocumentError(path, err)
	}

	return nil
}

func validateSARIFInvocations(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return sarifDocumentError(path, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return fmt.Errorf("%s: must be an array", path)
	}

	invocationIndex := 0
	for decoder.More() {
		var invocation sarifInvocation
		if err := decoder.Decode(&invocation); err != nil {
			return sarifDocumentError(fmt.Sprintf("%s[%d]", path, invocationIndex), err)
		}
		if invocation.ExecutionSuccessful == nil {
			return fmt.Errorf("%s[%d].executionSuccessful: is required", path, invocationIndex)
		}
		invocationIndex++
	}
	if _, err := decoder.Token(); err != nil {
		return sarifDocumentError(path, err)
	}
	if invocationIndex == 0 {
		return fmt.Errorf("%s: must contain at least one invocation", path)
	}

	return nil
}

func skipSARIFJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		for decoder.More() {
			if _, err := decoder.Token(); err != nil {
				return err
			}
			if err := skipSARIFJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := skipSARIFJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return nil
	}
}

func sarifDocumentError(path string, err error) error {
	var syntaxError *json.SyntaxError
	if errors.As(err, &syntaxError) {
		return fmt.Errorf("%s: invalid JSON near byte %d: %w", path, syntaxError.Offset, err)
	}

	return fmt.Errorf("%s: %w", path, err)
}

func publishSARIFDocument(tempPath, finalPath string) error {
	if err := os.Rename(tempPath, finalPath); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}

	if err := os.Remove(finalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return os.Rename(tempPath, finalPath)
}
