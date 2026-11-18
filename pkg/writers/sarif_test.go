package writers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sensepost/gowitness/pkg/models"
)

type decodedSARIF struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID                   string `json:"id"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string       `json:"ruleId"`
			RuleIndex int          `json:"ruleIndex"`
			Level     string       `json:"level"`
			Message   sarifMessage `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
					Region           sarifRegion           `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties sarifResultProperties `json:"properties"`
		} `json:"results"`
		Invocations []struct {
			ExecutionSuccessful        bool                `json:"executionSuccessful"`
			ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications"`
		} `json:"invocations"`
	} `json:"runs"`
}

func newSARIFTestWriter(t *testing.T) (*SarifWriter, string) {
	t.Helper()

	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	screenshots := filepath.Join(root, "screenshots")
	if err := os.MkdirAll(screenshots, 0755); err != nil {
		t.Fatal(err)
	}

	destination := filepath.Join(root, "reports", "gowitness.sarif")
	writer, err := NewSarifWriter(destination)
	if err != nil {
		t.Fatalf("NewSarifWriter: %v", err)
	}
	writer.RepositoryRoot = root
	writer.ScreenshotPath = screenshots

	return writer, root
}

func readDecodedSARIF(t *testing.T, writer *SarifWriter) ([]byte, decodedSARIF) {
	t.Helper()

	data, err := os.ReadFile(writer.FilePath)
	if err != nil {
		t.Fatalf("read SARIF: %v", err)
	}
	validateSARIFAgainstOfficialSchema(t, data)

	var document decodedSARIF
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}

	return data, document
}

func validateSARIFAgainstOfficialSchema(t *testing.T, data []byte) {
	t.Helper()

	schemaBytes, err := os.ReadFile(filepath.Join("testdata", "sarif-2.1.0.json"))
	if err != nil {
		t.Fatalf("read official SARIF schema: %v", err)
	}
	schemaDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		t.Fatalf("parse official SARIF schema: %v", err)
	}

	const schemaResource = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaResource, schemaDocument); err != nil {
		t.Fatalf("add official SARIF schema: %v", err)
	}
	schema, err := compiler.Compile(schemaResource)
	if err != nil {
		t.Fatalf("compile official SARIF schema: %v", err)
	}

	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse SARIF instance: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("SARIF does not validate against the official 2.1.0 schema: %v", err)
	}
}

func TestSARIFMultipleRulesAndExactLocations(t *testing.T) {
	writer, root := newSARIFTestWriter(t)
	probedAt := time.Date(2026, 11, 18, 1, 2, 3, 4, time.UTC)
	html := strings.Join([]string{
		"<html>",
		`<head><script src="/app.js"></script></head>`,
		"<body>",
		"<div>nginx</div>",
		"<div>jQuery</div>",
		"<div>session</div>",
		"<div>tracking</div>",
		`<script>console.error("boom")</script>`,
		"</body>",
		"</html>",
	}, "\n")

	result := &models.Result{
		URL:          "https://alice:supersecret@example.test/login?token=abc",
		FinalURL:     "https://example.test/login",
		ProbedAt:     probedAt,
		ResponseCode: 503,
		HTML:         html,
		Title:        "Example",
		Filename:     "target.jpeg",
		Failed:       true,
		FailedReason: "screenshot failed under /home/example/private/work",
		Technologies: []models.Technology{{Value: "nginx"}, {Value: "jQuery"}},
		Cookies: []models.Cookie{
			{Name: "tracking", Domain: "example.test"},
			{Name: "session", Domain: "example.test"},
		},
		Console: []models.ConsoleLog{{Type: "error", Value: "boom"}},
	}

	if err := writer.Write(result); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	data, document := readDecodedSARIF(t, writer)
	if document.Version != sarifVersion {
		t.Fatalf("version = %q, want %q", document.Version, sarifVersion)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(document.Runs))
	}

	run := document.Runs[0]
	if len(run.Results) != 8 {
		t.Fatalf("results = %d, want 8", len(run.Results))
	}

	ruleIDs := map[string]int{}
	technologyLocations := map[int]sarifRegion{}
	for _, result := range run.Results {
		ruleIDs[result.RuleID]++
		rule, ok := sarifRuleByID(result.RuleID)
		if !ok {
			t.Fatalf("unknown rule ID %q", result.RuleID)
		}
		if result.Level != SARIFSeverityLevels[rule.Severity] {
			t.Errorf("rule %s level = %q, want %q", result.RuleID, result.Level, SARIFSeverityLevels[rule.Severity])
		}
		if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "screenshots/target.jpeg" {
			t.Errorf("artifact URI = %q", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		if result.RuleID == sarifRuleTechnology {
			technologyLocations[result.Locations[0].PhysicalLocation.Region.StartLine] = result.Locations[0].PhysicalLocation.Region
		}
	}

	if ruleIDs[sarifRuleCaptureFailed] != 1 ||
		ruleIDs[sarifRuleHTTPServerErr] != 1 ||
		ruleIDs[sarifRuleAssetObserved] != 1 ||
		ruleIDs[sarifRuleTechnology] != 2 ||
		ruleIDs[sarifRuleInsecureCookie] != 2 ||
		ruleIDs[sarifRuleConsoleError] != 1 {
		t.Fatalf("unexpected per-rule result counts: %#v", ruleIDs)
	}

	nginx := technologyLocations[4]
	if nginx.StartColumn != 6 || nginx.EndColumn != 11 || nginx.EndLine != 4 {
		t.Errorf("nginx location = %+v, want line 4 columns 6-11", nginx)
	}
	jquery := technologyLocations[5]
	if jquery.StartColumn != 6 || jquery.EndColumn != 12 || jquery.EndLine != 5 {
		t.Errorf("jQuery location = %+v, want line 5 columns 6-12", jquery)
	}

	if bytes.Contains(data, []byte(root)) ||
		bytes.Contains(data, []byte("/home/")) ||
		bytes.Contains(data, []byte("supersecret")) ||
		bytes.Contains(data, []byte("alice:")) ||
		bytes.Contains(data, []byte("token=abc")) {
		t.Fatalf("SARIF leaked an absolute path or credential: %s", data)
	}
}

func TestSARIFDuplicateURLPreservesTimeline(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)

	first := &models.Result{
		URL:          "https://example.test/",
		ProbedAt:     time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC),
		ResponseCode: 200,
		Filename:     "example.jpeg",
	}
	second := *first
	second.ProbedAt = first.ProbedAt.Add(time.Minute)

	if err := writer.Write(first); err != nil {
		t.Fatalf("Write first: %v", err)
	}
	if err := writer.Write(&second); err != nil {
		t.Fatalf("Write second: %v", err)
	}
	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	_, document := readDecodedSARIF(t, writer)
	var assets []sarifResultProperties
	for _, result := range document.Runs[0].Results {
		if result.RuleID == sarifRuleAssetObserved {
			assets = append(assets, result.Properties)
		}
	}
	if len(assets) != 2 {
		t.Fatalf("asset results = %d, want 2", len(assets))
	}
	if assets[0].ProbedAt == assets[1].ProbedAt {
		t.Fatalf("timeline collapsed: both probed_at values are %q", assets[0].ProbedAt)
	}
}

func TestSARIFZeroFindings(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)

	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	data, document := readDecodedSARIF(t, writer)
	if len(document.Runs) != 1 || len(document.Runs[0].Results) != 0 {
		t.Fatalf("results = %#v, want empty", document.Runs)
	}
	if !bytes.Contains(data, []byte(`"results":[]`)) {
		t.Fatalf("zero-finding document does not contain an empty results array: %s", data)
	}
	if !document.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatal("zero-finding invocation should be successful")
	}
}

func TestSARIFScanFailureMarksInvocation(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)

	result := &models.Result{
		URL:          "https://example.test/",
		ProbedAt:     time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC),
		ResponseCode: 200,
		Filename:     "example.jpeg",
	}
	if err := writer.Write(result); err != nil {
		t.Fatalf("Write: %v", err)
	}

	runErr := errors.New("scan interrupted under /tmp/gowitness and https://user:pass@example.test/")
	if err := writer.CloseRun(runErr); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	data, document := readDecodedSARIF(t, writer)
	invocation := document.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful {
		t.Fatal("failed scan marked executionSuccessful=true")
	}
	if len(invocation.ToolExecutionNotifications) != 1 {
		t.Fatalf("notifications = %d, want 1", len(invocation.ToolExecutionNotifications))
	}
	message := invocation.ToolExecutionNotifications[0].Message.Text
	if strings.Contains(message, "/tmp/") || strings.Contains(message, "/home/") || strings.Contains(message, "user:pass") {
		t.Fatalf("failure notification leaked a path or credential: %q", message)
	}
	if bytes.Contains(data, []byte("/tmp/gowitness")) || bytes.Contains(data, []byte("user:pass")) {
		t.Fatalf("failed SARIF leaked a path or credential: %s", data)
	}
}

func TestSARIFWriteFailurePublishesNoPartialFile(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)

	if err := writer.Write(&models.Result{URL: "https://example.test/", ResponseCode: 200, Filename: "one.jpeg"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if writer.file == nil {
		t.Fatal("expected a temporary output file")
	}
	if err := writer.file.Close(); err != nil {
		t.Fatal(err)
	}
	writer.file = nil

	large := &models.Result{URL: "https://example.test/large", ResponseCode: 200, Filename: "large.jpeg"}
	for i := 0; i < 200; i++ {
		large.Technologies = append(large.Technologies, models.Technology{Value: strings.Repeat(fmt.Sprintf("tech-%03d-", i), 80)})
	}
	if err := writer.Write(large); err == nil {
		t.Fatal("expected a write error after the underlying file was closed")
	}
	if err := writer.CloseRun(nil); err == nil {
		t.Fatal("expected CloseRun to return the write error")
	}
	if _, err := os.Stat(writer.FilePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial SARIF file exists: %v", err)
	}
}

func TestSARIFWriteFailureKeepsPreviousDocument(t *testing.T) {
	writer, root := newSARIFTestWriter(t)
	if err := writer.Write(&models.Result{
		URL:          "https://example.test/",
		ProbedAt:     time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC),
		ResponseCode: 200,
		Filename:     "one.jpeg",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}
	previous, err := os.ReadFile(writer.FilePath)
	if err != nil {
		t.Fatal(err)
	}

	replacement, err := NewSarifWriter(writer.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	replacement.RepositoryRoot = root
	replacement.ScreenshotPath = writer.ScreenshotPath
	if err := replacement.Write(&models.Result{URL: "https://example.test/new", ResponseCode: 200}); err != nil {
		t.Fatalf("Write replacement: %v", err)
	}
	if err := replacement.file.Close(); err != nil {
		t.Fatal(err)
	}
	replacement.file = nil

	large := &models.Result{URL: "https://example.test/large", ResponseCode: 200}
	for i := 0; i < 200; i++ {
		large.Technologies = append(large.Technologies, models.Technology{Value: strings.Repeat(fmt.Sprintf("tech-%03d-", i), 80)})
	}
	if err := replacement.Write(large); err == nil {
		t.Fatal("expected replacement write to fail")
	}
	if err := replacement.CloseRun(nil); err == nil {
		t.Fatal("expected replacement CloseRun to fail")
	}

	current, err := os.ReadFile(replacement.FilePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(previous, current) {
		t.Fatal("failed replacement modified the previous valid SARIF document")
	}
}

func TestSARIFPathEscapingAndExternalization(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	spacePath := filepath.Join(root, "screenshots", "hello world.jpeg")
	uri, err := sarifArtifactURI(spacePath, root)
	if err != nil {
		t.Fatalf("space path: %v", err)
	}
	if uri != "screenshots/hello%20world.jpeg" {
		t.Fatalf("space path URI = %q", uri)
	}

	invalidName := string(append([]byte("screenshots/bad-"), 0xff, '.', 'j', 'p', 'g'))
	invalidPath := filepath.Join(root, invalidName)
	uri, err = sarifArtifactURI(invalidPath, root)
	if err != nil {
		t.Fatalf("non-UTF-8 path: %v", err)
	}
	if !utf8.ValidString(uri) || !strings.Contains(uri, "%FF") || strings.Contains(uri, string([]byte{0xff})) {
		t.Fatalf("non-UTF-8 path was not escaped: %q", uri)
	}

	secret := filepath.Join(outside, "secret.jpeg")
	if err := os.WriteFile(secret, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked.jpeg")
	if err := os.Symlink(secret, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	uri, err = sarifArtifactURI(link, root)
	if err != nil {
		t.Fatalf("symlink path: %v", err)
	}
	if !strings.HasPrefix(uri, "gowitness-external/") || strings.Contains(uri, outside) {
		t.Fatalf("escaping symlink was not externalized: %q", uri)
	}

	longPath := filepath.Join(root, strings.Repeat("a", 3000), "image.jpeg")
	uri, err = sarifArtifactURI(longPath, root)
	if err != nil {
		t.Fatalf("long path: %v", err)
	}
	if !strings.HasPrefix(uri, "gowitness-external/") || len(uri) >= sarifMaxURIPathLength {
		t.Fatalf("long path was not bounded: %q", uri)
	}

	if strings.Contains(uri, root) || strings.Contains(uri, "/home/") || (reprDrive(uri) != "" && strings.Contains(uri, reprDrive(uri))) {
		t.Fatalf("artifact URI leaked an absolute path: %q", uri)
	}
}

func TestSARIFNonUTF8FilenameProducesValidJSON(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)
	filename := "bad-" + string([]byte{0xff, 0xfe}) + ".jpeg"

	if err := writer.Write(&models.Result{
		URL:          "https://example.test/",
		ProbedAt:     time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC),
		ResponseCode: 200,
		Filename:     filename,
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	data, document := readDecodedSARIF(t, writer)
	uri := document.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !utf8.ValidString(string(data)) || !strings.Contains(uri, "%FF") || !strings.Contains(uri, "%FE") {
		t.Fatalf("non-UTF-8 filename was not safely escaped: uri=%q data=%q", uri, data)
	}
}

func TestSARIFPublicErrorsSanitizePathsAndCredentials(t *testing.T) {
	message := sanitizeSARIFError(
		errors.New("scan failed at /home/example/work/repo/target, /srv/data/target, C:\\work\\target, password=supersecret and https://user:pass@example.test/"),
		"/home/example/work/repo",
	)

	if strings.Contains(message, "/home/") ||
		strings.Contains(message, "/srv/") ||
		strings.Contains(message, "C:\\") ||
		strings.Contains(message, "supersecret") ||
		strings.Contains(message, "user:pass") ||
		strings.Contains(message, "/tmp/") {
		t.Fatalf("public error leaked a path or credential: %q", message)
	}

	writer, root := newSARIFTestWriter(t)
	if err := os.RemoveAll(filepath.Dir(writer.FilePath)); err != nil {
		t.Fatal(err)
	}
	err := writer.Write(&models.Result{URL: "https://user:pass@example.test/", ResponseCode: 200})
	if err == nil {
		t.Fatal("expected writer error after output directory was removed")
	}
	if strings.Contains(err.Error(), root) || strings.Contains(err.Error(), "/home/") || strings.Contains(err.Error(), "user:pass") {
		t.Fatalf("writer error leaked a path or credential: %q", err)
	}
}

func TestSARIFConcurrentWrites(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)

	const total = 80
	var waitGroup sync.WaitGroup
	errs := make(chan error, total)
	for i := 0; i < total; i++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			errs <- writer.Write(&models.Result{
				URL:          fmt.Sprintf("https://example.test/%d", index),
				ProbedAt:     time.Date(2026, 11, 18, 1, 0, index, 0, time.UTC),
				ResponseCode: 200,
				Filename:     fmt.Sprintf("target-%d.jpeg", index),
			})
		}(i)
	}
	waitGroup.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Write: %v", err)
		}
	}
	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	_, document := readDecodedSARIF(t, writer)
	if len(document.Runs[0].Results) != total {
		t.Fatalf("results = %d, want %d", len(document.Runs[0].Results), total)
	}
}

func TestSARIFOfficialSchema(t *testing.T) {
	writer, _ := newSARIFTestWriter(t)
	if err := writer.Write(&models.Result{
		URL:          "https://example.test/",
		ProbedAt:     time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC),
		ResponseCode: 404,
		Filename:     "example.jpeg",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := writer.CloseRun(nil); err != nil {
		t.Fatalf("CloseRun: %v", err)
	}

	data, err := os.ReadFile(writer.FilePath)
	if err != nil {
		t.Fatalf("read SARIF: %v", err)
	}
	validateSARIFAgainstOfficialSchema(t, data)
}

func TestSARIFSelfCheckReportsFieldPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.sarif")
	document := `{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"results":[{"ruleId":"","ruleIndex":0,"level":"error","message":{"text":"message"},"locations":[]}],"invocations":[{"executionSuccessful":true}]}]}`
	if err := os.WriteFile(path, []byte(document), 0644); err != nil {
		t.Fatal(err)
	}

	err := validateSARIFDocument(path)
	if err == nil {
		t.Fatal("expected self-check to reject the broken result")
	}
	if !strings.Contains(err.Error(), "runs[0].results[0].ruleId") {
		t.Fatalf("self-check error does not identify the field path: %v", err)
	}
}

func TestSARIFSeverityMappingIsExplicit(t *testing.T) {
	tests := map[string]string{
		sarifSeverityHigh:   sarifLevelError,
		sarifSeverityMedium: sarifLevelWarning,
		sarifSeverityHint:   sarifLevelNote,
	}
	for severity, want := range tests {
		if got := SARIFSeverityLevels[severity]; got != want {
			t.Errorf("SARIFSeverityLevels[%q] = %q, want %q", severity, got, want)
		}
	}
}

func TestSARIFWriterImplementsRunCloser(t *testing.T) {
	var _ RunCloser = (*SarifWriter)(nil)
	var _ Writer = (*SarifWriter)(nil)
}

func reprDrive(value string) string {
	if len(value) >= 2 && value[1] == ':' {
		return value[:2]
	}
	return ""
}
