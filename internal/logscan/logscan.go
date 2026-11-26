// Package logscan reads a GitHub Actions log archive and extracts evidence:
// which action commits the runner downloaded, which indicators of compromise
// appear, and the NAMES of secrets a memory-dumping payload printed.
//
// Secret values are never returned, stored or printed. The decoder keeps a
// decoded blob only long enough to pull the names out of it.
package logscan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// Download is one "Download action repository" line from the job setup log.
// The runner writes one for every action it fetches, including actions that
// a composite action calls, so this is the commit that actually ran.
type Download struct {
	Action string `json:"action"` // e.g. tj-actions/changed-files@v45
	SHA    string `json:"sha"`
	File   string `json:"file"`
}

// Hit is one indicator-of-compromise match.
type Hit struct {
	Indicator string `json:"indicator"`
	File      string `json:"file"`
	Line      int    `json:"line"`
}

// Evidence is everything found in one archive.
type Evidence struct {
	Downloads []Download `json:"downloads,omitempty"`
	Hits      []Hit      `json:"indicator_hits,omitempty"`
	// LeakedSecrets are secret names found in a decoded memory dump.
	LeakedSecrets []string `json:"leaked_secrets,omitempty"`
	// DumpFiles are the log files a memory dump was found in.
	DumpFiles []string `json:"dump_files,omitempty"`
	// Skipped lists files that could not be fully read (with the reason).
	Skipped []string `json:"skipped,omitempty"`
}

var (
	downloadLine = regexp.MustCompile(`Download action repository '([^']+)' \(SHA:([0-9a-fA-F]{40})\)`)
	// A run of base64 long enough to carry a dump. Short tokens (hashes, ids)
	// are ignored to keep the scan fast and quiet.
	b64Token = regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`)
	// The format the tj-actions / reviewdog payload printed after decoding:
	// "NAME":{"value":"...","isSecret":true}
	secretEntry = regexp.MustCompile(`"([^"\\]{1,200})":\{"value":"(?:[^"\\]|\\.)*","isSecret":true\}`)
)

// maxLine bounds one log line. A payload prints its whole dump on one line,
// so this is generous; a longer line is reported as skipped, never silently
// truncated.
const maxLine = 64 << 20

// ScanZip scans every file in a log archive.
func ScanZip(path string, indicators []string) (*Evidence, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("open log archive: %w", err)
	}
	defer zr.Close()
	ev := &Evidence{}
	leaked := map[string]bool{}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			ev.Skipped = append(ev.Skipped, f.Name+": "+err.Error())
			continue
		}
		err = scanFile(f.Name, rc, indicators, ev, leaked)
		rc.Close()
		if err != nil {
			ev.Skipped = append(ev.Skipped, f.Name+": "+err.Error())
		}
	}
	for k := range leaked {
		ev.LeakedSecrets = append(ev.LeakedSecrets, k)
	}
	sort.Strings(ev.LeakedSecrets)
	sort.Strings(ev.DumpFiles)
	return ev, nil
}

// ScanReader scans one log stream; it exists for tests and for single files.
func ScanReader(name string, r io.Reader, indicators []string) (*Evidence, error) {
	ev := &Evidence{}
	leaked := map[string]bool{}
	if err := scanFile(name, r, indicators, ev, leaked); err != nil {
		return nil, err
	}
	for k := range leaked {
		ev.LeakedSecrets = append(ev.LeakedSecrets, k)
	}
	sort.Strings(ev.LeakedSecrets)
	return ev, nil
}

func scanFile(name string, r io.Reader, indicators []string, ev *Evidence, leaked map[string]bool) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	lineNo := 0
	dumped := false
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if m := downloadLine.FindStringSubmatch(line); m != nil {
			ev.Downloads = append(ev.Downloads, Download{Action: m[1], SHA: strings.ToLower(m[2]), File: name})
		}
		for _, ind := range indicators {
			if ind != "" && strings.Contains(line, ind) {
				ev.Hits = append(ev.Hits, Hit{Indicator: ind, File: name, Line: lineNo})
			}
		}
		if len(line) >= 80 {
			for _, n := range secretNamesInLine(line) {
				leaked[n] = true
				dumped = true
			}
		}
	}
	if dumped {
		ev.DumpFiles = append(ev.DumpFiles, name)
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("a line is longer than %d MiB; the rest of this file was not scanned", maxLine>>20)
		}
		return err
	}
	return nil
}

// secretNamesInLine decodes every long base64 token once and twice and
// returns secret names found in either decoding. The tj-actions payload
// encoded twice to slip past GitHub's log masking, which only masks the raw
// secret value; other payloads may encode once.
func secretNamesInLine(line string) []string {
	var names []string
	for _, tok := range b64Token.FindAllString(line, -1) {
		once, ok := decodeB64(tok)
		if !ok {
			continue
		}
		names = append(names, namesIn(once)...)
		if twice, ok := decodeB64(string(once)); ok {
			names = append(names, namesIn(twice)...)
		}
	}
	return names
}

func namesIn(b []byte) []string {
	if !bytes.Contains(b, []byte(`"isSecret":true`)) {
		return nil
	}
	var out []string
	for _, m := range secretEntry.FindAllSubmatch(b, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

func decodeB64(s string) ([]byte, bool) {
	// A dump can be wrapped across lines once decoded; base64 ignores none of
	// that whitespace, so strip it before decoding.
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}
