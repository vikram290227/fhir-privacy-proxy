package admin

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// tailFile returns the last n lines of the file at path. The file is
// streamed from the start (not seeked from the end) — this is
// intentionally simple: audit files in the dev/demo target are
// expected to stay well under a few MB during incident response, and
// the alternative (reverse byte-scan with a sliding window) is much
// more error-prone for a marginal speedup. If you wire up a many-GB
// audit file this should be replaced with a chunked reverse reader.
//
// A ring buffer holds the most recent n non-empty lines so memory is
// O(n) regardless of file size.
func tailFile(path string, n int) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("audit tail: open %s: %w", path, err)
	}
	defer f.Close()

	ring := make([]string, n)
	count := 0
	idx := 0

	scanner := bufio.NewScanner(f)
	// Bump the max token size — audit lines carry full subject context
	// + redacted-paths arrays and routinely exceed bufio's 64KiB
	// default.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		ring[idx] = line
		idx = (idx + 1) % n
		count++
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, fmt.Errorf("audit tail: scan %s: %w", path, err)
	}

	// Materialise the ring into chronological order.
	out := make([]string, 0, min(count, n))
	if count <= n {
		// We never wrapped — entries 0..count-1 are in order.
		for i := 0; i < count; i++ {
			out = append(out, ring[i])
		}
		return out, nil
	}
	// We wrapped. The oldest retained entry is at idx (next write
	// slot); walk forward from there.
	for i := 0; i < n; i++ {
		out = append(out, ring[(idx+i)%n])
	}
	return out, nil
}
