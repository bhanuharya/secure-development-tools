package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTaintSourceAtReadsOnlySameFunctionSources(t *testing.T) {
	line, col, ok := taintSourceAt([]byte(`["CliLoc", [{"path": "A.java", "start": {"line": 5, "col": 30, "offset": 1}, "end": {"line": 5, "col": 60, "offset": 2}}, "upload.getOriginalFilename()"]]`))
	if !ok || line != 5 || col != 30 {
		t.Fatalf("CliLoc source: got %d:%d %v", line, col, ok)
	}
	if _, _, ok := taintSourceAt([]byte(`["CliCall", [[{"start": {"line": 5, "col": 1}}, "x"], [], ["CliLoc", []]]]`)); ok {
		t.Fatal("a source reached through a call must keep its sinks apart")
	}
	if _, _, ok := taintSourceAt(nil); ok {
		t.Fatal("no trace, no source")
	}
}

// TestOpengrepFoldsTheSinksOfOneFlow runs the real engine: one upload name that
// is written and then deleted is one finding naming the delete's line; a second
// upload in another method stays a finding of its own.
func TestOpengrepFoldsTheSinksOfOneFlow(t *testing.T) {
	bin := whichBin(envOr("SDT_OPENGREP_BIN", "opengrep"))
	if bin == "" || !IsOpenGrep(bin) {
		t.Skip("opengrep binary not installed")
	}
	dir := t.TempDir()
	src := `import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class UploadResource {
    public void store(MultipartFile upload) throws IOException {
        File file = new File(upload.getOriginalFilename());
        FileOutputStream out = new FileOutputStream(file);
        out.close();
        if (file.exists()) {
            file.delete();
        }
    }

    public void discard(MultipartFile second) {
        File copy = new File(second.getOriginalFilename());
        copy.delete();
    }
}
`
	if err := os.WriteFile(filepath.Join(dir, "UploadResource.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := filepath.Join(repoRoot(t), "rules", "opengrep-rules", "java", "boundary.yaml")
	cmd := exec.Command(bin, "scan", "--json", "-q", "--taint-intrafile", "--dataflow-traces", "--config", rule, dir)
	out, err := cmd.Output()
	if _, exited := err.(*exec.ExitError); err != nil && (!exited || len(out) == 0) {
		t.Fatalf("opengrep failed: %v", err)
	}
	res := (&OpengrepAdapter{}).Parse("test", dir, out, "", 0)
	var got []string
	for _, f := range res.Findings {
		if f.Rule.ID != "scp.java.path.request-path-to-file-operation" {
			continue
		}
		got = append(got, filepath.Base(f.Location.Path)+":"+strconv.Itoa(*f.Location.StartLine)+" "+lastSentence(f.Message))
	}
	want := []string{
		"UploadResource.java:9 The same value also reaches line 12.",
		"UploadResource.java:18 " + lastSentence(ruleMessageEnd),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\n\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// ruleMessageEnd is the rule message's last sentence: a flow with one sink keeps the message unchanged.
const ruleMessageEnd = "Generate the stored name on the server (a UUID), keep only an allow-listed extension, " +
	"and resolve it under a fixed directory with a normalize-and-startsWith check."

func lastSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(strings.TrimSuffix(s, "."), ". "); i >= 0 {
		return s[i+2:]
	}
	return s
}
