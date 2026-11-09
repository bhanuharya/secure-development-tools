import java.nio.file.Paths;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestParam;

// Safe: the request's object name only names the download; no file is opened or written.
public class DownloadHeader {
    public ResponseEntity<byte[]> download(@RequestParam String objectName) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Disposition", "attachment; filename=\"" + Paths.get(objectName).getFileName().toString() + "\"");
        return ResponseEntity.ok().headers(headers).body(fetch(objectName));
    }

    private byte[] fetch(String objectName) { return new byte[0]; }
}
