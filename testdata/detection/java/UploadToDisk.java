import java.io.File;
import java.io.FileOutputStream;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

// The upload's own file name becomes the path written and then deleted.
public class UploadToDisk {
    public String compare(@RequestParam("image") MultipartFile image) throws Exception {
        File file = new File(image.getOriginalFilename());
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(image.getBytes());
        } finally {
            file.delete();
        }
        return "ok";
    }
}
