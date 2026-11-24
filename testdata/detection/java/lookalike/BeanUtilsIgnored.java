import org.springframework.beans.BeanUtils;

public class BeanUtilsIgnored {
    public void updateUser(Object requestDto, Object userEntity) {
        BeanUtils.copyProperties(requestDto, userEntity, "role", "authorities", "activated");
    }
}
