import org.springframework.beans.BeanUtils;

public class BeanUtilsMassAssign {
    public void updateUser(Object requestDto, Object userEntity) {
        BeanUtils.copyProperties(requestDto, userEntity);
    }
}
