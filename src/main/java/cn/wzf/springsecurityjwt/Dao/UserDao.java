package cn.wzf.springsecurityjwt.Dao;

import cn.wzf.springsecurityjwt.entity.UserEntity;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.data.repository.CrudRepository;

public interface UserDao extends BaseMapper<UserEntity> {
    @Select("select * from sys_user where username=#{username}")
    UserEntity findByUsername(@Param("username") String username);
}
