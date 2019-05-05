package cn.wzf.springsecurityjwt.Dao;

import cn.wzf.springsecurityjwt.entity.UserEntity;
import org.springframework.data.repository.CrudRepository;

public interface LoginDao extends CrudRepository<UserEntity, Integer> {
    /**
     * 通过用户名获取用户信息
     * @param username
     * @return
     */

    UserEntity findByUsername(String username);
}
