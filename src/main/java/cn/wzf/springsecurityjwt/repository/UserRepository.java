package cn.wzf.springsecurityjwt.repository;


import cn.wzf.springsecurityjwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Integer> {
        User findByUsername(String username);
}
