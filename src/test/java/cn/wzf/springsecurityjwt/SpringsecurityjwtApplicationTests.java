package cn.wzf.springsecurityjwt;

import cn.wzf.springsecurityjwt.Dao.RoleDao;
import cn.wzf.springsecurityjwt.Dao.UserDao;
import cn.wzf.springsecurityjwt.service.RoleService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SpringsecurityjwtApplicationTests {
    @Autowired
    RoleService roleService;
    @Autowired
    UserDao userDao;
    @Test
    public void contextLoads() {

    }
    @Test
    public void testRoleDao(){
        System.out.println(roleService.getById(1));
        System.out.println(roleService.findByUserId(3));
    }
    @Test
    public void testUserDao(){
        System.out.println(userDao.findByUsername("admin"));
    }
}
