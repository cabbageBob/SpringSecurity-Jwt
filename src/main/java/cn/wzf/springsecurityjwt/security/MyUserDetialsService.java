package cn.wzf.springsecurityjwt.security;

import cn.wzf.springsecurityjwt.Dao.LoginDao;
import cn.wzf.springsecurityjwt.Dao.RoleDao;
import cn.wzf.springsecurityjwt.Dao.UserDao;
import cn.wzf.springsecurityjwt.entity.RoleEntity;
import cn.wzf.springsecurityjwt.entity.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MyUserDetialsService implements UserDetailsService {
    @Autowired
    private UserDao userDao;
    @Autowired
    private RoleDao roleDao;
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException{
        User user;
        try{
            UserEntity userEntity = userDao.findByUsername(s);
            List<RoleEntity> roleEntities = roleDao.findByUserId(userEntity.getId());
            Collection<SimpleGrantedAuthority> adminAuth = new ArrayList<>();
            roleEntities.stream().map(t->adminAuth.add(new SimpleGrantedAuthority(t.getRoleName())));
            for (RoleEntity roleEntity:roleEntities){
                adminAuth.add(new SimpleGrantedAuthority(roleEntity.getRoleName()));
            }
            user = new User(userEntity.getUsername(),userEntity.getPassword(),adminAuth);
        }catch (NullPointerException e){
            throw new UsernameNotFoundException("username not found");
        }
        return user;
    }
}
