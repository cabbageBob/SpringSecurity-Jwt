package cn.wzf.springsecurityjwt.entity;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;
@Data
@Entity
@Table(name = "sys_user")
public class UserEntity implements Serializable {
    @Id
    @Column(name = "id")
    private int id;
    @Column(name = "password")
    private String password;
    @Column(name = "username")
    private String username;
    @Transient
    private List<GrantedAuthority> roleEntities;
}
