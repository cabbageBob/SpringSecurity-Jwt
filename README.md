# SpringSecurity+Jwt的用户认证

## 1、创建用户实体类User
```
package cn.wzf.springsecurityjwt.entity;

import lombok.Data;
import javax.persistence.*;

@Entity
@Table(name = "sys_user")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "role")
    private String role;
}
```
## 2、dao层
```
package cn.wzf.springsecurityjwt.repository;

import cn.wzf.springsecurityjwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Integer> {
        User findByUsername(String username);
}
```
## 3、service层
```
package cn.wzf.springsecurityjwt.service;

import cn.wzf.springsecurityjwt.entity.JwtUser;
import cn.wzf.springsecurityjwt.entity.User;
import cn.wzf.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user =  userRepository.findByUsername(s);
        return new JwtUser(user);
    }
}
```
## 4、实现UserDetails
```
package cn.wzf.springsecurityjwt.entity;

import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@NoArgsConstructor
public class JwtUser implements UserDetails {

    private Integer id;
    private String username;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;

    // 写一个能直接使用user创建jwtUser的构造器
    public JwtUser(User user) {
        id = user.getId();
        username = user.getUsername();
        password = user.getPassword();
        authorities = Collections.singleton(new SimpleGrantedAuthority(user.getRole()));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    // 账号是否未过期，默认是false
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 账号是否未锁定，默认是false
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 账号凭证是否未过期，默认是false
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String toString() {
        return "JwtUser{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", password='" + password + '\'' +
                ", authorities=" + authorities +
                '}';
    }

}
```
## 5、实现UserDetailsService
```
package cn.wzf.springsecurityjwt.service;

import cn.wzf.springsecurityjwt.entity.JwtUser;
import cn.wzf.springsecurityjwt.entity.User;
import cn.wzf.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        User user =  userRepository.findByUsername(s);
        return new JwtUser(user);
    }
}
```
## 6、实现用户登录验证的拦截器
```
package cn.wzf.springsecurityjwt.filter;

import cn.wzf.springsecurityjwt.entity.JwtUser;
import cn.wzf.springsecurityjwt.model.LoginUser;
import cn.wzf.springsecurityjwt.utils.JwtTokenUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private ThreadLocal<Integer> rememberMe = new ThreadLocal<>();
    private AuthenticationManager authenticationManager;
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
        super.setFilterProcessesUrl("/auth/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response){
        // 从输入流中获取到登录的信息
        try {
            LoginUser loginUser = new ObjectMapper().readValue(request.getInputStream(),LoginUser.class);
            rememberMe.set(loginUser.getRememberMe());
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginUser.getUsername(),loginUser.getPassword(),new ArrayList<>())
            );
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 成功验证后调用的方法
    // 如果验证成功，就生成token并返回
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult){
        JwtUser jwtUser = (JwtUser) authResult.getPrincipal();
        log.info("jwtUser:" + jwtUser.toString());
        boolean isRemember = rememberMe.get() ==1;
        String role = "";
        Collection<? extends GrantedAuthority> authorities = jwtUser.getAuthorities();
        for (GrantedAuthority authority : authorities){
            role = authority.getAuthority();
        }
        String token = JwtTokenUtils.createToken(jwtUser.getUsername(),role,isRemember);
        response.setHeader("token",JwtTokenUtils.TOKEN_PREFIX+token);
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.getWriter().write("authentication failed, reason: " + failed.getMessage());
    }
}
```
## 7、实现验证用户权限的拦截器
```
package cn.wzf.springsecurityjwt.filter;

import cn.wzf.springsecurityjwt.utils.JwtTokenUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain chain) throws IOException, ServletException {
        String tokenHeader =request.getHeader(JwtTokenUtils.TOKEN_HEADER);
        // 如果请求头中没有Authorization信息则直接放行了
        if (tokenHeader == null || !tokenHeader.startsWith(JwtTokenUtils.TOKEN_PREFIX)){
            chain.doFilter(request,response);
            return;
        }
        // 如果请求头中有token，则进行解析，并且设置认证信息
        SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
        super.doFilterInternal(request,response,chain);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader){
        String token = tokenHeader.replace(JwtTokenUtils.TOKEN_PREFIX,"");
        String username = JwtTokenUtils.getUserName(token);
        String role = JwtTokenUtils.getUserRole(token);
        if (username != null){
            return new UsernamePasswordAuthenticationToken(username,null,
                    Collections.singleton(new SimpleGrantedAuthority(role)));
        }
        return null;
    }
}
```
## 8、登录失败进行的操作（实现AuthenticationEntryPoint）
```
package cn.wzf.springsecurityjwt.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentType("application/json; charset=utf-8");
        httpServletResponse.setStatus(httpServletResponse.SC_FORBIDDEN);
        String reason = "统一处理，原因："+e.getMessage();
        httpServletResponse.getWriter().write(new ObjectMapper().writeValueAsString(reason));
    }
}
```
## 9、配置SpringSecurity
```
package cn.wzf.springsecurityjwt.config;

import cn.wzf.springsecurityjwt.exception.JWTAuthenticationEntryPoint;
import cn.wzf.springsecurityjwt.filter.JWTAuthenticationFilter;
import cn.wzf.springsecurityjwt.filter.JWTAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    @Qualifier("userDetailsServiceImpl")
    private UserDetailsService  userDetailsService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception{
        http.cors().and().csrf().disable()
                .authorizeRequests()
                .antMatchers("/task/**").authenticated()
                .antMatchers(HttpMethod.DELETE,"/task/**").hasRole("ADMIN")
                .anyRequest().permitAll()
                .and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                // 不需要session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //异常捕获
                .exceptionHandling().authenticationEntryPoint(new JWTAuthenticationEntryPoint());
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",new CorsConfiguration().applyPermitDefaultValues());
        return source;
    }
}
```
## 10、编写Controller类进行测试
用户注册
```
package cn.wzf.springsecurityjwt.controller;

import cn.wzf.springsecurityjwt.entity.User;
import cn.wzf.springsecurityjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

@Controller
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @PostMapping("/register")
    public String registerUser(@RequestBody Map<String,String> registerUser){
        User user = new User();
        user.setUsername(registerUser.get("username"));
        user.setPassword(bCryptPasswordEncoder.encode(registerUser.get("password")));
        user.setRole("ROLE_USER");
        User save = userRepository.save(user);
        return save.toString();
    }
}
```
权限验证
```
package cn.wzf.springsecurityjwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/task")
public class TaskController {
    @GetMapping
    public String listTasks(){
        return "任务列表";
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public String newTasks(){
        return "创建了一个新的任务";
    }

    @PutMapping("/{taskId}")
    public String updateTasks(@PathVariable("taskId")Integer id){
        return "更新了一下id为:"+id+"的任务";
    }

    @DeleteMapping("/{taskId}")
    public String deleteTasks(@PathVariable("taskId")Integer id){
        return "删除了id为:"+id+"的任务";
    }
}
```
忘了jwttokenUtils,补上
```
package cn.wzf.springsecurityjwt.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtTokenUtils {
    public static final String TOKEN_HEADER = "Authonrization";
    public static final String TOKEN_PREFIX = "Bearer ";
    private static final String SECRET = "jwtsecretdemo";
    private static final String ISS = "echisan";
    // 角色的key
    private static final String ROLE_CLAIMS = "role";

    // 过期时间是3600秒，既是1个小时
    private static final long EXPIRATION = 3600L;

    // 选择了记住我之后的过期时间为7天
    private static final long EXPIRATION_REMEMBER = 604800L;
    // 创建token
    public static  String createToken(String username,String role,boolean isRememberMe){
        long expiration = isRememberMe? EXPIRATION : EXPIRATION_REMEMBER;
        Map<String,Object> map = new HashMap<>();
        map.put(ROLE_CLAIMS,role);
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS512,SECRET)
                .setClaims(map)
                .setIssuer(ISS)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION * 1000))
                .compact();
    }
    //从token中获取用户名
    public  static String getUserName(String token){
        return getTokenBody(token).getSubject();
    }
    //获取用户角色
    public static String getUserRole(String token){
        return (String) getTokenBody(token).get(ROLE_CLAIMS);
    }
    //是否过期
    public static boolean isExpiration(String token){
        return getTokenBody(token).getExpiration().before(new Date());
    }
    public static Claims getTokenBody(String token){
        return Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token)
                .getBody();
    }
}
```
