package cn.wzf.springsecurityjwt.config;

import cn.wzf.springsecurityjwt.filter.JWTAuthenticationFilter;
import cn.wzf.springsecurityjwt.filter.JWTLoginFilter;
import cn.wzf.springsecurityjwt.security.HttpUnauthorizedEntryPoint;
import cn.wzf.springsecurityjwt.security.MyAuthenticationProvider;
import cn.wzf.springsecurityjwt.security.MyPasswordEncoder;
import cn.wzf.springsecurityjwt.security.MyUserDetialsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAuthenticationProvider provider;

    @Bean
    public PasswordEncoder myPassowrdEncoder(){
        return new MyPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().loginProcessingUrl("/login")
                .and()
                .csrf().disable()
                .addFilter(new JWTLoginFilter(authenticationManager()))
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                .exceptionHandling().authenticationEntryPoint(new HttpUnauthorizedEntryPoint())
                .accessDeniedHandler(new HttpUnauthorizedEntryPoint());
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(provider);
        auth.userDetailsService(userDetailsService());
    }

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        return new MyUserDetialsService();
//        InMemoryUserDetailsManager iud = new InMemoryUserDetailsManager();
//        Collection<GrantedAuthority> adminAuth = new ArrayList<>();
//        adminAuth.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
//        iud.createUser(new User("zhangsan", "123456", adminAuth));
//        return iud;
    }
}
