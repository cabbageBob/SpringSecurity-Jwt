package cn.wzf.springsecurityjwt;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@MapperScan(value = "cn.wzf.springsecurityjwt.Dao")
public class SpringsecurityjwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringsecurityjwtApplication.class, args);
    }
}
