package cn.wzf.springsecurityjwt.service;

import cn.wzf.springsecurityjwt.entity.RoleEntity;
import com.baomidou.mybatisplus.extension.service.IService;

import java.util.List;

public interface RoleService extends IService<RoleEntity> {
    List<RoleEntity> findByUserId(int userId);
}
