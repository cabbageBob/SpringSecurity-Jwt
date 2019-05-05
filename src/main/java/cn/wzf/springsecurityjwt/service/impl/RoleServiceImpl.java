package cn.wzf.springsecurityjwt.service.impl;

import cn.wzf.springsecurityjwt.Dao.RoleDao;
import cn.wzf.springsecurityjwt.entity.RoleEntity;
import cn.wzf.springsecurityjwt.service.RoleService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;


import java.util.List;

@Service
public class RoleServiceImpl extends ServiceImpl<RoleDao,RoleEntity> implements RoleService {

    @Override
    public List<RoleEntity> findByUserId(int userId) {
        return baseMapper.findByUserId(userId);
    }
}
