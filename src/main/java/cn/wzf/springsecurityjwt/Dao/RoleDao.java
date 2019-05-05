package cn.wzf.springsecurityjwt.Dao;

import cn.wzf.springsecurityjwt.entity.RoleEntity;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.*;

import java.util.List;
public interface RoleDao extends BaseMapper<RoleEntity> {
    @Select("SELECT a.id,a.`name` FROM sys_role a \n" +
            "LEFT JOIN \n" +
            "sys_user_roles b\n" +
            "ON a.id=b.role_id\n" +
            "WHERE b.sys_user_id=${id}")
    @Results({
            @Result(column = "id",property = "roleId"),
            @Result(column = "name",property = "roleName")
    })
    List<RoleEntity> findByUserId(@Param("id") int userId);
    RoleEntity findAllByRoleId(int id  );
}
