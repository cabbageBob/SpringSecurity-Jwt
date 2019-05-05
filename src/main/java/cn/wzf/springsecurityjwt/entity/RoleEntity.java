package cn.wzf.springsecurityjwt.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

import javax.validation.constraints.Min;

@Data
@TableName(value = "sys_role")
public class RoleEntity {

    @TableId(value = "id")
    @Min(value = 1, message = "roleId必须大于等于1")
    private int roleId;

    @TableField(value = "name")
    private String roleName;
}
