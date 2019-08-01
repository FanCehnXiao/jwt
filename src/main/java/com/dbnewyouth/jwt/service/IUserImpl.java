package com.dbnewyouth.jwt.service;

import com.dbnewyouth.jwt.model.User;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author xinfeng
 * @version 1.0
 * @Description
 * @date 2019/7/30 18:12
 */
@Service("userService")
public class IUserImpl implements UserService {
    // 就不接入数据库了，测试jwt而已
    @Override
    public User queryById(String id) {
        User user = new User();
        user.setId(id);
        user.setUsername("admin");
        user.setPassword("123456");
        return user;
    }
}
