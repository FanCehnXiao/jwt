package com.dbnewyouth.jwt.service;

import com.dbnewyouth.jwt.model.User;

/**
 * @author xinfeng
 * @version 1.0
 * @Description
 * @date 2019/7/30 18:12
 */
public interface UserService {

    public User queryById(String id);
}
