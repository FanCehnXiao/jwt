package com.dbnewyouth.jwt.controller;

import com.alibaba.fastjson.JSONObject;
import com.dbnewyouth.jwt.model.User;
import com.dbnewyouth.jwt.service.UserService;
import com.dbnewyouth.jwt.utils.JwtUtil;
import com.dbnewyouth.jwt.utils.annotation.CheckToken;
import com.dbnewyouth.jwt.utils.annotation.LoginToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

/**
 * 测试
 *
 * @author xinfeng
 * @version 1.0
 * @Description
 * @date 2019/7/30 16:55
 */
@RestController
@RequestMapping("/test")
public class TestController {

    @Autowired
    private UserService userService;

    /**
     * 登录方法
     *
     * @param user 用户信息
     * @return 成功返回token ，失败返回错误信息
     * @date 2019/7/31 14:09
     */
    @LoginToken
    @PostMapping("/login")
    public Object login(@RequestBody @Valid User user) {
        // 校验参数
        if (user == null) {
            return "params is not null";
        }
        // 校验密码是否正确
        if (!(user.getPassword().equalsIgnoreCase("123456"))) {
            return "login fail";
        } else {
            // 返回一个假的参数回去，实际代码可不要这么用
            User queryUser = new User();
            queryUser.setId("028312312");
            queryUser.setUsername(user.getUsername());
            queryUser.setPassword("123456");
            // 生成一个jwt的token    6000000L是过期时间
            String token = JwtUtil.createJWT(6000000L, queryUser);
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("token", token);
            jsonObject.put("user", queryUser);
            return jsonObject;
        }
    }

    /**
     * 测试token校验方法
     *
     * @return 返回Hello World!
     * @date 2019/7/31 14:13
     */
    @GetMapping("/hello")
    @CheckToken
    public String hello() {
        return "Hello World!";
    }
}
