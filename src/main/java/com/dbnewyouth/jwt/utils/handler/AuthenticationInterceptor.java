package com.dbnewyouth.jwt.utils.handler;

import com.auth0.jwt.JWT;
import com.dbnewyouth.jwt.model.User;
import com.dbnewyouth.jwt.service.UserService;
import com.dbnewyouth.jwt.utils.JwtUtil;
import com.dbnewyouth.jwt.utils.annotation.CheckToken;
import com.dbnewyouth.jwt.utils.annotation.LoginToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

/**
 * 拦截器
 *
 * @author xinfeng
 * @version 1.0
 * @Description
 * @date 2019/7/30 17:54
 */
public class AuthenticationInterceptor implements HandlerInterceptor {

    @Autowired
    UserService userService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object object) throws Exception {
        // 从http请求头中取出token
        String token = request.getHeader("token");
        // 如果不是映射到方法直接通过
        if (!(object instanceof HandlerMethod)) {
            return true;
        }
        HandlerMethod handlerMethod = (HandlerMethod) object;
        Method method = handlerMethod.getMethod();
        // 如果有LoginToken注释，跳过认证
        if (method.isAnnotationPresent(LoginToken.class)) {
            LoginToken loginToken = method.getAnnotation(LoginToken.class);
            if (loginToken.required()) {
                return true;
            }
        }
        // 检查有没有需要用户权限的注解
        if (method.isAnnotationPresent(CheckToken.class)) {
            CheckToken checkToken = method.getAnnotation(CheckToken.class);
            if (checkToken.required()) {
                if (token == null) {
                    throw new RuntimeException("No Token，Please login again");
                }
            }
            // 获取token中的user id
            String userId = JWT.decode(token).getClaim("id").asString();
            User user = userService.queryById(userId);
            if (user == null) {
                throw new RuntimeException("User does not exist，Please login again");
            }
            Boolean verify = JwtUtil.isVerify(token, user);
            if (!verify) {
                throw new RuntimeException("Illegal visits！");
            }
            return true;
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, ModelAndView modelAndView) throws Exception {

    }

    @Override
    public void afterCompletion(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) throws Exception {

    }

}
