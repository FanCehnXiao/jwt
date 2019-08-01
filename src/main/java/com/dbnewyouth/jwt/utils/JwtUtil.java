package com.dbnewyouth.jwt.utils;

import com.dbnewyouth.jwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

/**
 * JWT相关工具类
 *
 * @author xinfeng
 * @version 1.0
 * @Description
 * @date 2019/7/30 17:11
 */
public class JwtUtil {

    /**
     * 生成jwt
     * 使用Hs256加密，私钥使用用户密码
     *
     * @param ttlMillis jwt的过期时间
     * @param user      用户信息
     * @return 返回token字符串
     * @date 2019/8/1 11:07
     */
    public static String createJWT(Long ttlMillis, User user) {
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
        // 生成JWT时间
        Long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        //创建payload的私有声明（根据特定的业务需要添加，如果要拿这个做验证，一般是需要和jwt的接收方提前沟通好验证方式的）
        HashMap<String, Object> claims = new HashMap<>();
        claims.put("id", user.getId());
        claims.put("username", user.getUsername());
        claims.put("password", user.getPassword());
        //生成签名的时候使用的秘钥secret,这个方法本地封装了的，一般可以从本地配置文件中读取，切记这个秘钥不能外露哦。它就是你服务端的私钥，在任何场景都不应该流露出去。一旦客户端得知这个secret, 那就意味着客户端是可以自我签发jwt了。
        String key = user.getPassword();
        // 签发人
        String subject = user.getUsername();
        //下面就是在为payload添加各种标准声明和私有声明了
        //这里其实就是new一个JwtBuilder，设置jwt的body
        JwtBuilder builder = Jwts.builder()
                //如果有私有声明，一定要先设置这个自己创建的私有的声明，这个是给builder的claim赋值，一旦写在标准的声明赋值之后，就是覆盖了那些标准的声明的
                .setClaims(claims)
                //设置jti(JWT ID)：是JWT的唯一标识，根据业务需要，这个可以设置为一个不重复的值，主要用来作为一次性token,从而回避重放攻击。
                .setId(UUID.randomUUID().toString())
                //iat: jwt的签发时间
                .setIssuedAt(now)
                //代表这个JWT的主体，即它的所有人，这个是一个json格式的字符串，可以存放什么userid，roldid之类的，作为什么用户的唯一标志。
                .setSubject(subject)
                //设置签名使用的签名算法和签名使用的秘钥
                .signWith(signatureAlgorithm, key);
        if (ttlMillis >= 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            // 设置过期时间
            builder.setExpiration(exp);
        }
        return builder.compact();
    }

    /**
     * Token解密
     *
     * @param token 需要解密的token
     * @param user  相关的用户
     * @return 返回解密后的信息
     * @date 2019/8/1 11:06
     */
    public static Claims parseJWT(String token, User user) {
        //签名秘钥，和生成的签名的秘钥一模一样
        String key = user.getPassword();
        //得到DefaultJwtParser
        Claims claims = Jwts.parser()
                //设置签名的秘钥
                .setSigningKey(key)
                //设置需要解析的jwt
                .parseClaimsJws(token).getBody();
        return claims;
    }

    /**
     * 校验token
     * 校验方法可以自行更改,项目中不能拿明文密码做比对,切记
     *
     * @param token 验证传入的token
     * @param user  用户信息
     * @return 校验正常时返回true, 否则返回false
     * @date 2019/8/1 11:04
     */
    public static Boolean isVerify(String token, User user) {
        //签名秘钥，和生成的签名的秘钥一模一样
        String key = user.getPassword();
        //得到DefaultJwtParser
        Claims claims = Jwts.parser()
                //设置签名的秘钥
                .setSigningKey(key)
                //设置需要解析的jwt
                .parseClaimsJws(token).getBody();
        // 项目中不要对密码进行明文校验，这里是为了方便
        if (claims.get("password").equals(user.getPassword())) {
            return true;
        }
        return false;
    }
}
