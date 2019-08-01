### JWT是什么？

> [JWT官网](https://jwt.io/)

Json web token (JWT), 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（(RFC 7519).该token被设计为紧凑且安全的，特别适用于分布式站点的单点登录（SSO）场景。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证，也可被加密。

### JWT的组成
HEADER：主要包含加密算法和token的类型
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

PAYLOAD：主要就是存放相关的数据，包含三个部分，标准中注册的声明、公共的声明、私有的声明。
1. 标准中注册的声明（不强制使用，建议使用）
    - iss：jwt签发者
    - sub：jwt所面向的用户
    - aud：接受jwt的一方
    - exp：jwt的过期时间，过期时间必须大于签发时间
    - nbf：在什么时间之前，该jwt都是不可用的
    - iat：jwt的签发时间
    - jti：jwt的唯一身份标识，主要用来作为一次性的token，回避重放攻击

2. 公共的声明可以添加任何信息，一般添加用户相关信息以及其它业务信息
3. 私有的声明是提供者和消费者共同定义的声明，不建议存放敏感信息，因为Base64是对称解密的。
```
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022
}
```

VERIFY SIGNATURE：验证签名
 - 由header进行base64加密：eyJhbGciOiJIUzI1NiJ9
 - 由payload进行base64加密：eyJzdWIiOiJhZG1pbiIsInBhc3N3b3JkIjoiMTIzNDU2IiwiaWQiOiIwMjgzMTIzMTIiLCJleHAiOjE1NjQ2MzU0NDgsImlhdCI6MTU2NDYyOTQ0OCwianRpIjoiNGZlY2E0ZTUtNjFmZi00NWMxLWFjNjMtN2JjY2YyZjFkNjg2IiwidXNlcm5hbWUiOiJhZG1pbiJ9
 - header加密后的字符串与payload加密后的字符串加上一个key进行HS256加密：XlVkTN1eS6F0mbTX-u9FQsGj1sSbRmbBkce21Tv4nl0
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInBhc3N3b3JkIjoiMTIzNDU2IiwiaWQiOiIwMjgzMTIzMTIiLCJleHAiOjE1NjQ2MzU0NDgsImlhdCI6MTU2NDYyOTQ0OCwianRpIjoiNGZlY2E0ZTUtNjFmZi00NWMxLWFjNjMtN2JjY2YyZjFkNjg2IiwidXNlcm5hbWUiOiJhZG1pbiJ9.XlVkTN1eS6F0mbTX-u9FQsGj1sSbRmbBkce21Tv4nl0
```

### 引入依赖
```
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.1</version>
</dependency>
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.4.0</version>
</dependency>
```

### 创建两个注解，一个用来校验登录，一个用来校验method是否需要校验token

>知识点：主要用到@Target、@Retention两个注解，@Target标注自定义的注解是可以作用的范围，比如类上、方法上、属性上。@Retention定义被它所标记的注解能保留多久，三种策略：SOURCE被编译器忽略，CLASS注解将会被保留在Class文件中，但在运行时并不会被VM保留。这是默认行为，所有没有用Retention标记的注解，都会采用这种策略。RUNTIME保留至运行时。所以我们可以通过反射去获取注解信息。

1. @LoginToken
```
@Target({ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface LoginToken {
    boolean required() default true;
}
```

2. @CheckToken
```
@Target({ElementType.METHOD,ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface CheckToken {
    boolean required() default true;
}
```

### 编写工具类，用于生成token，解析token，校验token
```
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
```

### 编写拦截器拦截请求进行权限校验
```
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
```

### 配置拦截器
```
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authenticationInterceptor())
                // 拦截所有请求，通过判断是否有 @LoginToken 注解 决定是否需要登录
                .addPathPatterns("/**");
    }

    @Bean
    public AuthenticationInterceptor authenticationInterceptor() {
        return new AuthenticationInterceptor();
    }
}
```

### 使用controller进行测试
```
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
```

### PostMan进行测试

![登录](http://img.dbnewyouth.cn/blog/20190801111851.jpg)

![Hello World](http://img.dbnewyouth.cn/blog/20190801112049.png)


### 源码链接

https://github.com/FanCehnXiao/jwt.git