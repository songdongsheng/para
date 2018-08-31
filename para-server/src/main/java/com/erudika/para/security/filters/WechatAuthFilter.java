package com.erudika.para.security.filters;

import com.erudika.para.Para;
import com.erudika.para.core.App;
import com.erudika.para.core.Sysprop;
import com.erudika.para.core.User;
import com.erudika.para.core.utils.CoreUtils;
import com.erudika.para.core.utils.ParaObjectUtils;
import com.erudika.para.rest.RestUtils;
import com.erudika.para.security.AuthenticatedUserDetails;
import com.erudika.para.security.SecurityUtils;
import com.erudika.para.security.UserAuthentication;
import com.erudika.para.utils.AES;
import com.erudika.para.utils.Config;
import com.erudika.para.utils.Utils;
import com.fasterxml.jackson.databind.ObjectReader;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.ParseException;
import java.util.*;

public class WechatAuthFilter extends AbstractAuthenticationProcessingFilter {

    private final CloseableHttpClient httpclient;
    private final ObjectReader jreader;
    private static final String PROFILE_URL = "https://api.weixin.qq.com/sns/userinfo?access_token={0}&openid={1}";
    private static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid={0}&secret={1}&code={2}&grant_type={3}";
    private static final String MINI_URL = "https://api.weixin.qq.com/sns/jscode2session?appid={0}&secret={1}&js_code={2}&grant_type={3}";
    private String openid = "";

    /**
     * The default filter mapping.
     */
    public static final String WECHAT_ACTION = "wechat_auth";

    /**
     * Default constructor.
     * @param defaultFilterProcessesUrl the url of the filter
     */
    public WechatAuthFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        this.jreader = ParaObjectUtils.getJsonReader(Map.class);
        this.httpclient = HttpClients.createDefault();
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Request is to process authentication");
        }

        final String requestURI = request.getRequestURI();
        if (requestURI.endsWith(WECHAT_ACTION)) {
            Authentication authResult;
            try {
                authResult = attemptAuthentication(request, response);
                if (authResult == null) {
                    return;
                }
                String appid = request.getParameter(Config._APPID);
                App app = Para.getDAO().read(App.id(appid == null ? Config.getRootAppIdentifier() : appid));
                User user = SecurityUtils.getAuthenticatedUser(authResult);
                if (user != null && user.getActive()) {
                    // issue token
                    SignedJWT newJWT = SecurityUtils.generateJWToken(user, app);
                    if (newJWT != null) {
                        succesHandler(response, user, newJWT);
                        return;
                    }
                    return;
                }
            } catch (InternalAuthenticationServiceException failed) {
                logger.error("An internal error occurred while trying to authenticate the user.", failed);
                unsuccessfulAuthentication(request, response, failed);
                return;
            } catch (AuthenticationException failed) {
                // Authentication failed
//                unsuccessfulAuthentication(request, response, failed);
                RestUtils.returnStatusResponse(response, HttpServletResponse.SC_FORBIDDEN, failed.getMessage());
                return;
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        final String requestURI = request.getRequestURI();
        UserAuthentication userAuth = null;

        if (requestURI.endsWith(WECHAT_ACTION)) {
            //2018-08-30 zhouzz 根据请求方式区分登录类型
            String method = request.getMethod();
            if ("POST".equalsIgnoreCase(method)) {
                // 微信小程序登录
                userAuth = loginMiniProgram(request);

            } else if ("GET".equalsIgnoreCase(method)){
                //微信二维码登录
                userAuth = loginWechat(request);

            }
        }
        return SecurityUtils.checkIfActive(userAuth, SecurityUtils.getAuthenticatedUser(userAuth), true);
    }

    private String acceptJSON(HttpServletRequest request){
        String acceptjson = "";
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(request.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String temp;
            while ((temp = br.readLine()) != null) {
                sb.append(temp);
            }
            br.close();
            acceptjson = sb.toString();
        } catch (Exception e) {
//            e.printStackTrace();
            logger.error("request date not json.");
        }
        return acceptjson;
    }

    /**
     * 2018-08-30 zhouzz 微信二维码登录
     * @param request 请求参数
     * @return userInfo
     */
    private UserAuthentication loginWechat(HttpServletRequest request) {
        UserAuthentication userAuth = null;

        String authCode = request.getParameter("code");
        if (!StringUtils.isBlank(authCode)) {
            String appid = request.getParameter(Config._APPID);
            App app = Para.getDAO().read(App.id(appid == null ? Config.getRootAppIdentifier() : appid));
            String grant_type = Config.getConfigParam("wechat_grant_type", "authorization_code");
            String[] keys = SecurityUtils.getOAuthKeysForApp(app, Config.WECHAT_PREFIX);
            String url = Utils.formatMessage(TOKEN_URL, keys[0], keys[1], authCode, grant_type);
            try {
                HttpGet tokenPost = new HttpGet(url);
                Map<String, Object> accessToken = parseAccessToken(httpclient.execute(tokenPost));
                if (accessToken != null && accessToken.containsKey("access_token")) {
                    String access_token = (String) accessToken.get("access_token");
                    openid = (String) accessToken.get("openid");
                    userAuth = getOrCreateUser(app, access_token);
                }
            } catch (Exception e) {
                logger.warn("wechat auth request failed: GET " + url, e);
            }
        } else {
            logger.warn("wechat auth request failed: the required query parameters 'code', are missing.");
        }
        return userAuth;
    }

    /**
     * 2018-08-30 zhouzz 微信小程序登录
     * @param request 请求参数
     * @return userInfo
     */
    private UserAuthentication loginMiniProgram(HttpServletRequest request) {
        UserAuthentication userAuth = null;
        User user = new User();

        try {
            // 请求body体参数
            Map<String, Object> params = jreader.readValue(acceptJSON(request));
            String code = (String) params.get("code");
            String encryptedData = (String) params.get("encryptedData");
            String iv = (String) params.get("iv");

            if (!StringUtils.isBlank(code)) {
                String appid = request.getParameter(Config._APPID);
                App app = Para.getDAO().read(App.id(appid == null ? Config.getRootAppIdentifier() : appid));
                String grant_type = Config.getConfigParam("wechat_grant_type", "authorization_code");
                String[] keys = SecurityUtils.getOAuthKeysForApp(app, Config.WECHAT_MINI_PREFIX);
                String url = Utils.formatMessage(MINI_URL, keys[0], keys[1], code, grant_type);
                try {
                    HttpGet tokenPost = new HttpGet(url);
                    Map<String, Object> accessToken = parseAccessToken(httpclient.execute(tokenPost));
                    if (accessToken != null && accessToken.containsKey("session_key")) {
                        String session_key = (String) accessToken.get("session_key");
                        openid = (String) accessToken.get("openid");

                        //解密微信的userInfo信息，从解密数据中获取unionId
                        String decrypt = AES.wxDecrypt(encryptedData, session_key, iv);
                        if (StringUtils.isNotBlank(decrypt)) {
                            logger.info("解密成功");
                            Map<String, Object> userInfo = jreader.readValue(decrypt);

                            user = getUser(app, user, userInfo);
                        } else {
                            logger.warn("解密失败");
                        }
    //                    EntityUtils.consumeQuietly(respEntity);

                        // 必须先刷新 ES，不然可能导致后续查询不到数据
                        CoreUtils.getInstance().getSearch().flush(app.getAppIdentifier());

                        userAuth = new UserAuthentication(new AuthenticatedUserDetails(user));
                    }
                } catch (Exception e) {
                    logger.warn("wechat mini request failed: POST " + url, e);
                }
            } else {
                logger.warn("wechat mini request failed: the required query body 'code', are missing.");
            }
        } catch (IOException e) {
            logger.warn("wechat mini request failed: POST ", e);
        }
        return SecurityUtils.checkIfActive(userAuth, SecurityUtils.getAuthenticatedUser(userAuth), true);
    }

    /**
     * Calls the WECHAT API to get the user profile using a given access token.
     * @param app the app where the user will be created, use null for root app
     * @param accessToken access token
     * @return {@link UserAuthentication} object or null if something went wrong
     * @throws IOException ex
     */
    public UserAuthentication getOrCreateUser(App app, String accessToken) throws IOException {
        UserAuthentication userAuth = null;
        User user = new User();
        if (accessToken != null) {
            HttpEntity respEntity;
            String ctype;
            String content;
            String url = Utils.formatMessage(PROFILE_URL, accessToken, openid);
            try {
                HttpGet profileGet = new HttpGet(url);
                profileGet.setHeader(HttpHeaders.ACCEPT, "application/json");
                CloseableHttpResponse resp2 = httpclient.execute(profileGet);
                content = EntityUtils.toString(resp2.getEntity(), Config.DEFAULT_ENCODING);
                respEntity = resp2.getEntity();
                ctype = resp2.getFirstHeader(HttpHeaders.CONTENT_TYPE).getValue();
            } catch (IOException e) {
                logger.warn("Wechat auth request failed: GET " + url, e);
                throw new RuntimeException("微信验证失败,请重新尝试!");
            }

            if (respEntity != null && StringUtils.equals("text/plain", ctype)) {
                Map<String, Object> profile = jreader.readValue(content);

                user = getUser(app, user, profile);

            }
            EntityUtils.consumeQuietly(respEntity);

            // 必须先刷新 ES，不然可能导致后续查询不到数据
            CoreUtils.getInstance().getSearch().flush(app.getAppIdentifier());

            userAuth = new UserAuthentication(new AuthenticatedUserDetails(user));
        }
        return SecurityUtils.checkIfActive(userAuth, user, false);
    }

    private static String getValueAsString(Map map, String... keys) {
        if (map == null || map.isEmpty()) {
            return null;
        }

        if (keys != null && keys.length > 0) {
            for (String key : keys) {
                if (map.containsKey(key)) {
                    return (String) map.get(key);
                }
            }
        }
        return null;
    }
    private static Integer getValueAsInteger(Map map, String... keys) {
        if (map == null || map.isEmpty()) {
            return null;
        }

        if (keys != null && keys.length > 0) {
            for (String key : keys) {
                if (map.containsKey(key)) {
                    return (Integer) map.get(key);
                }
            }
        }
        return null;
    }

    /**
     * 2018-08-30 zhouzz 根据微信的userInfo中的unionid获取或者创建系统用户
     * @param app app
     * @param user user
     * @param profile 微信的userInfo
     * @return 查询或者创建的User对象
     */
    private User getUser(App app, User user, Map<String, Object> profile) {
        if (profile != null && (profile.containsKey("unionid") || profile.containsKey("unionId"))) {
            String unionid = getValueAsString(profile, "unionid", "unionId"); //用户统一标识。针对一个微信开放平台帐号下的应用，同一用户的unionid是唯一的。
            String openid = getValueAsString(profile, "openid", "openId"); //普通用户的标识，对当前开发者帐号唯一
            String name = getValueAsString(profile, "nickname", "nickName"); //普通用户昵称

            String pic = getValueAsString(profile, "headimgurl", "avatarUrl"); //用户头像，最后一个数值代表正方形头像大小（有0、46、64、96、132数值可选，0代表640*640正方形头像），用户没有头像时该项为空
            String country = (String) profile.get("country");   //国家，如中国为CN
            String province = (String) profile.get("province"); //普通用户个人资料填写的省份
            String city = (String) profile.get("city"); //普通用户个人资料填写的城市

            String sex = "";
            Integer gender = getValueAsInteger(profile, "sex", "gender"); //普通用户性别，1为男性，2为女性
            if (gender != null) {
                sex = gender == 1 ? "男" : "女";
            }

            // 查询用户是否已注册
            HashMap<String, String> map = new HashMap<>();
            map.put("wechat", Config.WECHAT_PREFIX + unionid);
            map.put("active", "true");
            List<Sysprop> muList = CoreUtils.getInstance().getDao().findTerms(app.getAppIdentifier(), "metaUser", map, true);
            if (muList != null && !muList.isEmpty()) {
                Sysprop mu = muList.get(0);
                map.clear();
                map.put("id", mu.getParentid());
                List<User> userList = CoreUtils.getInstance().getDao().findTerms(app.getAppid(), "user", map, true);
                if (userList != null && !userList.isEmpty()) {
                    user = userList.get(0);
                    String picture = getPicture(pic);
                    boolean update = false;
                    if (!StringUtils.equals(user.getPicture(), picture)) {
                        user.setPicture(picture);
                        ParaObjectUtils.setProperty(mu, "picture", picture); // mu.setPicture(picture);
                        update = true;
                    }
                    String sex1 = ParaObjectUtils.getPropertyAsString(mu, "sex"); //  String sex1 = mu.getSex();
                    if (!StringUtils.equals(sex, sex1)) {
                        mu.addProperty("sex", sex);
                        update = true;
                    }
                    if (update) {
                        user.update();
                        mu.update();
                    }
                    SecurityUtils.setTenantInfo(user, mu);
                }
            } else {
                // 查询该微信号未绑定用户时自动根据微信号注册账号
                Sysprop metaUser = createUser(app, name, pic, unionid, sex, user);
                String mid = metaUser.getId();
                if (mid == null) {
                    user.delete();
                    throw new AuthenticationServiceException("Authentication failed: cannot create new metaUser.");
                }
//                throw new AuthenticationServiceException("您的微信还未在本平台绑定账号，请先绑定账号");
            }
        }
        return user;
    }

    private Sysprop createUser(App app, String name, String pic, String unionid, String sex, User user) {
        //user is new
        user.setName(name);
        user.setActive(true);
        user.setAppid(getAppid(app));
//        user.setEmail(StringUtils.isBlank(email) ? unionid + "@github.com" : email);
        user.setName(StringUtils.isBlank(name) ? "No Name" : name);
        user.setPicture(getPicture(pic));
        user.setGroups(User.Groups.ADMINS.toString());
        user.setIdentifier(Config.WECHAT_PREFIX + unionid);
        String id = user.create();
        if (id == null) {
            throw new AuthenticationServiceException("Authentication failed: cannot create new user.");
        }
        Sysprop metaUser = ParaObjectUtils.newParaObjectInstance("metaUser");
        metaUser.setType("metaUser");
        metaUser.setAppid(getAppid(app));
        metaUser.setTimestamp(System.currentTimeMillis());
        metaUser.setUpdated(System.currentTimeMillis());
        metaUser.setParentid(id);
        metaUser.setName(name);
        ParaObjectUtils.setProperty(metaUser, "picture", pic); // metaUser.setPicture(pic);
        ParaObjectUtils.setProperty(metaUser, "sex", sex); //  metaUser.setSex(sex);
        ParaObjectUtils.setProperty(metaUser, "wechat", Config.WECHAT_PREFIX + unionid); //  metaUser.setWechat(Config.WECHAT_PREFIX + unionid);
        metaUser.addProperty("tenantId", Config.getConfigParam("rootTenantId", "00000000"));
        metaUser.addProperty("username", name);
        ParaObjectUtils.setProperty(metaUser, "roleId", Collections.singletonList("05G109TZB1WFEXA1")); //  metaUser.setRoleId(Arrays.asList("05G109TZB1WFEXA1"));
        ParaObjectUtils.setProperty(metaUser, "profileId", Collections.emptyList()); //  metaUser.setProfileId(Arrays.asList());
        metaUser.create();
        return metaUser;
    }


    private void succesHandler(HttpServletResponse response, User user, final SignedJWT token) {
        if (user != null && token != null) {
            Map<String, Object> result = new HashMap<>();
            try {
                HashMap<String, Object> jwt = new HashMap<>();
                jwt.put("access_token", token.serialize());
                jwt.put("refresh", token.getJWTClaimsSet().getLongClaim("refresh"));
                jwt.put("expires", token.getJWTClaimsSet().getExpirationTime().getTime());
                result.put("jwt", jwt);
                result.put("user", user);
                response.setHeader("Authorization", "Bearer" + token.serialize());
            } catch (ParseException ex) {
                logger.info("Unable to parse JWT.", ex);
                RestUtils.returnStatusResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Bad token.");
            }
            RestUtils.returnObjectResponse(response, result);
        } else {
            RestUtils.returnStatusResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Null token.");
        }
    }

    private Map<String, Object> parseAccessToken(CloseableHttpResponse resp1) {
        if (resp1 != null && resp1.getEntity() != null) {
            try {
                // Facebook keep changing their API so we try to read the access_token by the old and new ways
                String token = EntityUtils.toString(resp1.getEntity(), Config.DEFAULT_ENCODING);
                if (token != null) {
                    Map<String, Object> tokenObject = jreader.readValue(token);
                    if (tokenObject != null && !tokenObject.containsKey("errcode")) {
                        return tokenObject;
                    } else {
                        logger.error("get session_key fail, response: " + tokenObject.toString());
                    }
                }
            } catch (Exception e) {
                logger.error(null, e);
            } finally {
                EntityUtils.consumeQuietly(resp1.getEntity());
            }
        }
        return null;
    }

    private static String getPicture(String pic) {
        if (pic != null) {
            if (pic.contains("?")) {
                // user picture migth contain size parameters - remove them
                return pic.substring(0, pic.indexOf('?'));
            } else {
                return pic;
            }
        }
        return null;
    }

    private String getAppid(App app) {
        return (app == null) ? null : app.getAppIdentifier();
    }
}
