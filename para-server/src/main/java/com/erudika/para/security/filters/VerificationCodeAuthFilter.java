package com.erudika.para.security.filters;

import cn.abrain.baas.rbac.entity.VerificationCode;
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
import com.erudika.para.utils.Config;
import com.fasterxml.jackson.databind.ObjectReader;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
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
import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VerificationCodeAuthFilter extends AbstractAuthenticationProcessingFilter{

    /**
     * The default filter mapping.
     */
    private final CloseableHttpClient httpclient;
    private final ObjectReader jreader;
    public static final String VERIFICATIONCODE_ACTION = "vcode_auth";

    /**
     * Default constructor.
     * @param defaultFilterProcessesUrl the url of the filter
     */
    public VerificationCodeAuthFilter(String defaultFilterProcessesUrl) {
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
        if (requestURI.endsWith(VERIFICATIONCODE_ACTION)) {
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
                RestUtils.returnStatusResponse(response, HttpServletResponse.SC_FORBIDDEN, failed.getMessage());
                return;
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        final String requestURI = request.getRequestURI();
        UserAuthentication userAuth = null;

        if (requestURI.endsWith(VERIFICATIONCODE_ACTION)) {
            //验证码
            String authCode = request.getParameter("code");
            String phone = request.getParameter("phone");

            if (StringUtils.isBlank(authCode)) {
                logger.warn("wechat auth request failed: the required query parameters 'code', are missing.");
            }

            String appid = request.getParameter(Config._APPID);
            App app = Para.getDAO().read(App.id(appid == null ? Config.getRootAppIdentifier() : appid));

            try{
                //验证码通过
                userAuth = getOrCreateUser( app,phone );

            } catch (Exception e) {
                logger.warn("verificationcode auth request failed ", e);
            }

        }
        return SecurityUtils.checkIfActive( userAuth, SecurityUtils.getAuthenticatedUser(userAuth), true );
    }

    /**
     * Calls the WECHAT API to get the user profile using a given access token.
     * @param app the app where the user will be created, use null for root app
     * @return {@link UserAuthentication} object or null if something went wrong
     * @throws IOException ex
     */
    public UserAuthentication getOrCreateUser( App app,String accessToken ) throws IOException {
        UserAuthentication userAuth = null;
        User user = new User();

        if (accessToken != null && accessToken.contains(Config.SEPARATOR)) {
            String[] parts = accessToken.split(Config.SEPARATOR, 3);
            String phone = parts[0];
            String name = parts[1];
            String vcode = (parts.length > 2) ? parts[2] : "";

            if (StringUtils.isBlank(vcode) || !checkVcode(app.getAppIdentifier(), phone, vcode)) {
//                throw new AuthenticationServiceException("验证码输入有误");
                logger.warn("验证码:"+vcode+" 输入错误或已失效!");
                return null;
            }

            // 查询用户是否已注册
            HashMap<String, String> map = new HashMap<>();
            map.put("phone", phone);
            List<Sysprop> metaUsers = CoreUtils.getInstance().getDao().findTerms(app.getAppIdentifier(), "metaUser", map, true);
            if (metaUsers != null && !metaUsers.isEmpty()) {
                Sysprop metaUser = metaUsers.get(0);

                map.clear();
                map.put("id", metaUser.getParentid());
                List<User> users = CoreUtils.getInstance().getDao().findTerms(app.getAppid(), "user", map, true);
                if (users != null && !users.isEmpty()) {
                    user = users.get(0);
                    if (!user.getActive()) {
                        user.setActive(true);
                        user.update();
                    }
                }

                //判断是否激活
                if (!metaUser.isActive()) {
                    metaUser.setActive(true);
                    metaUser.update();
                }

            } else {
                // 查询该手机号未绑定用户时自动根据手机号注册账号
                Sysprop metaUser = createUser(app, phone, user);
                String mid = metaUser.getId();
                if (mid == null) {
                    user.delete();
                    throw new AuthenticationServiceException("Authentication failed: cannot create new metaUser.");
                }

            }
            userAuth = new UserAuthentication(new AuthenticatedUserDetails(user));
        }
        return SecurityUtils.checkIfActive(userAuth, user, false);
    }

    private boolean checkVcode(String appid, String phone, String vcode) {
        long time = System.currentTimeMillis();

        //校验验证码时否有效
        Map<String, Object> terms = new HashMap<>();
        terms.put("active", "true");
        terms.put("phone", phone);
        terms.put("vCode", vcode);
        List<VerificationCode> vcs = Para.getDAO().findTerms(appid, "verificationCode", terms, true);

		if(vcs==null || vcs.size()<=0){
			return false;
		}
		VerificationCode vc = vcs.get(0);
		if(time-vc.getTimestamp()>(10*60*1000)){
			vc.delete();
			return false;
		}
		vc.delete();
        return true;
    }

    private Sysprop createUser(App app, String phone, User user) {
        //user is new
        user.setActive(true);
        user.setAppid(getAppid(app));
        user.setGroups(User.Groups.ADMINS.toString());
        user.setIdentifier(phone);
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
        metaUser.setName(phone); //手机验证码登陆默认使用手机号昵称
        ParaObjectUtils.setProperty(metaUser, "picture", user.getPicture());
        ParaObjectUtils.setProperty(metaUser,"phone",phone);
        ParaObjectUtils.setProperty(metaUser,"tenantId", Config.getConfigParam("rootTenantId", "00000000"));
        ParaObjectUtils.setProperty(metaUser,"username", phone);
        ParaObjectUtils.setProperty(metaUser, "roleId", Arrays.asList("05G109TZB1WFEXA1")); //  metaUser.setRoleId(Arrays.asList("05G109TZB1WFEXA1"));
        ParaObjectUtils.setProperty(metaUser, "profileId", Arrays.asList()); //  metaUser.setProfileId(Arrays.asList());
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

    private String getAppid(App app) {
        return (app == null) ? null : app.getAppIdentifier();
    }


    private Map<String, Object> parseAccessToken(CloseableHttpResponse resp1) {
        if (resp1 != null && resp1.getEntity() != null) {
            try {
                // Facebook keep changing their API so we try to read the access_token by the old and new ways
                String token = EntityUtils.toString(resp1.getEntity(), Config.DEFAULT_ENCODING);
                if (token != null) {
                    Map<String, Object> tokenObject = jreader.readValue(token);
                    if (tokenObject != null && tokenObject.containsKey("access_token")) {
                        return tokenObject;
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

}
