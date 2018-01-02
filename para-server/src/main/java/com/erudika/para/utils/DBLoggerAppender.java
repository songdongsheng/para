package com.erudika.para.utils;

import ch.qos.logback.access.spi.IAccessEvent;
import ch.qos.logback.core.UnsynchronizedAppenderBase;
import com.alibaba.druid.pool.DruidDataSource;
import org.apache.commons.lang3.StringUtils;

import java.sql.*;

public class DBLoggerAppender extends UnsynchronizedAppenderBase<IAccessEvent> {

    private static final DruidDataSource dataSource;

    static {
        String dialectName = Config.getConfigParam("jdbc.dialect", "sqlite");
        dataSource = new DruidDataSource();
        dataSource.setUrl(Config.getConfigParam("jdbc.url", "jdbc:sqlite:sqlite.db"));
        dataSource.setUsername(Config.getConfigParam("jdbc.username", ""));
        dataSource.setPassword(Config.getConfigParam("jdbc.password", ""));
        dataSource.setInitialSize(Config.getConfigInt("jdbc.initial_size", 1));
        dataSource.setMaxActive(Config.getConfigInt("jdbc.max_active", 16));
        dataSource.setMaxWait(Config.getConfigInt("jdbc.max_wait", 5000));
        dataSource.setTestWhileIdle(false);
        if ("oracle".equalsIgnoreCase(dialectName)) {
            dataSource.setPoolPreparedStatements(true);
        }
    }

    @Override
    protected void append(IAccessEvent event) {
        String insertSQL = "INSERT INTO META_API_LOG (ID, APP_ID, TENANT_ID, ACCESS_TIME, REMOTE_USER, REMOTE_HOST, REQUEST_HOST, REQUEST_METHOD, REQUEST_PATH, API_IDENTIFIER, QUERY_STRING, REQUEST_REFERER, USER_AGENT, STATUS_CODE, PROCESS_TIME, REQUEST_CONTENT_LENGTH, REQUEST_CONTENT, RESPONSE_CONTENT_LENGTH, RESPONSE_CONTENT) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection cn = getConnection()) {
            cn.setAutoCommit(true);
            try (PreparedStatement ps = cn.prepareStatement(insertSQL)) {
                addAccessEvent(ps, event);
                int updateCount = ps.executeUpdate();
                if (updateCount != 1) {
                    addWarn("Failed to insert access event");
                }
            }
        } catch (SQLException e) {
            addWarn("Failed to insert access event", e);
        }
    }

    public static Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }

    private void addAccessEvent(PreparedStatement stmt, IAccessEvent event) throws SQLException {
        if (event instanceof JwtAccessEvent) {
            JwtAccessEvent jwt = (JwtAccessEvent) event;
            stmt.setString(1, Utils.getNewId());
            stmt.setString(2, Config.getRootAppIdentifier());
            stmt.setString(3, jwt.getTenantId());
            stmt.setTimestamp(4, new Timestamp(jwt.getRequestTime()));
            stmt.setString(5, jwt.getRemoteUser());
            stmt.setString(6, jwt.getRemoteHost());
            stmt.setString(7, jwt.getRequestHeader("Host"));
            stmt.setString(8, jwt.getMethod());
            stmt.setString(9, jwt.getRequestURI());
            stmt.setString(10, getApiName(jwt.getRequestURI()));
            stmt.setString(11, jwt.getQueryString().replace("?", ""));
            stmt.setString(12, jwt.getRequestHeader("Referer"));
            stmt.setString(13, jwt.getRequestHeader("User-Agent"));
            stmt.setInt(14, jwt.getResponse().getStatus());
            stmt.setLong(15, jwt.getElapsedTime());
            stmt.setLong(16, jwt.getRequest().getContentLength() < 0 ? 0 : jwt.getRequest().getContentLength());
            stmt.setString(17, jwt.getRequestContent());
            stmt.setLong(18, jwt.getContentLength());
            stmt.setString(19, jwt.getResponseContent());
        }
    }

    private String getApiName(String uri){
        if (StringUtils.isBlank(uri) || !uri.startsWith("/v1/")) {
            return uri;
        }

        String[] termList = uri.split("/");
        if (termList.length < 3 || termList[2].length() < 1 || termList[2].charAt(0) == '_'
                || "utils".equals(termList[2])) return uri;

        switch (termList.length) {
            case 3:
                if (uri.startsWith("/v1/")) {
                    return "/v1/{type}";
                }
                break;
            case 4:
                if (uri.startsWith("/v1/abrain/usermgr")) {
                    return "/v1/abrain/usermgr";
                } else if (uri.startsWith("/v1/abrain/batch")) {
                    return "/v1/abrain/batch";
                } else if (uri.startsWith("/v1/abrain/delete")) {
                    return "/v1/abrain/delete";
                } else if (uri.startsWith("/v1/abrain/rbac")) {
                    return "/v1/abrain/rbac";
                } else if (uri.startsWith("/v1/search")) {
                    return "/v1/search/{querytype}";
                } else {
                    return "/v1/{type}/{id}";
                }
            case 5:
                if (uri.startsWith("/v1/abrain/mapping/reindex")) {
                    return "/v1/abrain/mapping/reindex/{indexName}";
                } else if (uri.startsWith("/v1/abrain/mapping/sync")) {
                    return "/v1/abrain/mapping/sync";
                } else if (uri.startsWith("/v1/abrain/usermgr")) {
                    return "/v1/abrain/usermgr/{id}";
                } else if (uri.startsWith("/v1/abrain/rbac/sync")) {
                    return "/v1/abrain/rbac/sync";
                } else if (uri.startsWith("/v1/abrain/validate/sync")) {
                    return "/v1/abrain/validate/sync";
                } else if (uri.startsWith("/v1/abrain/view/generate")) {
                    return "/v1/abrain/view/generate";
                } else if (uri.startsWith("/v1/abrain/bo/joint")) {
                    return "/v1/abrain/bo/joint";
                } else if (uri.startsWith("/v1/abrain/bo/cascade")) {
                    return "/v1/abrain/bo/cascade";
                } else if (uri.startsWith("/v1/abrain/bo/productOutStore")) {
                    return "/v1/abrain/bo/productOutStore";
                } else if (uri.startsWith("/v1/abrain/bo/tenant/")) {
                    return "/abrain/bo/tenant/{querytype}";
                } else if (uri.startsWith("/v1/abrain/bo")) {
                    return "/v1/abrain/bo/{type}";
                } else if (uri.startsWith("/v1/") && uri.contains("/search/")) {
                    return "/v1/{type}/search/{querytype}";
                }
                break;
            case 6:
                if (uri.startsWith("/v1/") && uri.contains("/links/")) {
                    return "/v1/{type1}/{id}/links/{type2}";
                } else if (uri.startsWith("/v1/abrain/mapping/reindex")) {
                    return "/v1/abrain/mapping/reindex/{indexName}/{id}";
                } else if (uri.startsWith("/v1/abrain/auto/code")) {
                    return "/v1/abrain/auto/code/{type}";
                } else if (uri.startsWith("/v1/abrain/coderule/")) {
                    return "/v1/abrain/coderule/{objectName}/{prefixCode}";
                } else if (uri.startsWith("/v1/abrain/childRelation/")) {
                    return "/v1/abrain/childRelation/{parentType}/{parentId}";
                } else if (uri.startsWith("/v1/abrain/tree/code/")) {
                    return "/v1/abrain/tree/code/{type}";
                } else if (uri.startsWith("/v1/abrain/rbac/tree/")) {
                    return "/v1/abrain/rbac/tree/{type}";
                } else if (uri.startsWith("/v1/abrain/tcc/dtc/")) {
                    return "/v1/abrain/tcc/dtc/{txid}";
                } else if (uri.startsWith("/v1/abrain/tcc/tx/")) {
                    return "/v1/abrain/tcc/tx/{txid}";
                } else if (uri.startsWith("/v1/abrain/tcc/bo/")) {
                    return "/v1/abrain/tcc/bo/{type}";
                } else if (uri.startsWith("/v1/abrain/bo/search")) {
                    return "/v1/abrain/bo/search/{querytype}";
                } else if (uri.startsWith("/v1/abrain/bo/mold")) {
                    return "/v1/abrain/bo/mold/{requestType}";
                } else if (uri.startsWith("/v1/abrain/bo")) {
                    return "/v1/abrain/bo/{type}/{id}";
                }
                break;
            case 7:
                if (uri.startsWith("/v1/") && uri.contains("/links/")) {
                    return "/v1/{type1}/{id}/links/{type2}/{id2}";
                } else if (uri.startsWith("/v1/abrain/tcc/bo/")) {
                    return "/v1/abrain/tcc/bo/{type}/{id}";
                } else if (uri.startsWith("/v1/abrain/bo")) {
                    return "/v1/abrain/bo/{type}/{id}/{linkedType}";
                }
                break;
        }
        return uri;
    }

}
