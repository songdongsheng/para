package com.erudika.para.utils;

import ch.qos.logback.access.jetty.JettyServerAdapter;
import ch.qos.logback.access.joran.JoranConfigurator;
import ch.qos.logback.access.spi.AccessEvent;
import ch.qos.logback.access.spi.IAccessEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.ContextBase;
import ch.qos.logback.core.CoreConstants;
import ch.qos.logback.core.boolex.EventEvaluator;
import ch.qos.logback.core.filter.Filter;
import ch.qos.logback.core.joran.spi.JoranException;
import ch.qos.logback.core.spi.*;
import ch.qos.logback.core.status.ErrorStatus;
import ch.qos.logback.core.status.InfoStatus;
import ch.qos.logback.core.util.FileUtil;
import ch.qos.logback.core.util.OptionHelper;
import ch.qos.logback.core.util.StatusPrinter;
import com.erudika.para.Para;
import com.erudika.para.core.App;
import com.erudika.para.core.User;
import com.erudika.para.security.SecurityUtils;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Response;

import javax.ws.rs.core.HttpHeaders;
import java.io.File;
import java.net.URL;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public class RequestLogImpl extends ContextBase implements RequestLog, AppenderAttachable<IAccessEvent>, FilterAttachable<IAccessEvent> {
    public final static String DEFAULT_CONFIG_FILE = "etc" + File.separatorChar + "logback-access.xml";

    AppenderAttachableImpl<IAccessEvent> aai = new AppenderAttachableImpl<IAccessEvent>();
    FilterAttachableImpl<IAccessEvent> fai = new FilterAttachableImpl<IAccessEvent>();
    String fileName;
    String resource;
    boolean started = false;
    boolean quiet = false;

    public RequestLogImpl() {
        putObject(CoreConstants.EVALUATOR_MAP, new HashMap<String, EventEvaluator<?>>());
    }

    @Override
    public void log(Request jettyRequest, Response jettyResponse) {
        String token = jettyRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (token == null) {
            token = jettyRequest.getParameter(HttpHeaders.AUTHORIZATION);
        }
        try {
            if (token == null) {
                return;
            }
            //解析token
            SignedJWT jwt = SignedJWT.parse(token.substring(6).trim());
            String userid = jwt.getJWTClaimsSet().getSubject();
            String appid = (String) jwt.getJWTClaimsSet().getClaim(Config._APPID);
            App app = Para.getDAO().read(App.id(appid));
            if (app != null){
                //获取请求用户名
                User user = Para.getDAO().read(app.getAppIdentifier(), userid);
                jettyRequest.setAttribute("usermgr", user.getEmail());
                JettyServerAdapter adapter = new JettyServerAdapter(jettyRequest, jettyResponse);
                AccessEvent accessEvent = new AccessEvent(jettyRequest, jettyResponse, adapter);
                //获取请求所消耗的毫秒数
                jettyRequest.setAttribute("spendTime", accessEvent.getElapsedTime());
                if (getFilterChainDecision(accessEvent) == FilterReply.DENY) {
                    return;
                }
                aai.appendLoopOnAppenders(accessEvent);
            }
        } catch (ParseException e) {
        }
    }

    private void addInfo(String msg) {
        getStatusManager().add(new InfoStatus(msg, this));
    }

    private void addError(String msg) {
        getStatusManager().add(new ErrorStatus(msg, this));
    }

    @Override
    public void start() {
        configure();
        if (!isQuiet()) {
            StatusPrinter.print(getStatusManager());
        }
        started = true;
    }

    protected void configure() {
        URL configURL = getConfigurationFileURL();
        if (configURL != null) {
            runJoranOnFile(configURL);
        } else {
            addError("Could not find configuration file for logback-access");
        }
    }

    protected URL getConfigurationFileURL() {
        if (fileName != null) {
            addInfo("Will use configuration file [" + fileName + "]");
            File file = new File(fileName);
            if (!file.exists())
                return null;
            return FileUtil.fileToURL(file);
        }
        if (resource != null) {
            addInfo("Will use configuration resource [" + resource + "]");
            return this.getClass().getResource(resource);
        }

        String jettyHomeProperty = OptionHelper.getSystemProperty("jetty.home");
        String defaultConfigFile = DEFAULT_CONFIG_FILE;
        if (!OptionHelper.isEmpty(jettyHomeProperty)) {
            defaultConfigFile = jettyHomeProperty + File.separatorChar + DEFAULT_CONFIG_FILE;
        } else {
            addInfo("[jetty.home] system property not set.");
        }
        File file = new File(defaultConfigFile);
        addInfo("Assuming default configuration file [" + defaultConfigFile + "]");
        if (!file.exists())
            return null;
        return FileUtil.fileToURL(file);
    }

    private void runJoranOnFile(URL configURL) {
        try {
            JoranConfigurator jc = new JoranConfigurator();
            jc.setContext(this);
            jc.doConfigure(configURL);
            if (getName() == null) {
                setName("LogbackRequestLog");
            }
        } catch (JoranException e) {
            // errors have been registered as status messages
        }
    }

    @Override
    public void stop() {
        aai.detachAndStopAllAppenders();
        started = false;
    }

    public boolean isRunning() {
        return started;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public boolean isStarted() {
        return started;
    }

    public boolean isStarting() {
        return false;
    }

    public boolean isStopping() {
        return false;
    }

    public boolean isStopped() {
        return !started;
    }

    public boolean isFailed() {
        return false;
    }

    public boolean isQuiet() {
        return quiet;
    }

    public void setQuiet(boolean quiet) {
        this.quiet = quiet;
    }

    @Override
    public void addAppender(Appender<IAccessEvent> newAppender) {
        aai.addAppender(newAppender);
    }

    @Override
    public Iterator<Appender<IAccessEvent>> iteratorForAppenders() {
        return aai.iteratorForAppenders();
    }

    @Override
    public Appender<IAccessEvent> getAppender(String name) {
        return aai.getAppender(name);
    }

    @Override
    public boolean isAttached(Appender<IAccessEvent> appender) {
        return aai.isAttached(appender);
    }

    @Override
    public void detachAndStopAllAppenders() {
        aai.detachAndStopAllAppenders();
    }

    @Override
    public boolean detachAppender(Appender<IAccessEvent> appender) {
        return aai.detachAppender(appender);
    }

    @Override
    public boolean detachAppender(String name) {
        return aai.detachAppender(name);
    }

    @Override
    public void addFilter(Filter<IAccessEvent> newFilter) {
        fai.addFilter(newFilter);
    }

    @Override
    public void clearAllFilters() {
        fai.clearAllFilters();
    }

    @Override
    public List<Filter<IAccessEvent>> getCopyOfAttachedFiltersList() {
        return fai.getCopyOfAttachedFiltersList();
    }

    @Override
    public FilterReply getFilterChainDecision(IAccessEvent event) {
        return fai.getFilterChainDecision(event);
    }

}
