package com.erudika.para.utils;

import ch.qos.logback.access.jetty.JettyServerAdapter;
import ch.qos.logback.access.jetty.RequestLogImpl;
import ch.qos.logback.access.spi.IAccessEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.spi.FilterReply;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;

import java.util.Iterator;

public class JwtRequestLogImpl extends RequestLogImpl {
    @Override
    public void log(Request jettyRequest, Response jettyResponse) {
        JettyServerAdapter adapter = new JettyServerAdapter(jettyRequest, jettyResponse);
        IAccessEvent accessEvent = new JwtAccessEvent(jettyRequest, jettyResponse, adapter);
        if (getFilterChainDecision(accessEvent) == FilterReply.DENY) {
            return;
        }

        Iterator<Appender<IAccessEvent>> ai = iteratorForAppenders();
        while (ai.hasNext()) {
            Appender<IAccessEvent> appender = ai.next();
            appender.doAppend(accessEvent);
        }
    }
}
