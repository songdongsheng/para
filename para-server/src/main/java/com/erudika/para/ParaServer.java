/*
 * Copyright 2013-2017 Erudika. https://erudika.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For issues and patches go to: https://github.com/erudika
 */
package com.erudika.para;

import ch.qos.logback.access.jetty.RequestLogImpl;
import com.erudika.para.aop.AOPModule;
import com.erudika.para.cache.CacheModule;
import com.erudika.para.core.utils.CoreUtils;
import com.erudika.para.email.EmailModule;
import com.erudika.para.i18n.I18nModule;
import com.erudika.para.iot.IoTModule;
import com.erudika.para.persistence.PersistenceModule;
import com.erudika.para.queue.QueueModule;
import com.erudika.para.rest.Api1;
import com.erudika.para.search.SearchModule;
import com.erudika.para.security.SecurityModule;
import com.erudika.para.storage.StorageModule;
import com.erudika.para.utils.Config;
import com.erudika.para.utils.JwtRequestLogImpl;
import com.erudika.para.utils.filters.CORSFilter;
import com.erudika.para.utils.filters.ErrorFilter;
import com.google.inject.Module;
import org.apache.commons.lang3.math.NumberUtils;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.glassfish.jersey.servlet.ServletContainer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.Banner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.builder.ParentContextApplicationContextInitializer;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.embedded.AnnotationConfigEmbeddedWebApplicationContext;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.jetty.JettyEmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.jetty.JettyServerCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.support.ServletContextApplicationContextInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.PreDestroy;
import javax.servlet.Servlet;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletException;
import java.util.ServiceLoader;

/**
 * Para modules are initialized and destroyed from here.
 *
 * @author Alex Bogdanovski [alex@erudika.com]
 */
@Configuration
@ComponentScan
public class ParaServer implements WebApplicationInitializer, Ordered {

	private static final Logger logger = LoggerFactory.getLogger(ParaServer.class);

	/**
	 * Returns the list of core modules.
	 * @return the core modules
	 */
	public static Module[] getCoreModules() {
		return new Module[] {
			new PersistenceModule(),
			new SearchModule(),
			new CacheModule(),
			new AOPModule(),
			new IoTModule(),
			new EmailModule(),
			new I18nModule(),
			new QueueModule(),
			new StorageModule(),
			new SecurityModule()
		};
	}

	@Override
	public int getOrder() {
		return 1;
	}

	/**
	 * @return API servlet bean
	 */
	@Bean
	public ServletRegistrationBean apiV1RegistrationBean() {
		String path = Api1.PATH + "*";
		ServletRegistrationBean reg = new ServletRegistrationBean(new ServletContainer(new Api1()), path);
		logger.debug("Initializing Para API v1 [{}]...", path);
		reg.setName(Api1.class.getSimpleName());
		reg.setAsyncSupported(true);
		reg.setEnabled(true);
		reg.setOrder(3);
		return reg;
	}

	/**
	 * @return CORS filter bean
	 */
	@Bean
	public FilterRegistrationBean corsFilterRegistrationBean() {
		String path = Api1.PATH + "*";
		logger.debug("Initializing CORS filter [{}]...", path);
		FilterRegistrationBean frb = new FilterRegistrationBean(new CORSFilter());
		frb.addInitParameter("cors.support.credentials", "true");
		frb.addInitParameter("cors.allowed.methods", "GET,POST,PATCH,PUT,DELETE,HEAD,OPTIONS");
		frb.addInitParameter("cors.exposed.headers", "Cache-Control,Content-Length,Content-Type,Date,ETag,Expires");
		frb.addInitParameter("cors.allowed.headers", "Origin,Accept,X-Requested-With,Content-Type,"
				+ "Access-Control-Request-Method,Access-Control-Request-Headers,X-Amz-Credential,"
				+ "X-Amz-Date,Authorization");
//		frb.addUrlPatterns(path, "/" + JWTRestfulAuthFilter.JWT_ACTION);
		frb.addUrlPatterns("/*");
		frb.setAsyncSupported(true);
		frb.setEnabled(Config.CORS_ENABLED);
		frb.setMatchAfter(false);
		frb.setOrder(2);
		return frb;
	}

	/**
	 * @return Jetty config bean
	 */
	@Bean
	public EmbeddedServletContainerFactory jettyConfigBean() {
		JettyEmbeddedServletContainerFactory jef = new JettyEmbeddedServletContainerFactory();
		jef.addServerCustomizers(new JettyServerCustomizer() {
			public void customize(Server server) {
				if (Config.GZIP_ENABLED) {
					GzipHandler gzipHandler = new GzipHandler();
					gzipHandler.setMinGzipSize(128);
					gzipHandler.addIncludedMimeTypes("application/json");
					gzipHandler.addIncludedMethods("GET", "POST", "PATCH", "PUT");
					gzipHandler.setHandler(server.getHandler());
					server.setHandler(gzipHandler);
				}

				if (Config.getConfigBoolean("access_log_enabled", true)) {
					// enable access log via Logback
					HandlerCollection handlers = new HandlerCollection();
					for (Handler handler : server.getHandlers()) {
						handlers.addHandler(handler);
					}
					RequestLogHandler reqLogs = new RequestLogHandler();
					reqLogs.setServer(server);
					RequestLogImpl rli = new JwtRequestLogImpl();
					rli.setResource("/logback-access.xml");
					rli.setQuiet(true);
					rli.start();
					reqLogs.setRequestLog(rli);
					handlers.addHandler(reqLogs);
					server.setHandler(handlers);
				}

				for (Connector y : server.getConnectors()) {
					for (ConnectionFactory cf : y.getConnectionFactories()) {
						if (cf instanceof HttpConnectionFactory) {
							HttpConnectionFactory dcf = (HttpConnectionFactory) cf;
							// support for X-Forwarded-Proto
							// redirect back to https if original request uses it
							if (Config.IN_PRODUCTION) {
								HttpConfiguration httpConfiguration = dcf.getHttpConfiguration();
								httpConfiguration.addCustomizer(new ForwardedRequestCustomizer());
							}
							// Disable Jetty version header
							dcf.getHttpConfiguration().setSendServerVersion(false);
						}
					}
				}
			}
		});
		int defaultPort = NumberUtils.toInt(System.getProperty("jetty.http.port", "8080"));
		jef.setPort(NumberUtils.toInt(System.getProperty("server.port"), defaultPort));
		logger.info("Listening on port {}...", jef.getPort());
		return jef;
	}

	@Bean
	public ServletRegistrationBean UserRegistrationServletRegistrationBean() {
		String[] classNameList = new String[] {
				"cn.abrain.api.usermgr.UserRegistrationServlet",
				"cn.abrain.api.usermgr.servlet.UserRegistrationServlet"};

		ServiceLoader<Servlet> loader = ServiceLoader.load(Servlet.class, Para.getParaClassLoader());
		for (Servlet servlet : loader) {
			for (String className: classNameList) {
				if (servlet != null && servlet.getClass().getName().equals(className)) {
					return new ServletRegistrationBean(servlet, "/register/*");
				}
			}
		}
		throw new RuntimeException("UserRegistrationServlet not found");
	}
	@Bean
	public ServletRegistrationBean UserTestRegistrationServletRegistrationBean() {
		String[] classNameList = new String[] {"cn.abrain.api.ldc.order.servlet.UserTrialRegistrationServlet"};
		ServiceLoader<Servlet> loader = ServiceLoader.load(Servlet.class, Para.getParaClassLoader());
		for (Servlet servlet : loader) {
			for (String className: classNameList) {
				if (servlet != null && servlet.getClass().getName().equals(className)) {
					return new ServletRegistrationBean(servlet, "/trialRegister/*");
				}
			}
		}
		throw new RuntimeException("UserTrialRegistrationServlet not found");
	}
	@Bean
	public ServletRegistrationBean UserResetServletRegistrationBean() {
		String[] classNameList = new String[] {
				"cn.abrain.api.usermgr.UserReSetServlet",
				"cn.abrain.api.usermgr.servlet.UserReSetServlet" };

		ServiceLoader<Servlet> loader = ServiceLoader.load(Servlet.class, Para.getParaClassLoader());
		for (Servlet servlet : loader) {
			for (String className: classNameList) {
				if (servlet != null && servlet.getClass().getName().equals(className)) {
					return new ServletRegistrationBean(servlet, "/reset/*");
				}
			}
		}
		throw new RuntimeException("UserReSetServlet not found");
	}
	@Bean
	public ServletRegistrationBean UserLoginServletRegistrationBean() {
		String[] classNameList = new String[] {
				"cn.abrain.api.usermgr.UserLoginServlet",
				"cn.abrain.api.usermgr.servlet.UserLoginServlet" };

		ServiceLoader<Servlet> loader = ServiceLoader.load(Servlet.class, Para.getParaClassLoader());
		for (Servlet servlet : loader) {
			for (String className: classNameList) {
				if (servlet != null && servlet.getClass().getName().equals(className)) {
					return new ServletRegistrationBean(servlet, "/check/*");
				}
			}
		}
		throw new RuntimeException("UserLoginServlet not found");
	}
    @Bean
    public ServletRegistrationBean UserActiveServletRegistrationBean() {
        String[] classNameList = new String[] {
                "cn.abrain.api.usermgr.UserActiveServlet",
                "cn.abrain.api.usermgr.servlet.UserActiveServlet" };

        ServiceLoader<Servlet> loader = ServiceLoader.load(Servlet.class, Para.getParaClassLoader());
        for (Servlet servlet : loader) {
            for (String className: classNameList) {
                if (servlet != null && servlet.getClass().getName().equals(className)) {
                    return new ServletRegistrationBean(servlet, "/active/*");
                }
            }
        }
        throw new RuntimeException("UserActiveServlet not found");
    }

	/**
	 * Called before shutdown.
	 */
	@PreDestroy
	public void preDestroy() {
		Para.destroy();
	}

	@Override
	public void onStartup(ServletContext sc) throws ServletException {
		runAsWAR(sc, ParaServer.class);
	}

	/**
	 * This is the initializing method when running ParaServer as WAR,
	 * deployed to a servlet container.
	 * @param sc the ServletContext instance
	 * @param sources the application classes that will be scanned
	 * @return the application context
	 */
	protected static WebApplicationContext runAsWAR(ServletContext sc, Object... sources) {
		ApplicationContext parent = null;
		Object object = sc.getAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE);
		if (object instanceof ApplicationContext) {
			logger.info("Root context already created (using as parent).");
			parent = (ApplicationContext) object;
			sc.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, null);
		}
		SpringApplicationBuilder application = new SpringApplicationBuilder(sources);
		if (parent != null) {
			application.initializers(new ParentContextApplicationContextInitializer(parent));
		}
		application.initializers(new ServletContextApplicationContextInitializer(sc));
		application.contextClass(AnnotationConfigEmbeddedWebApplicationContext.class);

		// entry point (WAR)
		application.profiles(Config.ENVIRONMENT);
		application.web(true);
		application.bannerMode(Banner.Mode.OFF);
		Para.addInitListener(CoreUtils.getInstance());
		Para.initialize(getCoreModules());
		// Ensure error pages are registered
		application.sources(ErrorFilter.class);

		WebApplicationContext rootAppContext = (WebApplicationContext) application.run();

		if (rootAppContext != null) {
			sc.addListener(new ContextLoaderListener(rootAppContext) {
				@Override
				public void contextInitialized(ServletContextEvent event) {
					// no-op because the application context is already initialized
				}
			});
			sc.getSessionCookieConfig().setName("sess");
			sc.getSessionCookieConfig().setMaxAge(1);
			sc.getSessionCookieConfig().setHttpOnly(true);
			sc.setInitParameter("org.eclipse.jetty.servlet.Default.dirAllowed", "false");
		}
		return rootAppContext;
	}

	/**
	 * This is the initializing method when running ParaServer as executable JAR (or WAR),
	 * from the command line: java -jar para.jar.
	 * @param args command line arguments array (same as those in {@code void main(String[] args)} )
	 * @param sources the application classes that will be scanned
	 */
	protected static void runAsJAR(String[] args, Object... sources) {
		// entry point (JAR)
		SpringApplication app = new SpringApplication(sources);
		app.setAdditionalProfiles(Config.ENVIRONMENT);
		app.setWebEnvironment(true);
		app.setBannerMode(Banner.Mode.OFF);
		Para.addInitListener(CoreUtils.getInstance());
		Para.initialize(getCoreModules());
		app.run(args);
	}

	/**
	 * Para starts from here.
	 * @param args args
	 */
	public static void main(String[] args) {
		runAsJAR(args, ParaServer.class);
	}
}
