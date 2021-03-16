package com.example.ecslogger.config;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Scope;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.stereotype.Component;

import com.example.ecslogger.enumeration.LogEvents;

@Component
@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE) // More overhead but workaround for the singleton
public class AuthenticationEventListener implements ApplicationListener<AbstractAuthenticationEvent> {

	private static Logger logger = LoggerFactory.getLogger(AuthenticationEventListener.class);

	@Autowired
	private HttpServletRequest request;

	@Value("${spring.application.name}")
	private String appName;

	@Override
	public void onApplicationEvent(AbstractAuthenticationEvent authenticationEvent) {
		Authentication authentication = authenticationEvent.getAuthentication();
		MDC.put("test", "test");
		MDC.put("app_name", appName);
		MDC.put("user.name", authentication.getName());
		MDC.put("url.full", request.getRequestURI());
		MDC.put("params",
				"{DB_ID=073fc186-4ae2-4fce-a2f2-f353b6d0ddae, OLUSTURAN_KULLANICI=6594fb8c-3272-4201-9789-45ebdcb07d46, AD=test, VERSION=0, GUNCELLEME_ZAMANI=1615795499521, SON_GUNCELLEYEN_KULLANICI=6594fb8c-3272-4201-9789-45ebdcb07d46, SILINDI=false, OLUSMA_ZAMANI=1615795499521}");
		if (request.getHeader("x-forwarded-for") != null) {
			MDC.put("source.ip", request.getHeader("x-forwarded-for"));
		} else {
			MDC.put("source.ip", request.getRemoteAddr());
		}

		// These would be duplicate events in the case of successful logins
		if ((authenticationEvent instanceof InteractiveAuthenticationSuccessEvent)
				|| (authenticationEvent instanceof SessionFixationProtectionEvent)) {
			logger.debug("Authentication event [{}]", authenticationEvent.getClass());
			return;
		}

		if (authentication.isAuthenticated()) {
			MDC.put("event.action", LogEvents.LOGIN_SUCCESS.name());
			logger.info("[{}] logged in successfully", authentication.getName());
		} else {
			MDC.put("event.action", LogEvents.LOGIN_FAILURE.name());
			logger.warn("[{}] failed to log in with password [{}]", authentication.getName(),
					authentication.getCredentials().toString().replaceAll(".", "*"));

			// Simulate a stacktrace
			if (authentication.getName().equals("admin")) {
				throw new RuntimeException("There is no admin here...");
			}
		}

		// Clear MDC data for reuse of the thread
		MDC.clear();

	}

}
