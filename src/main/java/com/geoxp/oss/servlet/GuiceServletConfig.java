package com.geoxp.oss.servlet;

import javax.servlet.ServletContextEvent;

import com.geoxp.oss.OSS;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.GuiceServletContextListener;

public class GuiceServletConfig extends GuiceServletContextListener {
  
  @Override
  public void contextInitialized(ServletContextEvent servletContextEvent) {
    
    //
    // Read context parameters
    //
    
    OSS.setMaxTokenAge(servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_TOKEN_TTL));
    OSS.setGenSecretSSHKeys(servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_GENSECRET_SSHKEYS));
    OSS.setInitSSHKeys(servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_INIT_SSHKEYS));
    OSS.setKeyStoreDirectory(servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_KEYSTORE_DIR));
    
    super.contextInitialized(servletContextEvent);
  }
  
  @Override
  protected Injector getInjector() {
    return Guice.createInjector(new GuiceServletModule());
  }
}
