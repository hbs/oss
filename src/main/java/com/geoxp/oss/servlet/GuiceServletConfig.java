/*
 * Copyright 2012-2013 Mathias Herberts 
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

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
    // Read parameters, from system properties then as a fall back from context parameters
    //
    
    String maxsecretsize = System.getProperty(OSS.CONTEXT_PARAM_OSS_MAX_SECRET_SIZE);
    OSS.setMaxSecretSize(null != maxsecretsize ? maxsecretsize : servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_MAX_SECRET_SIZE));
    
    String maxtokenage = System.getProperty(OSS.CONTEXT_PARAM_OSS_TOKEN_TTL);
    OSS.setMaxTokenAge(null != maxtokenage ? maxtokenage : servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_TOKEN_TTL));

    String gensecretsshkeys = System.getProperty(OSS.CONTEXT_PARAM_OSS_GENSECRET_SSHKEYS);
    OSS.setGenSecretSSHKeys(null != gensecretsshkeys ? gensecretsshkeys : servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_GENSECRET_SSHKEYS));

    String putsecretsshkeys = System.getProperty(OSS.CONTEXT_PARAM_OSS_PUTSECRET_SSHKEYS);
    OSS.setPutSecretSSHKeys(null != putsecretsshkeys ? putsecretsshkeys : servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_PUTSECRET_SSHKEYS));

    String initsshkeys = System.getProperty(OSS.CONTEXT_PARAM_OSS_INIT_SSHKEYS);
    OSS.setInitSSHKeys(null != initsshkeys ? initsshkeys : servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_INIT_SSHKEYS));

    String keystoredir = System.getProperty(OSS.CONTEXT_PARAM_OSS_KEYSTORE_DIR);
    OSS.setKeyStoreDirectory(null != keystoredir ? keystoredir : servletContextEvent.getServletContext().getInitParameter(OSS.CONTEXT_PARAM_OSS_KEYSTORE_DIR));
    
    super.contextInitialized(servletContextEvent);
  }
  
  @Override
  protected Injector getInjector() {
    return Guice.createInjector(new GuiceServletModule());
  }
}
