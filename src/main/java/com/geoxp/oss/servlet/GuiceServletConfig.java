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
