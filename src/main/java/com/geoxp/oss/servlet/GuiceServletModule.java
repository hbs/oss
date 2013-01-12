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

import com.google.inject.servlet.ServletModule;

public class GuiceServletModule extends ServletModule {
  
  public static final String SERVLET_PATH_INIT = "/Init";
  public static final String SERVLET_PATH_GET_SECRET = "/GetSecret";
  public static final String SERVLET_PATH_GEN_SECRET = "/GenSecret";
  public static final String SERVLET_PATH_PUT_SECRET = "/PutSecret";
  public static final String SERVLET_PATH_GET_OSS_RSA = "/GetOSSRSA";
  public static final String SERVLET_PATH_ADD_ACL = "/AddACL";
  public static final String SERVLET_PATH_GET_ACL = "/GetACL";
  public static final String SERVLET_PATH_REMOVE_ACL = "/RemoveACL";
  
  
  @Override
  protected void configureServlets() {
    serve(SERVLET_PATH_INIT).with(InitServlet.class);
    serve(SERVLET_PATH_GET_SECRET).with(GetSecretServlet.class);
    serve(SERVLET_PATH_PUT_SECRET).with(PutSecretServlet.class);
    serve(SERVLET_PATH_GEN_SECRET).with(GenSecretServlet.class);
    serve(SERVLET_PATH_GET_OSS_RSA).with(GetOSSRSAServlet.class);
    serve(SERVLET_PATH_ADD_ACL).with(AddACLServlet.class);
    serve(SERVLET_PATH_REMOVE_ACL).with(RemoveACLServlet.class);
    serve(SERVLET_PATH_GET_ACL).with(GetACLServlet.class);
  }
}
