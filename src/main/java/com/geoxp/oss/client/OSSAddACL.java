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

package com.geoxp.oss.client;

import java.util.Arrays;

public class OSSAddACL {
  public static void main(String[] args) throws Exception {
    
    if (args.length < 3) {
      System.err.println("Usage: OSSAddACL OSS_URL SECRET_NAME LIST_OF_SSH_FINGERPRINTS_TO_ADD [SSH_SIGNING_KEY_FINGERPRINT]");
      System.exit(1);
    }

    String[] fingerprints = args[2].split(",");
    
    String sshkey = args.length > 3 ? ("".equals(args[3]) ? null : args[3]) : null;
    OSSClient.addACL(args[0], sshkey, args[1], Arrays.asList(fingerprints));    
  }
}
