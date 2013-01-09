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

package com.geoxp.oss.pig;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import org.apache.pig.EvalFunc;
import org.apache.pig.data.DataByteArray;
import org.apache.pig.data.Tuple;
import org.apache.pig.impl.logicalLayer.schema.Schema;
import org.apache.pig.impl.util.UDFContext;
import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.data.ACL;
import org.bouncycastle.util.encoders.Base64;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.OSSException;
import com.geoxp.oss.client.OSSClient;

public class PigSecretStore extends EvalFunc<Object> {
  
  /**  
   * Name of property containaing the name of the file storing the first halves of the secrets
   */
  private static String PSS_FILE = "pss.file";
  
  /**
   * Name of system property containing the OSS URL
   */
  public static final String PSS_OSS_URL = "pss.oss.url";
  
  /**
   * Fingerprint of SSH key to use for secret retrieval
   */
  public static final String PSS_OSS_SSHKEY = "pss.oss.sshkey";
  
  /**
   * ZooKeeper quorum
   */
  public static final String PSS_ZK_QUORUM = "pss.zk.quorum";
  
  /**
   * ZooKeeper root
   */
  public static final String PSS_ZK_ROOT = "pss.zk.root";
  
  /**
   * Secrets managed by PigSecretStore
   */
  private static final Map<String,byte[]> secrets = new HashMap<String, byte[]>();
  
  public PigSecretStore(String... args) {
    //
    // If PSS_FILE is null, attempt to read it from UDFContext
    //
    
    synchronized(secrets) {      
      if (secrets.isEmpty()) {
        Properties props = UDFContext.getUDFContext().getUDFProperties(PigSecretStore.class);
        
        //
        // If props contains a key PSS_FILE, we are executing on the backend
        //
        
        if (props.containsKey(PSS_FILE)) {
          
          //
          // We're on the backend
          //
          
          //
          // Open PSS_File
          //
          
          try {
            //
            // Retrieve one half of the secrets
            //
            
            InputStream pssis = PigSecretStore.class.getClassLoader().getResourceAsStream(props.getProperty(PSS_FILE));
            BufferedReader br = new BufferedReader(new InputStreamReader(pssis));
            
            //
            // Read zknode
            //
            
            String zknode = br.readLine();
            
            //
            // Read all secret halves
            //
            
            while(true) {
              String line = br.readLine();
              
              if (null == line) {
                break;
              }
              
              String[] tokens = line.split(" ");
              
              if (2 != tokens.length) {
                throw new RuntimeException("Invalid PSS_FILE content.");
              }
              
              secrets.put(tokens[0], Base64.decode(tokens[1].getBytes("UTF-8")));
            }
            
            br.close();
            
            //
            // Read ZooKeeper to retrieve second half of secrets
            //
            
            ZooKeeper zk = new ZooKeeper(UDFContext.getUDFContext().getClientSystemProps().getProperty(PSS_ZK_QUORUM), 5000, null);
            String zkdata = new String(zk.getData(zknode, false, null), "UTF-8");
            zk.close();
            
            br = new BufferedReader(new StringReader(zkdata));
            
            //
            // Read all secret halves
            //
            
            while(true) {
              String line = br.readLine();
              
              if (null == line) {
                break;
              }
              
              String[] tokens = line.split(" ");
              
              if (2 != tokens.length) {
                throw new RuntimeException("Invalid PSS_FILE content.");
              }

              byte[] otp = Base64.decode(tokens[1].getBytes("UTF-8"));
              
              //
              // Apply XOR
              //
              
              for (int i = 0; i < otp.length; i++) {
                secrets.get(tokens[0])[i] = (byte) (secrets.get(tokens[0])[i] ^ otp[i]);
              }
            }            
            br.close();            
          } catch (InterruptedException ie) {
            throw new RuntimeException(ie);
          } catch (KeeperException ke) {
            throw new RuntimeException(ke);
          } catch (IOException ioe) {
            throw new RuntimeException(ioe);
          }          
        } else {
          
          //
          // We're on the frontend
          //

          //
          // File is the first argument
          //          
          props.setProperty(PSS_FILE, args[0]);
          
          List<String> secrets = Arrays.asList(args).subList(1, args.length);
          
          try {
            //
            // StringBuilder for ZK content
            //
            
            StringBuilder sb = new StringBuilder();
            
            String uuid = UUID.randomUUID().toString();
            String zknode = System.getProperty(PSS_ZK_ROOT) + "/" + uuid;  
            
            //
            // Open PSS_FILE for writing
            //            
            PrintWriter pw = new PrintWriter(args[0], "UTF-8");

            // Write zknode first
            
            pw.println(zknode);
            
            //
            // Attempt to retrieve each listed secret from OSS and split them in two
            // halves using a OTP
            //
            
            for (String secretname: secrets) {
              byte[] secret = OSSClient.getSecret(System.getProperty(PSS_OSS_URL), secretname, System.getProperty(PSS_OSS_SSHKEY));
                
              //
              // Generate OTP
              //
                
              byte[] otp = new byte[secret.length];
              CryptoHelper.getSecureRandom().nextBytes(otp);
                
              //
              // Do an XOR between secret and OTP
              //
                
              for (int i = 0; i < secret.length; i++) {
                secret[i] = (byte) (secret[i] ^ otp[i]);
              }
              
              //
              // Output first half to file, second to sb for ZK
              //
              
              pw.print(secretname);
              pw.print(" ");
              pw.println(new String(Base64.encode(secret), "UTF-8"));
              
              sb.append(secretname);
              sb.append(" ");
              sb.append(new String(Base64.encode(otp), "UTF-8"));
              sb.append("\n");
            }
            
            pw.close();
            
            //
            // Write zookeeper content
            //
            
            ZooKeeper zk = new ZooKeeper(System.getProperty(PSS_ZK_QUORUM), 5000, null);
            
            List<ACL> acls = new ArrayList<ACL>();
            acls.add(new ACL(ZooDefs.Perms.ALL, ZooDefs.Ids.ANYONE_ID_UNSAFE));
            zk.create(zknode, sb.toString().getBytes("UTF-8"), acls, CreateMode.EPHEMERAL);
          } catch (InterruptedException ie) {
            throw new RuntimeException(ie);
          } catch (KeeperException ke) {
            throw new RuntimeException(ke);
          } catch (IOException ioe) {
            throw new RuntimeException(ioe);
          } catch (OSSException osse) {
            throw new RuntimeException(osse);
          }
        }
      }      
    }
  }
  
  @Override
  public Object exec(Tuple input) throws IOException {
    //
    // If UDF is called with one parameter, it's simply a wrapper that does nothing.
    // Otherwise UDF performs unwrapping of the bytearray (2nd member of tuple)
    // using the secret whose name is the first member of the input tuple.
    //
    
    if (1 == input.size()) {
      return input.get(0);
    } else if (2 == input.size()) {
      return new DataByteArray(CryptoHelper.unwrapBlob(getSecret((String) input.get(0)), ((DataByteArray) input.get(1)).get()));
    } else {
      throw new IOException("Invalid input Tuple size, may be 1 or 2.");
    }
  }

  @Override
  public Schema outputSchema(Schema input) {
    return input;
  }
  
  public static byte[] getSecret(String name) {
    return secrets.get(name).clone();
  }
}
