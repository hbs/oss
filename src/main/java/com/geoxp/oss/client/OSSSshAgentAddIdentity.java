package com.geoxp.oss.client;

import java.io.*;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.openssl.EncryptionException;
import org.bouncycastle.openssl.PasswordFinder;

import com.geoxp.oss.CryptoHelper;
import com.geoxp.oss.CryptoHelper.SSHAgentClient;
import com.geoxp.oss.CryptoHelper.SSHAgentClient.SSHKey;

public class OSSSshAgentAddIdentity {
  private static class DefaultPasswordFinder implements PasswordFinder {

    private final char[] password;

    private DefaultPasswordFinder(char [] password) {
      this.password = password;
    }

    @Override
    public char[] getPassword() {
      return Arrays.copyOf(password, password.length);
    }
  } 
  
  final static String[] SSH_DEFAULT_KEY_FILENAMES = {"id_dsa", "id_rsa" };

  private static List<File> getDefaultsKeyFiles() {
    String sshDir = System.getProperty("user.home") + File.separator + ".ssh";
    ArrayList<File> result = new ArrayList<File>();

    for (String sshKeyFilename : SSH_DEFAULT_KEY_FILENAMES) {
      File file = new File(sshDir, sshKeyFilename);
      if (file.canRead()) {
        result.add(file);
      }
    }

    return result;		
  }

  /**
   * @param args
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      System.err.println("Usage: OSSLoadAgent OSS_URL SECRET_NAME AGENT_AUTH_SOCK WRAPPED_PASSPHRASE [ProviderEmbedded default false] [KEY_FILE]");
      System.exit(1);
    }

    SSHAgentClient sshAgent = new SSHAgentClient(args[2]);

    System.out.println("Unwrap secret");
    // Get the secret from OSS
    // FIXME ? Provide a way to specify the ssh signing key fingerprint
    byte[] secret = OSSClient.getSecret(args[0], args[1], null);
    // Use the secret to unwrap the passphrase
    byte[] unwrap = CryptoHelper.unwrapBlob(secret, Hex.decode(args[3]));
    String password = new String(unwrap, "UTF-8");

    boolean providerEmbedded = false;

    // Read private keys
    // openssh store it in PEM format
    List<File> sshKeyFiles = new ArrayList<File>(1);

    for (int i=4; i<args.length; i++) {
      if ("ProviderEmbedded".equals(args[i])) {
        providerEmbedded = true;
      } else {
        sshKeyFiles.add(new File(args[i]));
      }
    }

    // not key founded take the default keyFiles
    if (sshKeyFiles.size() == 0){
      sshKeyFiles = getDefaultsKeyFiles();
    }

    for (File sshKeyFile : sshKeyFiles) {
      Reader fRd = new BufferedReader(new FileReader(sshKeyFile));

      if (providerEmbedded) {
        // load with embedded provider
        System.out.println("Load PEM file " + sshKeyFile.getName() + " with embedded provider"  );
        BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
        com.geoxp.oss.client.bouncycastle.openssl.PEMReader pem = new com.geoxp.oss.client.bouncycastle.openssl.PEMReader(fRd, new DefaultPasswordFinder(password.toCharArray()), bouncyCastleProvider);
        Object o;
        try {
          while ((o = pem.readObject()) != null) {
            if (o instanceof KeyPair) {
              loadKeyPair((KeyPair) o, sshKeyFile, sshAgent);
            }
          }
        } catch (EncryptionException ee) {
          System.err.println("Can't read private key in " + sshKeyFile.getAbsolutePath());
          ee.printStackTrace();
        } finally {
          pem.close();
        }
      } else {
        // load with signed javax security provider
        System.out.println("Load PEM file " + sshKeyFile.getName() + " with JCE provider"  );
        org.bouncycastle.openssl.PEMReader pem = new org.bouncycastle.openssl.PEMReader(fRd, new DefaultPasswordFinder(password.toCharArray()), "BC");
        Object o;
        try {
          while ((o = pem.readObject()) != null) {
            if (o instanceof KeyPair) {
              loadKeyPair((KeyPair) o, sshKeyFile, sshAgent);
            }
          }
        } catch (EncryptionException ee) {
          System.err.println("Can't read private key in " + sshKeyFile.getAbsolutePath());
          ee.printStackTrace();
        } finally {
          pem.close();
        }
      }
    }

    System.out.println("Keys in agent:");

    List<SSHKey> identities = sshAgent.requestIdentities();
    for (SSHKey identity : identities) {
      System.out.println(identity);
    }
  }

  private static void loadKeyPair(KeyPair kp, File sshKeyFile, SSHAgentClient sshAgent) {
    // Add the identity in the ssh-agent
    try {
      byte[] keyblob = CryptoHelper.sshPrivateKeyBlobFromKeyPair(kp);
      System.out.println("Loading " + sshKeyFile.getPath());
      sshAgent.addIdentity(keyblob, sshKeyFile.getPath());
    } catch (IOException e) {
      System.err.println("Can't read private key in " + sshKeyFile.getAbsolutePath());
      e.printStackTrace();
    }
  }
}
