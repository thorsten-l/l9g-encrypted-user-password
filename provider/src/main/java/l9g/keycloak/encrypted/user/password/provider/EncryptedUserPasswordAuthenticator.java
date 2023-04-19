package l9g.keycloak.encrypted.user.password.provider;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.crypto.Cipher;
import javax.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class EncryptedUserPasswordAuthenticator implements Authenticator
{
  private final static Logger LOGGER = Logger.getLogger(
    EncryptedUserPasswordAuthenticator.class);

  private final static String PUBLIC_KEY_FILENAME = "l9g-encrypted-user-password-server.publickey";

  private final static String USER_ATTRIBUTE_NAME = "ENCRYPTED_USER_PASSWORD";
  
  private final static String[] CONFIG_DIRS =
  {
    ".", "providers", "/opt/keycloak/providers"
  };

  private static PublicKey publicKey;

  static
  {
    File publicKeyFile = null;
    boolean fileExists = false;

    for (int i = 0; i < CONFIG_DIRS.length && !fileExists; i++)
    {
      publicKeyFile = new File(CONFIG_DIRS[i], PUBLIC_KEY_FILENAME);
      fileExists = publicKeyFile.exists() && publicKeyFile.canRead();
    }

    if (publicKeyFile != null && fileExists)
    {
      LOGGER.
        info("Loading public key file : " + publicKeyFile.getAbsolutePath());
      try (FileInputStream fis = new FileInputStream(publicKeyFile))
      {
        byte[] publicKeyBytes = new byte[fis.available()];
        fis.read(publicKeyBytes);
        fis.close();
        X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
        publicKey = keyFactory.generatePublic(spec);
      }
      catch (Exception ex)
      {
        LOGGER.error(ex);
      }
    }
    else
    {
      LOGGER.error("No public key file found! <" + PUBLIC_KEY_FILENAME + ">");
    }
  }

  @Override
  public void authenticate(AuthenticationFlowContext context)
  {
    MultivaluedMap<String, String> formData = context.getHttpRequest().
      getDecodedFormParameters();

    String plainPassword = null;

    for (String key : formData.keySet())
    {
      if ("password".equals(key))
      {
        plainPassword = ((List<String>) formData.get(key)).get(0);
        break;
      }
    }

    if (publicKey != null && plainPassword != null && plainPassword.length() > 0)
    {
      try
      {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedMessage = cipher.doFinal(plainPassword.getBytes());

        String encryptedPassword
          = Base64.getEncoder().encodeToString(encryptedMessage);

        ArrayList<String> pwd = new ArrayList<>();
        pwd.add(encryptedPassword);
        
        UserModel userModel = context.getUser();
        userModel.setAttribute(USER_ATTRIBUTE_NAME, pwd);
        userModel.getAttributes().put(USER_ATTRIBUTE_NAME, pwd);
      }
      catch (Exception ex)
      {
        LOGGER.error(ex);
      }
    }

    context.success();
  }

  @Override
  public void action(AuthenticationFlowContext context)
  {
    context.success();
  }

  @Override
  public void close()
  {
  }

  @Override
  public boolean requiresUser()
  {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession ks, RealmModel rm, UserModel um)
  {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession ks, RealmModel rm, UserModel um)
  {
  }
}
