package l9g.keycloak.encrypted.user.password.provider;

import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 *
 * @author Thorsten Ludewig (t.ludewig@gmail.com)
 */
public class EncryptedUserPasswordAuthenticatorFactory implements
  AuthenticatorFactory
{
  private static final Logger LOGGER = Logger.getLogger(
    EncryptedUserPasswordAuthenticatorFactory.class);

  private static final String PROVIDER_ID = "l9g-encrypted-user-password";

  private static final AuthenticationExecutionModel.Requirement[] 
    REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]
  {
    REQUIRED, DISABLED
  };

  @Override
  public String getDisplayType()
  {
    return "L9G Encrypted User Password";
  }

  @Override
  public String getHelpText()
  {
    return "Copy encrypted user password into users attributes. Attribute name is ENCRYPTED_USER_PASSWORD";
  }

  @Override
  public String getReferenceCategory()
  {
    return "Custom";
  }

  @Override
  public boolean isConfigurable()
  {
    return false;
  }

  @Override
  public String getId()
  {
    return PROVIDER_ID;
  }

  @Override
  public Authenticator create(KeycloakSession session)
  {
    LOGGER.debug("create(KeycloakSession session)");
    return new EncryptedUserPasswordAuthenticator();
  }

  @Override
  public void init(Config.Scope scope)
  {
    this.config = config;
  }

  @Override
  public void postInit(KeycloakSessionFactory ksf)
  {
  }

  @Override
  public void close()
  {
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices()
  {
    return REQUIREMENT_CHOICES;
  }

  @Override
  public boolean isUserSetupAllowed()
  {
    return false;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties()
  {
    return null;
  }

  private Config.Scope config;
}
