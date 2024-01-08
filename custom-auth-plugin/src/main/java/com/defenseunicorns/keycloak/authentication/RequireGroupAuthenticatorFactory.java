package com.defenseunicorns.keycloak.authentication;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class RequireGroupAuthenticatorFactory implements AuthenticatorFactory {

  /**
   * provider id variable.
   */
  public static final String PROVIDER_ID = "require-group-restriction";
  /**
   * group authenticator variable.
   */
  public static final RequireGroupAuthenticator GROUP_AUTHENTICATOR = new RequireGroupAuthenticator();
  /**
   * Configuration declarations.
   */
  public static final String USER_ACTIVE_X509_ATTRIBUTE = "userActive509Attribute";
  public static final String GROUP_PROTECTION_IGNORE_CLIENTS = "groupProtectionIgnoreClients";
  private static final List<ProviderConfigProperty> configProperties;

  static {
    List<String> groupProtectionIgnoreClients = new ArrayList<>();
    groupProtectionIgnoreClients.add("account");
    groupProtectionIgnoreClients.add("account-console");
    groupProtectionIgnoreClients.add("broker");
    groupProtectionIgnoreClients.add("security-admin-console");

    configProperties = ProviderConfigurationBuilder.create()
        .property()
        .name(USER_ACTIVE_X509_ATTRIBUTE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("User X509 Attribute")
        .helpText(
            "Tracks if the current login session is using PKI at all, even if not bound to the user.")
        .defaultValue("activecac")
        .add()
        .property()
        .name(GROUP_PROTECTION_IGNORE_CLIENTS)
        .type(ProviderConfigProperty.TEXT_TYPE)
        .label("Group Protection Ignore Clients")
        .helpText(
            "White-list clients that do not require P1 group protection logic. Comma-separated list of strings.")
        .defaultValue(groupProtectionIgnoreClients)
        .add().
        build();
  }

  /**
   * requirement choices variable.
   */
  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED
  };

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public Authenticator create(final KeycloakSession session) {
    return GROUP_AUTHENTICATOR;
  }

  @Override
  public void init(final Config.Scope scope) {
    // no implementation needed here
  }

  @Override
  public void postInit(final KeycloakSessionFactory keycloakSessionFactory) {
    // no implementation needed here
  }

  @Override
  public void close() {
    // no implementation needed here
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public String getDisplayType() {
    return "Require Group Authentication Validation";
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public String getReferenceCategory() {
    return null;
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public boolean isConfigurable() {
    return true;
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public String getHelpText() {
    return "Enables User to Client Authentication via Groups Membership. ";
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    // no implementation needed here. Just return empty collection
    return configProperties;
  }

}
