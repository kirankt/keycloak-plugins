package com.defenseunicorns.keycloak.authentication;

import static com.defenseunicorns.keycloak.authentication.RequireGroupAuthenticatorFactory.GROUP_PROTECTION_IGNORE_CLIENTS;
import static com.defenseunicorns.keycloak.authentication.RequireGroupAuthenticatorFactory.USER_ACTIVE_X509_ATTRIBUTE;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Simple {@link Authenticator} that checks of a user is member of a given
 * {@link GroupModel Group}.
 */
public class RequireGroupAuthenticator implements Authenticator {

  /**
   * Logger variable.
   */
  private static final Logger LOGGER = Logger.getLogger(RequireGroupAuthenticator.class);

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public void authenticate(final AuthenticationFlowContext context) {

    RealmModel realm = context.getRealm();
    UserModel user = context.getUser();

    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    AuthenticationSessionModel authenticationSession = context.getAuthenticationSession();
    ClientModel client = authenticationSession.getClient();
    String clientId = client.getClientId();
    String logPrefix =
        "REQUIRE_GROUP_AUTHENTICATE_" + authenticationSession.getParentSession().getId();

    if (config == null ) {
      LOGGER.warnf("{} execution configuration is null", logPrefix);
      context.failure(AuthenticationFlowError.INTERNAL_ERROR);
      return;
    }
    if (user != null) {
      LOGGER.infof("{} user {} / {}", logPrefix, user.getId(), user.getUsername());
    } else {
      LOGGER.warnf("{} invalid user", logPrefix);

    }
    LOGGER.infof("{} client {} / {}", logPrefix, clientId, client.getName());

    // Match the pattern "test_b4e4ae70-5b78-47ff-ad5c-7ebf3c10e452_app"
    // where "test" is the short name and "b4e4ae70-5b78-47ff-ad5c-7ebf3c10e452" is the group id
    String clientIdPatternMatch =
        "^[a-z0-9-]+_([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})_[_a-z0-9-]+$";
    Pattern pattern = Pattern.compile(clientIdPatternMatch);
    Matcher matcher = pattern.matcher(clientId);

    // Check for a valid match
    if (matcher.find() && matcher.groupCount() == 1) {
      String groupId = matcher.group(1);
      checkIfUserIsAuthorized(context, realm, user, logPrefix, groupId);
    } else {
      String groupProtectionClients = config.getConfig().get(GROUP_PROTECTION_IGNORE_CLIENTS);
      if (groupProtectionClients != null && groupProtectionClients.contains(clientId)
          && user != null) {
        LOGGER.infof("{} matched authorized ignored group protect client", logPrefix);
        success(context, user);
      } else {
        LOGGER.warnf("{} failed ignored group protect client test", logPrefix);
        context.failure(AuthenticationFlowError.CLIENT_DISABLED);
      }
    }
  }

  private void checkIfUserIsAuthorized(
      final AuthenticationFlowContext context,
      final RealmModel realm,
      final UserModel user,
      final String logPrefix,
      final String groupId) {

    GroupModel group = null;

    if (realm != null) {
      group = realm.getGroupById(groupId);
    }

    // Must be a valid environment name
    if (groupId == null || group == null) {
      LOGGER.warnf("{} invalid group {}", logPrefix, groupId);
      context.failure(AuthenticationFlowError.CLIENT_DISABLED);
    } else {
      // Check if the user is a member of the specified group
      if (isMemberOfGroup(realm, user, group, logPrefix)) {
        LOGGER.infof("{} matched authorized group", logPrefix);
        success(context, user);
      } else {
        LOGGER.warnf("{} failed authorized group match", logPrefix);
        context.failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
      }
    }
  }

  private void success(final AuthenticationFlowContext context, final UserModel user) {
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    // Reset X509 attribute per login event
    user.setSingleAttribute(config.getConfig().get(USER_ACTIVE_X509_ATTRIBUTE), "");
    user.addRequiredAction("TERMS_AND_CONDITIONS");
    context.success();
  }

  private boolean isMemberOfGroup(
      final RealmModel realm,
      final UserModel user,
      final GroupModel group,
      final String logPrefix) {

    // No one likes null pointers
    if (realm == null || user == null || group == null) {
      LOGGER.warnf("{} realm, group or user null", logPrefix);
      return false;
    }

    String groupList = user.getGroupsStream()
        .map(GroupModel::getId)
        .collect(Collectors.joining(","));

    LOGGER.infof("{} user groups {}", logPrefix, groupList);

    return user.isMemberOf(group);
  }

  @Override
  public void action(final AuthenticationFlowContext authenticationFlowContext) {
    // no implementation needed here
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public boolean requiresUser() {
    return false;
  }

  /**
   * This implementation is not intended to be overridden.
   */
  @Override
  public boolean configuredFor(
      final KeycloakSession keycloakSession,
      final RealmModel realmModel,
      final UserModel userModel) {

    return true;
  }

  @Override
  public void setRequiredActions(
      final KeycloakSession keycloakSession,
      final RealmModel realmModel,
      final UserModel userModel) {

    // no implementation needed here
  }

  @Override
  public void close() {
    // no implementation needed here
  }
}
