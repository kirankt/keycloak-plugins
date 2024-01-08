package com.defenseunicorns.keycloak.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.jboss.logging.Logger;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.x509.X509ClientCertificateLookup;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class X509Tools {

  /**
   * The LOGGER.
   */
  public static final Logger LOGGER = Logger.getLogger(Utils.class);
  /**
   * The certificate policy OID.
   */
  private static final String CERTIFICATE_POLICY_OID = "2.5.29.32";
  /**
   * The max number of certificate policies to check.
   */
  private static final int MAX_CERT_POLICIES_TO_CHECK = 10;
  public static final String USER_ACTIVE_X509_ATTRIBUTE = "userActive509Attribute";
  public static final String REQUIRED_CERTIFICATE_POLICIES = "requiredCertificatePolicies";


  private static String getLogPrefix(final AuthenticationSessionModel authenticationSession,
      final String suffix) {
    return "P1_X509_TOOLS_" + suffix + "_" + authenticationSession.getParentSession().getId();
  }

  // hide constructor per checkstyle linting
  private X509Tools() {
  }

  private static boolean isX509Registered(
      final KeycloakSession session,
      final HttpRequest httpRequest,
      final RealmModel realm,
      final AuthenticatorConfigModel config) {

    String logPrefix = getLogPrefix(session.getContext().getAuthenticationSession(),
        "IS_X509_REGISTERED");
    String username = getX509Username(session, httpRequest, realm, config);
    LOGGER.infof("{} X509 ID: {}", logPrefix, username);

    if (username != null) {
      Stream<UserModel> users = session.users().searchForUserByUserAttributeStream(realm,
          config.getConfig().get(USER_ACTIVE_X509_ATTRIBUTE), username);
      return users != null && users.count() > 0;
    }
    return false;
  }

  /**
   * Determine if x509 is registered from form context.
   *
   * @param context
   * @return boolean
   */
  public static boolean isX509Registered(final FormContext context) {
    return isX509Registered(context.getSession(), context.getHttpRequest(), context.getRealm(),
        context.getAuthenticatorConfig());
  }

  /**
   * Determine if x509 is registered from required action.
   *
   * @param context
   * @return boolean

  public static boolean isX509Registered(final RequiredActionContext context) {
  return isX509Registered(context.getSession(), context.getHttpRequest(), context.getRealm(),
  context.getRealm()
  .getAuthenticatorConfigById(USER_ACTIVE_X509_ATTRIBUTE));
  }
   */

  /**
   * Get x509 username from identity.
   *
   * @param session
   * @param httpRequest
   * @param realm
   * @return String
   */
  private static String getX509Username(
      final KeycloakSession session,
      final HttpRequest httpRequest,
      final RealmModel realm,
      final AuthenticatorConfigModel config) {

    Object identity = getX509Identity(session, httpRequest, realm, config);
    if (identity != null && !identity.toString().isEmpty()) {
      return identity.toString();
    }
    return null;
  }

  /**
   * Get x509 username from form context.
   *
   * @param context a Keycloak form context
   * @return String
   */
  public static String getX509Username(final FormContext context) {
    return getX509Username(context.getSession(), context.getHttpRequest(), context.getRealm(),
        context.getAuthenticatorConfig());
  }

  /**
   * Get x509 certificate policy.
   *
   * @param cert                 x509 CA certificate
   * @param certificatePolicyPos an Integer
   * @param policyIdentifierPos  an Integer
   * @return String
   */
  public static String getCertificatePolicyId(
      final X509Certificate cert,
      final int certificatePolicyPos,
      final int policyIdentifierPos) throws IOException {

    byte[] extPolicyBytes = cert.getExtensionValue(CERTIFICATE_POLICY_OID);
    if (extPolicyBytes == null) {
      return null;
    }

    DEROctetString oct = (DEROctetString) (new ASN1InputStream(
        new ByteArrayInputStream(extPolicyBytes))
        .readObject());
    ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(
        new ByteArrayInputStream(oct.getOctets())).readObject();

    if (seq.size() <= (certificatePolicyPos)) {
      return null;
    }

    CertificatePolicies certificatePolicies = new CertificatePolicies(
        PolicyInformation.getInstance(seq.getObjectAt(certificatePolicyPos)));
    if (certificatePolicies.getPolicyInformation().length <= policyIdentifierPos) {
      return null;
    }

    PolicyInformation[] policyInformation = certificatePolicies.getPolicyInformation();
    return policyInformation[policyIdentifierPos].getPolicyIdentifier().getId();
  }

  /**
   * Get x509 identity from cert chain.
   *
   * @param certs                 an array of CA certs
   * @param realm                 a Keycloak realm model
   * @param authenticationSession a Keycloak authentication session
   * @return Object
   */
  public static Object getX509IdentityFromCertChain(final X509Certificate[] certs,
      final RealmModel realm,
      final AuthenticationSessionModel authenticationSession,
      final AuthenticatorConfigModel configModel) {

    String logPrefix = getLogPrefix(authenticationSession, "GET_X509_IDENTITY_FROM_CHAIN");

    if (certs == null || certs.length == 0) {
      LOGGER.infof("{} no valid certs found", logPrefix);
      return null;
    }

    boolean hasValidPolicy = false;

    int index = 0;
    // Only check up to 10 cert policies, DoD only uses 1-2 policies
    while (!hasValidPolicy && index < MAX_CERT_POLICIES_TO_CHECK) {
      try {
        String certificatePolicyId = getCertificatePolicyId(certs[0], index, 0);
        if (certificatePolicyId == null) {
          break;
        }
        LOGGER.infof("{} checking cert policy {}", logPrefix, certificatePolicyId);
        hasValidPolicy = configModel.getConfig().get(REQUIRED_CERTIFICATE_POLICIES)
            .contains(certificatePolicyId);
        index++;
      } catch (Exception ignored) {
        LOGGER.warnf("{} error parsing cert policies", logPrefix);
        // abort checks
        index = MAX_CERT_POLICIES_TO_CHECK;
      }
    }

    if (!hasValidPolicy) {
      LOGGER.warnf("{} no valid cert policies found", logPrefix);
      return null;
    }

    if (realm.getAuthenticatorConfigsStream().count() > 0) {
      return realm.getAuthenticatorConfigsStream().filter(config ->
          config.getConfig()
              .containsKey(AbstractX509ClientCertificateAuthenticator.CUSTOM_ATTRIBUTE_NAME)
      ).map(config -> {
        X509ClientCertificateAuthenticator authenticator = new X509ClientCertificateAuthenticator();
        X509AuthenticatorConfigModel model = new X509AuthenticatorConfigModel(config);
        return authenticator.getUserIdentityExtractor(model).extractUserIdentity(certs);
      }).findFirst().orElse(null);
    }

    return null;
  }

  private static Object getX509Identity(
      final KeycloakSession session,
      final HttpRequest httpRequest,
      final RealmModel realm,
      final AuthenticatorConfigModel config) {

    try {
      if (session == null || httpRequest == null || realm == null) {
        return null;
      }

      X509ClientCertificateLookup provider = session.getProvider(
          X509ClientCertificateLookup.class);
      if (provider == null) {
        return null;
      }

      X509Certificate[] certs = provider.getCertificateChain(httpRequest);

      AuthenticationSessionModel authenticationSession = session.getContext()
          .getAuthenticationSession();

      return getX509IdentityFromCertChain(certs, realm, authenticationSession, config);
    } catch (GeneralSecurityException e) {
      LOGGER.error(e.getMessage());
    }
    return null;
  }

}