package com.defenseunicorns.keycloak.registration;

import static org.keycloak.models.utils.KeycloakModelUtils.findGroupByPath;

import com.defenseunicorns.keycloak.common.Utils;
import com.defenseunicorns.keycloak.common.X509Tools;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationUserCreation;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

public class X509RegistrationUserCreation extends RegistrationUserCreation {

  public static final String PROVIDER_ID = "x509-registration-user-creation";

  private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
      AuthenticationExecutionModel.Requirement.REQUIRED};
  private static final String EMAIL = "email";
  private static final String LOGGING_USER_TEXT = " user ";

  @Override
  public String getHelpText() {
    return "Custom X509/CAC user registration. This action must always be first!";
  }

  public static final String RESTRICT_REGISTRATION = "restrictRegistration";
  public static final ProviderConfigProperty RESTRICT_REGISTRATION_PROPERTY = new ProviderConfigProperty(
      RESTRICT_REGISTRATION, "Restrict registration to X509/CAC users only",
      "Should registration be restricted to X509/CAC users only.",
      ProviderConfigProperty.BOOLEAN_TYPE, "false");
  public static final String USER_IDENTITY_ATTRIBUTE = "userIdentityAttribute";
  public static final String AUTO_JOIN_GROUP = "autoJoinGroup";
  public static final String REQUIRED_CERTIFICATE_POLICIES = "requiredCertificatePolicies";
  public static final String NO_EMAIL_MATCH_AUTO_JOIN_GROUP = "noEmailMatchAutoJoinGroup";
  public static final String EMAIL_MATCH_AUTO_JOIN_GROUP = "emailMatchAutoJoinGroup";
  protected static final List<ProviderConfigProperty> configProperties;

  static {
    // Set a few default values from the old customreg.yaml file
    List<String> autoJoinGroups = new ArrayList<>();
    autoJoinGroups.add("/Impact Level 2 Authorized");
    autoJoinGroups.add("/Impact Level 4 Authorized");
    autoJoinGroups.add("/Impact Level 5 Authorized");

    List<String> requiredCertificatePolicies = new ArrayList<>();
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.5");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.9");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.10");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.17");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.18");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.19");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.20");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.31");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.36");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.37");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.38");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.39");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.40");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.41");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.42");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.43");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.44");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.59");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.60");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.61");
    requiredCertificatePolicies.add("2.16.840.1.101.2.1.11.62");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.1");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.2");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.3");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.4");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.5");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.6");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.7");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.8");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.9");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.12.10");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.4");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.7");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.12");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.13");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.16");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.18");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.20");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.24");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.36");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.38");
    requiredCertificatePolicies.add("2.16.840.1.101.3.2.1.3.39");

    List<String> noEmailMatchAutoJoinGroup = new ArrayList<>();
    noEmailMatchAutoJoinGroup.add("/Randos");

    Map<String, String[]> emailMatchAutoJoinGroup = new HashMap<>();

    configProperties = ProviderConfigurationBuilder.create()
        .property(RESTRICT_REGISTRATION_PROPERTY)
        .property()
        .name(USER_IDENTITY_ATTRIBUTE)
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("User Attribute")
        .helpText("User attribute to bind to when associating PKI with a user account.")
        .defaultValue("usercertificate")
        .add()
        .property()
        .name(AUTO_JOIN_GROUP)
        .type(ProviderConfigProperty.TEXT_TYPE)
        .label("Auto Join Groups")
        .helpText(
            "When a user with valid PKI registers, join to the listed groups. Comma-separated list of strings.")
        .defaultValue(autoJoinGroups)
        .add()
        .property()
        .name(REQUIRED_CERTIFICATE_POLICIES)
        .type(ProviderConfigProperty.TEXT_TYPE)
        .label("Required X509 Policies")
        .helpText(
            "Policies that must match to consider the cert valid. Comma-separated list of strings.")
        .defaultValue(requiredCertificatePolicies)
        .add()
        .property()
        .name(NO_EMAIL_MATCH_AUTO_JOIN_GROUP)
        .type(ProviderConfigProperty.TEXT_TYPE)
        .label("No Email Auto Join Groups")
        .helpText(
            "When a user registers without matching any top-level domain in emailMatchAutoJoinGroup, join to the listed groups. Comma-separated list of strings.")
        .defaultValue(noEmailMatchAutoJoinGroup)
        .add()
        .property()
        .name(EMAIL_MATCH_AUTO_JOIN_GROUP)
        .type(ProviderConfigProperty.MAP_TYPE)
        .label("Email Match AutoJoin Groups")
        .helpText(
            "When a user registers with the given top-level domain, join to the listed groups. Key is a string. Value is a comma-separated list of strings.")
        .defaultValue(emailMatchAutoJoinGroup)
        .add()
        .build();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public void validate(final ValidationContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    List<FormMessage> errors = new ArrayList<>();
    String username = formData.getFirst(Validation.FIELD_USERNAME);
    String email = formData.getFirst(Validation.FIELD_EMAIL);

    String eventError = Errors.INVALID_REGISTRATION;

    validateConfiguration(context);

    String location = formData.getFirst("user.attributes.location");
    if (Validation.isBlank(location) || !location.equals("42")) {
      errors.add(new FormMessage("Bot-like activity detected, try disabling auto form filling"));
    }

    if (Validation.isBlank(username)) {
      errors.add(new FormMessage(Validation.FIELD_USERNAME, Messages.MISSING_USERNAME));
    }

    if (Validation.isBlank(formData.getFirst(RegistrationPage.FIELD_FIRST_NAME))) {
      errors.add(new FormMessage(RegistrationPage.FIELD_FIRST_NAME, Messages.MISSING_FIRST_NAME));
    }

    if (Validation.isBlank(formData.getFirst(RegistrationPage.FIELD_LAST_NAME))) {
      errors.add(new FormMessage(RegistrationPage.FIELD_LAST_NAME, Messages.MISSING_LAST_NAME));
    }

    if (Validation.isBlank(formData.getFirst("user.attributes.affiliation"))) {
      errors.add(new FormMessage("user.attributes.affiliation",
          "Please specify your organization affiliation."));
    }

    if (Validation.isBlank(formData.getFirst("user.attributes.rank"))) {
      errors.add(
          new FormMessage("user.attributes.rank", "Please specify your rank or choose n/a."));
    }

    if (Validation.isBlank(formData.getFirst("user.attributes.organization"))) {
      errors.add(
          new FormMessage("user.attributes.organization", "Please specify your organization."));
    }

    if (X509Tools.getX509Username(context) != null && X509Tools.isX509Registered(context)) {
      // X509 auth, invite code not required
      errors.add(new FormMessage(null, "Sorry, this CAC seems to already be registered."));
      context.error(Errors.INVALID_REGISTRATION);
      context.validationError(formData, errors);
    }

    if (Validation.isBlank(email) || !Validation.isEmailValid(email)) {
      context.getEvent().detail(Details.EMAIL, email);
      errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL,
          "Please check your email address, it seems to be invalid"));
    }

    if (context.getSession().users().getUserByEmail(context.getRealm(), email) != null) {
      eventError = Errors.EMAIL_IN_USE;
      formData.remove(EMAIL);
      context.getEvent().detail(EMAIL, email);
      errors.add(new FormMessage(EMAIL, Messages.EMAIL_EXISTS));
    }

    if (!errors.isEmpty()) {
      context.error(eventError);
      context.validationError(formData, errors);
    } else {
      context.success();
    }
  }

  @Override
  public void buildPage(final FormContext context, final LoginFormsProvider form) {
    String x509Username = X509Tools.getX509Username(context);
    if (x509Username != null) {
      form.setAttribute("cacIdentity", x509Username);
    }
  }

  /*
   * Validation of the execution configuration
   */
  public void validateConfiguration(final ValidationContext context) {

    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    List<FormMessage> errors = new ArrayList<>();
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();
    if (config == null) {
      errors.add(new FormMessage(null,
          "Registration configuration was null."));
    }
    boolean disallow = Boolean.parseBoolean(config.getConfig().get(RESTRICT_REGISTRATION));
    if (disallow) {
      errors.add(new FormMessage(null, "Warning: Registration without CAC is disallowed"));
    }

    String userIdentityAttribute = config.getConfig().get(USER_IDENTITY_ATTRIBUTE);
    if (userIdentityAttribute == null || userIdentityAttribute.isEmpty()) {
      errors.add(
          new FormMessage(null, "Configuration Error: User Identity Attribute not found"));
    }

    String autoJoinGroup = config.getConfig().get(AUTO_JOIN_GROUP);
    if (autoJoinGroup == null || autoJoinGroup.isEmpty()) {
      errors.add(
          new FormMessage(null, "Configuration Error: Auto join group not found"));
    } else {
      List<String> autoJoinGroupList = Arrays.asList(autoJoinGroup.split(","));
      autoJoinGroupList.forEach(group -> {
        if (!group.trim().startsWith("/")) {
          errors.add(new FormMessage(null,
              "Configuration Error: Auto Join Group entry does not start with a '/'"));
        }
      });
    }

    String requiredCertificatePolicies = config.getConfig().get(REQUIRED_CERTIFICATE_POLICIES);
    if (requiredCertificatePolicies == null || requiredCertificatePolicies.isEmpty()) {
      errors.add(
          new FormMessage(null, "Configuration Error: Required certificate policy not found"));
    } else {
      List<String> requiredCertificatePoliciesList = Arrays.asList(
          requiredCertificatePolicies.split(","));
      requiredCertificatePoliciesList.forEach(policy -> {
        if (!policy.trim().matches("^\\d+(\\.\\d+)*$")) {
          errors.add(new FormMessage(null,
              "Configuration Error: Unknown Required certificate policy"));
        }
      });
    }

    String noEmailAutoJoinGroup = config.getConfig().get(NO_EMAIL_MATCH_AUTO_JOIN_GROUP);
    if (noEmailAutoJoinGroup == null || noEmailAutoJoinGroup.isEmpty()) {
      errors.add(
          new FormMessage(null, "Configuration Error: No E-mail auto join group not found"));
    } else {
      List<String> noEmailAutoJoinGroupList = Arrays.asList(noEmailAutoJoinGroup.split(","));
      noEmailAutoJoinGroupList.stream().filter(group -> !group.trim().startsWith("/"))
          .map(group -> new FormMessage(null,
              "Configuration Error: No e-mail auto join group entry does not start with a '/'"))
          .forEach(errors::add);
    }

    String emailAutoJoinGroup = config.getConfig().get(NO_EMAIL_MATCH_AUTO_JOIN_GROUP);
    if (emailAutoJoinGroup == null || emailAutoJoinGroup.isEmpty()) {
      errors.add(
          new FormMessage(null, "Configuration Error: E-mail auto join group not found"));
    } else {
      Map<String, String[]> emailAutoJoinGroupMap = convertStringToMap(emailAutoJoinGroup);
      emailAutoJoinGroupMap.forEach((email, groups) -> {
        if (!email.startsWith("@") || (!email.startsWith("."))) {
          errors.add(new FormMessage(null,
              "Configuration Error: E-mail domain must start with a '.' or '@'"));
        }
        Arrays.asList(groups).forEach(group -> {
          if (!group.trim().startsWith("/")) {
            errors.add(new FormMessage(null,
                "Configuration Error: E-mail auto join group entry does not start with a '/'"));
          }
        });
      });
    }

    if (!errors.isEmpty()) {
      context.error(Errors.INVALID_CONFIG);
      context.validationError(formData, errors);
    }
  }

  @Override
  public void success(final FormContext context) {
    UserModel user = context.getUser();
    String userIdentityAttribute = context.getAuthenticatorConfig().getConfig()
        .get(USER_IDENTITY_ATTRIBUTE);
    String x509Username = X509Tools.getX509Username(context);

    joinValidUserToGroups(context, user, x509Username);
    processX509UserAttribute(user, userIdentityAttribute, x509Username);
    bindRequiredActions(user, x509Username);
  }

  @Override
  public String getDisplayType() {
    return "X509/CAC Registration User Creation";
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return REQUIREMENT_CHOICES;
  }

  private static void bindRequiredActions(final UserModel user, final String x509Username) {
    // Default actions for all users
    user.addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
    user.addRequiredAction("TERMS_AND_CONDITIONS");

    if (x509Username == null) {
      user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
    }
  }

  private static void joinValidUserToGroups(final FormContext context, final UserModel user,
      final String x509Username) {

    String email = user.getEmail().toLowerCase();
    RealmModel realm = context.getRealm();
    KeycloakSession session = context.getSession();
    AuthenticatorConfigModel config = context.getAuthenticatorConfig();

    Map<String, String[]> emailMatchAutoJoinGroupMap;
    emailMatchAutoJoinGroupMap = convertStringToMap(
        config.getConfig().get(EMAIL_MATCH_AUTO_JOIN_GROUP));

    long domainMatchCount = emailMatchAutoJoinGroupMap.size();

    if (x509Username != null) {
      // User is a X509 user - Has a CAC
      Utils.LOGGER.infof("{} {} / {} found with X509: {}", LOGGING_USER_TEXT,
          user.getId(), user.getUsername(), x509Username);
      //config.getAutoJoinGroupX509().forEach(user::joinGroup);
      String[] autoJoinGroups = config.getConfig().get(AUTO_JOIN_GROUP).split(",");
      convertPathsToGroupModels(session, realm, Arrays.asList(autoJoinGroups)).forEach(
          user::joinGroup);
    } else {
      if (domainMatchCount != 0) {
        // User is not a X509 user but is in the whitelist
        Utils.LOGGER.infof("{} {} / {}: Email found in whitelist", LOGGING_USER_TEXT,
            user.getUsername(), email);
        String[] emailMatchAutoJoinGroupList = emailMatchAutoJoinGroupMap.entrySet().stream()
            .filter(entry -> email.endsWith(entry.getKey())).findFirst().get().getValue();
        convertPathsToGroupModels(session, realm,
            Arrays.asList(emailMatchAutoJoinGroupList)).forEach(
            user::joinGroup);
      } else {
        // User is not a X509 user or in whitelist
        Utils.LOGGER.infof("{} {} / {}: Email Not found in whitelist",
            LOGGING_USER_TEXT, user.getUsername(), email);
        String[] noEmailAutoJoinGroups = config.getConfig().get(NO_EMAIL_MATCH_AUTO_JOIN_GROUP)
            .split(",");
        convertPathsToGroupModels(session, realm, Arrays.asList(noEmailAutoJoinGroups)).forEach(
            user::joinGroup);
        user.setSingleAttribute("public-registrant", "true");
      }
    }
  }

  private static void processX509UserAttribute(
      final UserModel user,
      final String userIdentityAttribute,
      final String x509Username) {

    if (x509Username != null) {
      // Bind the X509 attribute to the user
      user.setSingleAttribute(userIdentityAttribute, x509Username);
    }
  }

  private static Map<String, String[]> convertStringToMap(String inputString) {
    Map<String, String[]> resultMap = new HashMap<>();

    // Split the input string to separate key-value pairs
    String[] keyValuePairs = inputString.split(";");

    for (String keyValuePair : keyValuePairs) {
      // Split each key-value pair to extract the key and values
      String[] keyAndValues = keyValuePair.split("=");

      // Extract the key
      String key = keyAndValues[0];

      // Extract the values and convert them to an array
      String[] values = keyAndValues[1].split(",");

      // Put the key-value pair into the result map
      resultMap.put(key, values);
    }

    return resultMap;
  }

  private static List<GroupModel> convertPathsToGroupModels(final KeycloakSession session,
      final RealmModel realm,
      final List<String> paths) {
    return paths
        .stream()
        .map(group -> findGroupByPath(session, realm, group))
        .filter(Objects::nonNull)
        .collect(Collectors.toList());
  }

}