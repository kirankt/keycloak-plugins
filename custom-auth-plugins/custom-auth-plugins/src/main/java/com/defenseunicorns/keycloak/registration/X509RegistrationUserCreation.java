package com.defenseunicorns.keycloak.registration;

import static com.defenseunicorns.keycloak.common.CommonConfig.getInstance;

import com.defenseunicorns.keycloak.common.CommonConfig;
import com.defenseunicorns.keycloak.common.X509Tools;
import jakarta.ws.rs.core.MultivaluedMap;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.authentication.forms.RegistrationUserCreation;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;

public class X509RegistrationUserCreation extends RegistrationUserCreation {
    public static final String PROVIDER_ID = "x509-registration-user-creation";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {AuthenticationExecutionModel.Requirement.REQUIRED};
    private static final String EMAIL = "email";
    private static final String LOGGING_USER_TEXT = " user ";

    @Override
    public String getHelpText() {
        return "Custom X509/CAC user registration. This action must always be first!";
    }

    @Override
    public void validate(ValidationContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        String username = formData.getFirst(Validation.FIELD_USERNAME);
        String email = formData.getFirst(Validation.FIELD_EMAIL);

        String eventError = Errors.INVALID_REGISTRATION;

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
            errors.add(new FormMessage("user.attributes.affiliation", "Please specify your organization affiliation."));
        }

        if (Validation.isBlank(formData.getFirst("user.attributes.rank"))) {
            errors.add(new FormMessage("user.attributes.rank", "Please specify your rank or choose n/a."));
        }

        if (Validation.isBlank(formData.getFirst("user.attributes.organization"))) {
            errors.add(new FormMessage("user.attributes.organization", "Please specify your organization."));
        }

        if (X509Tools.getX509Username(context) != null && X509Tools.isX509Registered(context)) {
            // X509 auth, invite code not required
            errors.add(new FormMessage(null, "Sorry, this CAC seems to already be registered."));
            context.error(Errors.INVALID_REGISTRATION);
            context.validationError(formData, errors);
        }

        if (Validation.isBlank(email) || !Validation.isEmailValid(email)) {
            context.getEvent().detail(Details.EMAIL, email);
            errors.add(new FormMessage(RegistrationPage.FIELD_EMAIL, "Please check your email address, it seems to be invalid"));
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
    public void buildPage(FormContext context, LoginFormsProvider form) {
        String x509Username = X509Tools.getX509Username(context);
        if (x509Username != null) {
            form.setAttribute("cacIdentity", x509Username);
        }
    }

    @Override
    public void success(final FormContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        String x509Username = X509Tools.getX509Username(context);

        joinValidUserToGroups(context, user, x509Username);
        processX509UserAttribute(realm, user, x509Username);
        bindRequiredActions(user, x509Username);
    }

    @Override
    public String getDisplayType() {
        return "X509-only Registration User Creation";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public boolean isConfigurable() {
        return false;
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

    private static void joinValidUserToGroups(final FormContext context, final UserModel user, final String x509Username) {

        String email = user.getEmail().toLowerCase();
        RealmModel realm = context.getRealm();
        CommonConfig config = getInstance(realm);

        long domainMatchCount = config.getEmailMatchAutoJoinGroup().filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith)).count();

        if (x509Username != null) {
            // User is a X509 user - Has a CAC
            CommonConfig.LOGGER_COMMON.infof("{} {} / {} found with X509: {}", LOGGING_USER_TEXT, user.getId(), user.getUsername(), x509Username);
            config.getAutoJoinGroupX509().forEach(user::joinGroup);
        } else {
            if (domainMatchCount != 0) {
                // User is not a X509 user but is in the whitelist
                CommonConfig.LOGGER_COMMON.infof("{} {} / {}: Email found in whitelist", LOGGING_USER_TEXT, user.getUsername(), email);
                config.getEmailMatchAutoJoinGroup().filter(collection -> collection.getDomains().stream().anyMatch(email::endsWith)).forEach(match -> {
                    CommonConfig.LOGGER_COMMON.infof("Adding user {} to group(s): {}", user.getUsername(), match.getGroups());
                    match.getGroupModels().forEach(user::joinGroup);
                });

            } else {
                // User is not a X509 user or in whitelist
                CommonConfig.LOGGER_COMMON.infof("{} {} / {}: Email Not found in whitelist", LOGGING_USER_TEXT, user.getUsername(), email);
                config.getNoEmailMatchAutoJoinGroup().forEach(user::joinGroup);
                user.setSingleAttribute("public-registrant", "true");
            }
        }
    }

    private static void processX509UserAttribute(
            final RealmModel realm,
            final UserModel user,
            final String x509Username) {

        if (x509Username != null) {
            // Bind the X509 attribute to the user
            user.setSingleAttribute(getInstance(realm).getUserIdentityAttribute(), x509Username);
        }
    }

}