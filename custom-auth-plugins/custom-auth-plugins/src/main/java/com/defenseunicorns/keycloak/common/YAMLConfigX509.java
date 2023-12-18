package com.defenseunicorns.keycloak.common;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@NoArgsConstructor
public class YAMLConfigX509 {

    /**
     * String for user identity attribute.
     */
    @Getter
    @Setter
    private String userIdentityAttribute;
    /**
     * String for user active 509 attribute.
     */
    @Getter
    @Setter
    private String userActive509Attribute;
    /**
     * List of strings for auto join group.
     */
    @Getter
    @Setter
    private List<String> autoJoinGroup;
    /**
     * List of strings required certificate policies.
     */
    @Getter
    @Setter
    private List<String> requiredCertificatePolicies;

}