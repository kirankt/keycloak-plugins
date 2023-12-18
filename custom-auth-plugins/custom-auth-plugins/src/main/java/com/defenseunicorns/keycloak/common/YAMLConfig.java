package com.defenseunicorns.keycloak.common;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@NoArgsConstructor
public class YAMLConfig {

    /**
     * Yaml config x509.
     */
    @Getter
    @Setter
    private YAMLConfigX509 x509;

    /**
     * List of strings for group protection ignore clients.
     */
    @Getter
    @Setter
    private List<String> groupProtectionIgnoreClients;

    /**
     * List of strings for no email match auto join group.
     */
    @Getter
    @Setter
    private List<String> noEmailMatchAutoJoinGroup;

    /**
     * List of YAMLConfigEmailAutoJoin objects.
     */
    @Getter
    @Setter
    private List<YAMLConfigEmailAutoJoin> emailMatchAutoJoinGroup;

}