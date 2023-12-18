package com.defenseunicorns.keycloak.common;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.keycloak.models.GroupModel;

import java.util.List;

@NoArgsConstructor
public class YAMLConfigEmailAutoJoin {

    /**
     * String for description.
     */
    @Getter
    @Setter
    private String description;
    /**
     * List of strings for goups.
     */
    @Getter
    @Setter
    private List<String> groups;
    /**
     * List of strings for domains.
     */
    @Getter
    @Setter
    private List<String> domains;
    /**
     * Lsit of GroupModel.
     */
    @Getter
    @Setter
    private List<GroupModel> groupModels;
}