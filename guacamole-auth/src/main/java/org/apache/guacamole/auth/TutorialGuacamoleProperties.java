package org.apache.guacamole.auth;

import org.apache.guacamole.properties.StringGuacamoleProperty;

/**
 * Utility class containing all properties used by the custom authentication
 * tutorial. The properties defined here must be specified within
 * guacamole.properties to configure the tutorial authentication provider.
 */
public class TutorialGuacamoleProperties {

    /**
     * This class should not be instantiated.
     */
    private TutorialGuacamoleProperties() {}

    /**
     * The only user to allow.
     */
    public static final StringGuacamoleProperty PROVIDER_URL = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "rutgers-ldap-url"; }

    };

    public static final StringGuacamoleProperty SEARCH_DN = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "rutgers-ldap-search-dn"; }

    };

    public static final StringGuacamoleProperty SEARCH_PASSWORD = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "rutgers-ldap-search-password"; }

    };

    public static final StringGuacamoleProperty ALLOWED_GROUP = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "rutgers-ldap-allowed-group"; }

    };

    public static final StringGuacamoleProperty USER_BASE = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "rutgers-ldap-user-base"; }

    };

    public static final StringGuacamoleProperty GUAC_DATA = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "rutgers-ldap-guac-data"; }

    };


    public static final StringGuacamoleProperty TUTORIAL_USER = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "tutorial-user"; }

    };

    /**
     * The password required for the specified user.
     */
    public static final StringGuacamoleProperty TUTORIAL_PASSWORD = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "tutorial-password"; }

    };


    /**
     * The protocol to use when connecting.
     */
    public static final StringGuacamoleProperty TUTORIAL_PROTOCOL = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "tutorial-protocol"; }

    };


    /**
     * All parameters associated with the connection, as a comma-delimited
     * list of name="value" 
     */
    public static final StringGuacamoleProperty TUTORIAL_PARAMETERS = 
        new StringGuacamoleProperty() {

        @Override
        public String getName() { return "tutorial-parameters"; }

    };

}
