package de.campus_compact.campus_dual_service_keycloak_spi;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.utils.reflection.Properties;
import org.keycloak.storage.UserStorageProviderFactory;

import java.io.IOException;
import java.io.InputStream;

public class CampusDualServiceUserProviderFactory
        implements UserStorageProviderFactory<CampusDualServiceUserProvider> {

    public static final String PROVIDER_NAME = "readonly-property-file";

    @Override
    public CampusDualServiceUserProvider create(KeycloakSession session, ComponentModel model) {
        return new CampusDualServiceUserProvider(session, model);
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }
}
