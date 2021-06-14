package de.campus_compact.campus_dual_service_keycloak_spi;


import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.Set;

public class CampusDualServiceUserProvider implements
        UserStorageProvider,
        UserLookupProvider,
        CredentialInputValidator,
        CredentialInputUpdater {

    protected KeycloakSession session;
    protected ComponentModel model;
    protected String campusDualServiceAddr = System.getenv("CAMPUS_DUAL_SERVICE_ADDR");
    protected int campusDualServicePort = Integer.parseInt(System.getenv("CAMPUS_DUAL_SERVICE_PORT"));


    public CampusDualServiceUserProvider(KeycloakSession session, ComponentModel storageComponentModel) {
        this.session = session;
        this.model = storageComponentModel;
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        return createAdapter(realm, username);
    }

    protected UserModel createAdapter(RealmModel realm, String username) {
        UserModel local = session.userLocalStorage().getUserByUsername(username, realm);
        if (local == null) {
            local = session.userLocalStorage().addUser(realm, username);
            local.setFederationLink(model.getId());
            local.setEnabled(true);
        }
        return new UserModelDelegate(local);
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(username, realm);
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        return null;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return credentialType.equals(CredentialModel.PASSWORD);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(CredentialModel.PASSWORD);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) return false;

        try {
            HttpClient client = HttpClient.newBuilder().build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://" + campusDualServiceAddr + ":" + campusDualServicePort + "/login"))
                    .POST(HttpRequest.BodyPublishers.ofString("{\"username\":\"" + user.getUsername() + "\",\"pw\":\"" + input.getChallengeResponse() + "\"}"))
                    .build();

            HttpResponse<?> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            String body = (String) response.body();
            JSONObject json = new JSONObject(body);

            if (status == 200) {
                user.setAttribute("campus-dual-hash", Collections.singletonList(json.getString("hash")));
                user.setFirstName(json.getString("firstName"));
                user.setLastName(json.getString("lastName"));
                return true;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (input.getType().equals(CredentialModel.PASSWORD))
            throw new ReadOnlyException("user is read only for this update");

        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.EMPTY_SET;
    }

    @Override
    public void close() {

    }
}