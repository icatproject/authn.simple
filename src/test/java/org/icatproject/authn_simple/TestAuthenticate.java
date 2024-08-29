package org.icatproject.authn_simple;

import jakarta.json.Json;
import jakarta.json.JsonObject;

import org.icatproject.authentication.AuthnException;
import org.icatproject.utils.AddressChecker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TestAuthenticate {

    private SIMPLE_Authenticator authenticator;

    @BeforeEach
    public void setup() {
        authenticator = new SIMPLE_Authenticator();

        // Manually set up the required fields
        authenticator.passwordtable = new HashMap<>();
        authenticator.passwordtable.put("testuser", "testpassword");

        authenticator.mechanism = "simple";
        authenticator.ipProperty = Optional.of("127.0.0.1");

        // Mock AddressChecker to always return true for IP check
        authenticator.addressChecker = mock(AddressChecker.class);
        try {
            when(authenticator.addressChecker.check(Mockito.anyString())).thenReturn(true);
        } catch (Exception e) {
            // Handle exception
        }
    }

    @Test
    public void testAuthenticateSuccess() throws Exception {
        // Create a valid JSON string as input
        JsonObject credentials = Json.createObjectBuilder()
                .add("credentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder().add("username", "testuser"))
                        .add(Json.createObjectBuilder().add("password", "testpassword")))
                .add("ip", "127.0.0.1")
                .build();

        // Call the authenticate method
        String response = authenticator.authenticate(credentials.toString());

        // Parse the response
        JsonObject responseJson = Json.createReader(new java.io.StringReader(response)).readObject();

        // Validate the response
        assertEquals("testuser", responseJson.getString("username"));
        assertEquals("simple", responseJson.getString("mechanism"));
    }

    @Test
    public void testAuthenticateInvalidPassword() throws Exception {
        // Create a JSON string with an incorrect password
        JsonObject credentials = Json.createObjectBuilder()
                .add("credentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder().add("username", "testuser"))
                        .add(Json.createObjectBuilder().add("password", "wrongpassword")))
                .add("ip", "127.0.0.1")
                .build();

        // Expect an AuthnException to be thrown
        AuthnException exception = assertThrows(AuthnException.class, () -> authenticator.authenticate(credentials.toString()));

        // Validate the exception message
        assertEquals(HttpURLConnection.HTTP_FORBIDDEN, exception.getHttpStatusCode());
        assertTrue(exception.getMessage().contains("(403)"));
        assertTrue(exception.getMessage().contains("The username and password do not match "));
    }

    @Test
    public void testAuthenticateMissingUsername() throws Exception {
        // Create a JSON string with a missing username
        JsonObject credentials = Json.createObjectBuilder()
                .add("credentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder().add("password", "testpassword")))
                .add("ip", "127.0.0.1")
                .build();

        // Expect an AuthnException to be thrown
        AuthnException exception = assertThrows(AuthnException.class, () -> authenticator.authenticate(credentials.toString()));

        // Validate the exception message
        assertEquals(HttpURLConnection.HTTP_FORBIDDEN, exception.getHttpStatusCode());
        assertTrue(exception.getMessage().contains("(403)"));
        assertTrue(exception.getMessage().contains("username cannot be null or empty."));
    }

    @Test
    public void testAuthenticateInvalidIP() throws Exception {
        // Mock AddressChecker to return false
        when(authenticator.addressChecker.check(Mockito.anyString())).thenReturn(false);

        // Create a valid JSON string
        JsonObject credentials = Json.createObjectBuilder()
                .add("credentials", Json.createArrayBuilder()
                        .add(Json.createObjectBuilder().add("username", "testuser"))
                        .add(Json.createObjectBuilder().add("password", "testpassword")))
                .add("ip", "127.0.0.1")
                .build();

        // Expect an AuthnException to be thrown
        AuthnException exception = assertThrows(AuthnException.class, () -> authenticator.authenticate(credentials.toString()));

        // Validate the exception message
        assertEquals(HttpURLConnection.HTTP_FORBIDDEN, exception.getHttpStatusCode());
        assertTrue(exception.getMessage().contains("(403)"));
        assertTrue(exception.getMessage().contains("authn.simple does not allow log in from your IP address 127.0.0.1"));
    }
}
