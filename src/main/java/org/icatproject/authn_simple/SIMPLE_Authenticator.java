package org.icatproject.authn_simple;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonValue;
import jakarta.json.stream.JsonGenerator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.icatproject.authentication.AuthnException;
import org.icatproject.authentication.PasswordChecker;
import org.icatproject.utils.AddressChecker;
import org.icatproject.utils.AddressCheckerException;

import org.jboss.logging.Logger;

/* Mapped name is to avoid name clashes */
@Path("/")
@ApplicationScoped
public class SIMPLE_Authenticator {

    private static final Logger logger = Logger.getLogger(SIMPLE_Authenticator.class);

    Map<String, String> passwordtable;
    AddressChecker addressChecker;

    @Inject
    @ConfigProperty(name = "user.list")
    List<String> users;

    @Inject
    @ConfigProperty(name = "mechanism", defaultValue = "simple")
    String mechanism;

    @Inject
    @ConfigProperty(name = "ip")
    Optional<String> ipProperty;

    @Inject
    @ConfigProperty(name = "quarkus.application.version")
    String projectVersion;

    @PostConstruct
    private void init() {

        passwordtable = new HashMap<>();
        // Populate the password table using the injected users list
        for (String user : users) {
            String password = ConfigProvider.getConfig().getValue("user." + user + ".password", String.class);
            passwordtable.put(user, password);
        }

        String msg = "users configured [" + users.size() + "]: " + String.join(" ", users);
        logger.debug(msg);

        // Initialize the AddressChecker if the IP property is present
        ipProperty.ifPresent(ip -> {
            try {
                addressChecker = new AddressChecker(ip);
            } catch (Exception e) {
                logger.error("Problem creating AddressChecker with IP: " + ip, e);
                throw new IllegalStateException("Invalid IP configuration", e);
            }
        });

        logger.debug("Initialised SIMPLE_Authenticator");
    }

    @GET
    @Path("version")
    @Produces(MediaType.APPLICATION_JSON)
    public String getVersion() {
        JsonObject versionJson = Json.createObjectBuilder()
                .add("version", projectVersion)
                .build();
        return versionJson.toString();
    }

    @POST
    @Path("authenticate")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public String authenticate(@FormParam("json") String jsonString) throws AuthnException {

        ByteArrayInputStream s = new ByteArrayInputStream(jsonString.getBytes());

        String username = null;
        String password = null;
        String ip = null;

        try (JsonReader r = Json.createReader(s)) {
            JsonObject o = r.readObject();
            for (JsonValue c : o.getJsonArray("credentials")) {
                JsonObject credential = (JsonObject) c;
                if (credential.containsKey("username")) {
                    username = credential.getString("username");
                } else if (credential.containsKey("password")) {
                    password = credential.getString("password");
                }
            }
            if (o.containsKey("ip")) {
                ip = o.getString("ip");
            }
        }

        logger.debug("Login request by: " + username);

        if (username == null || username.isEmpty()) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "username cannot be null or empty.");
        }

        if (password == null || password.isEmpty()) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "password cannot be null or empty.");
        }

        if (addressChecker != null) {
            try {
                if (ip==null) {
                    throw new AuthnException(HttpURLConnection.HTTP_BAD_REQUEST,
                            "An Ip address must be provided");
                }
                if (!addressChecker.check(ip)) {
                    throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN,
                            "authn.simple does not allow log in from your IP address " + ip);
                }
            } catch (AddressCheckerException e) {
                throw new AuthnException(HttpURLConnection.HTTP_INTERNAL_ERROR, e.getClass() + " " + e.getMessage());
            }
        }

        String encodedPassword = passwordtable.get(username);
        if (!PasswordChecker.verify(password, encodedPassword)) {
            throw new AuthnException(HttpURLConnection.HTTP_FORBIDDEN, "The username and password do not match ");
        }

        logger.info(username + " logged in succesfully" + (mechanism != null ? " by " + mechanism : ""));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JsonGenerator gen = Json.createGenerator(baos)) {
            gen.writeStartObject().write("username", username);
            if (mechanism != null) {
                gen.write("mechanism", mechanism);
            }
            gen.writeEnd();
        }
        return baos.toString();
    }

    @GET
    @Path("description")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public String getDescription() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JsonGenerator gen = Json.createGenerator(baos)) {
            gen.writeStartObject().writeStartArray("keys");
            gen.writeStartObject().write("name", "username").writeEnd();
            gen.writeStartObject().write("name", "password").write("hide", true).writeEnd();
            gen.writeEnd().writeEnd();
        }
        return baos.toString();
    }
}
