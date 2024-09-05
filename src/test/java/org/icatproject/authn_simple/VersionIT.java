package org.icatproject.authn_simple;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.restassured.RestAssured;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusIntegrationTest
public class VersionIT {

    @Test
    public void testVersion() throws Exception {
        // Get the version from the pom.xml
        String expectedVersion = getVersionFromPom();

        // Send a request to the version endpoint
        String versionResponse = RestAssured.given()
                .when().get("/authn.simple/version")
                .then()
                .statusCode(200)
                .extract().asString();

        // Parse the JSON response
        JsonObject versionJson;
        try (JsonReader jsonReader = Json.createReader(new StringReader(versionResponse))) {
            versionJson = jsonReader.readObject();
        }

        // Extract the version from the JSON object
        String actualVersion = versionJson.getString("version");

        // Assert that the version matches the expected version from the pom.xml
        assertEquals(expectedVersion, actualVersion);
    }

    // Helper method to load the version from the pom.xml
    private String getVersionFromPom() throws Exception {
        File pomFile = new File("pom.xml");
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(pomFile);
        doc.getDocumentElement().normalize();
        Element versionElement = (Element) doc.getElementsByTagName("version").item(0);
        return versionElement.getTextContent();
    }
}
