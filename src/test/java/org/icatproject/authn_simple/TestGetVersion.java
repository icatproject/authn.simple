package org.icatproject.authn_simple;

import static org.junit.Assert.assertEquals;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;

public class TestGetVersion{
    @Test
    public void testVersion() throws Exception {
        // get the version from the pom file
        String expectedVersion = getVersionFromPom();

        SIMPLE_Authenticator authenticator = new SIMPLE_Authenticator();

        // Manually set the projectVersion field to simulate injection
        authenticator.projectVersion = expectedVersion;

        // Call the getVersion method
        String versionResponse = authenticator.getVersion();

        // Parse the JSON response
        JsonObject versionJson;
        try (JsonReader jsonReader = Json.createReader(new java.io.StringReader(versionResponse))) {
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
