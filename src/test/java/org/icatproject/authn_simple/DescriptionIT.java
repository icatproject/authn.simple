package org.icatproject.authn_simple;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static org.hamcrest.Matchers.equalTo;

@QuarkusIntegrationTest
public class DescriptionIT {

	@Test
	public void getDescription() {
		RestAssured.given()
				.when().get("/authn.simple/description")
				.then()
				.statusCode(200)
				.body(equalTo("{\"keys\":[{\"name\":\"username\"},{\"name\":\"password\",\"hide\":true}]}"));
	}
}