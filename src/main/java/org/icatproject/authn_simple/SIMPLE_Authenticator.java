package org.icatproject.authn_simple;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.stream.JsonGenerator;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.authentication.PasswordChecker;
import org.icatproject.core.IcatException;
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_simple.SIMPLE_Authenticator")
@Remote
public class SIMPLE_Authenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(SIMPLE_Authenticator.class);
	private Map<String, String> passwordtable;
	private org.icatproject.authentication.AddressChecker addressChecker;
	private String mechanism;

	@PostConstruct
	private void init() {
		File f = new File("authn_simple.properties");
		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromFile("authn_simple.properties");

			// Build the passwordtable out of user.list and
			// user.<usern>.password
			passwordtable = new HashMap<String, String>();
			String[] users = props.getString("user.list").split("\\s+");

			String msg = "users configured [" + users.length + "]: ";
			for (String user : users) {
				passwordtable.put(user, props.getString("user." + user + ".password"));
				msg = msg + user + " ";
			}
			logger.debug(msg);

			if (props.has("ip")) {
				String authips = props.getString("ip");
				try {
					addressChecker = new AddressChecker(authips);
				} catch (IcatException e) {
					msg = "Problem creating AddressChecker with information from " + f.getAbsolutePath() + "  "
							+ e.getMessage();
					logger.fatal(msg);
					throw new IllegalStateException(msg);
				}
			}

			// Note that the mechanism is optional
			if (props.has("mechanism")) {
				mechanism = props.getString("mechanism");
			}

		} catch (CheckedPropertyException e) {
			logger.fatal(e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.debug("Initialised SIMPLE_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr) throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_simple does not allow log in from your IP address " + remoteAddr);
			}
		}

		String username = credentials.get("username");
		logger.trace("login:" + username);
		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION, "Username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.isEmpty()) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION, "Password cannot be null or empty.");
		}

		String encodedPassword = passwordtable.get(username);
		if (!PasswordChecker.verify(password, encodedPassword)) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION, "The username and password do not match.");
		}

		logger.debug(username + " logged in succesfully");
		return new Authentication(username, mechanism);

	}

	@Override
	public String getDescription() {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		JsonGenerator gen = Json.createGenerator(baos);
		gen.writeStartObject().writeStartArray("keys");
		gen.writeStartObject().write("name", "username").writeEnd();
		gen.writeStartObject().write("name", "password").write("hide", true).writeEnd();
		gen.writeEnd().writeEnd().close();
		return baos.toString();
	}

}
