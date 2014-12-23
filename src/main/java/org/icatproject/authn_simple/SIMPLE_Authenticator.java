package org.icatproject.authn_simple;

import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.authentication.PasswordChecker;
import org.icatproject.core.IcatException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_simple.SIMPLE_Authenticator")
@Remote
public class SIMPLE_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(SIMPLE_Authenticator.class);
	private Map<String, String> passwordtable;
	private org.icatproject.authentication.AddressChecker addressChecker;
	private String mechanism;

	@PostConstruct
	private void init() {
		File f = new File("authn_simple.properties");
		Properties props = null;
		try {
			props = new Properties();
			props.load(new FileInputStream(f));
		} catch (Exception e) {
			String msg = "Unable to read property file " + f.getAbsolutePath() + "  "
					+ e.getMessage();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}

		// Build the passwordtable out of user.list and user.<usern>.password
		passwordtable = new HashMap<String, String>();
		String[] users;
		String userlist = props.getProperty("user.list");

		if (userlist == null) {
			String msg = "user.list not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);

		}
		if (userlist.trim().isEmpty()) {
			users = new String[0];
		} else {
			users = userlist.trim().split("\\s+");
		}
		String msg = "users configured [" + users.length + "]: ";
		for (String u : users) {
			msg = msg + u + " ";
		}
		log.debug(msg);

		for (String user : users) {
			String pass = props.getProperty("user." + user + ".password");
			if (pass != null) {
				passwordtable.put(user, pass);
			} else {
				msg = "no passwd defined for user " + user + " in " + f.getAbsolutePath();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
		}

		String authips = props.getProperty("ip");
		if (authips != null) {
			try {
				addressChecker = new AddressChecker(authips);
			} catch (IcatException e) {
				msg = "Problem creating AddressChecker with information from "
						+ f.getAbsolutePath() + "  " + e.getMessage();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
		}

		// Note that the mechanism is optional
		mechanism = props.getProperty("mechanism");

		log.debug("Initialised SIMPLE_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_simple does not allow log in from your IP address " + remoteAddr);
			}
		}

		String username = credentials.get("username");
		log.trace("login:" + username);
		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.isEmpty()) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Password cannot be null or empty.");
		}

		String encodedPassword = passwordtable.get(username);
		if (!PasswordChecker.verify(password, encodedPassword)) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"The username and password do not match.");
		}

		log.info(username + " logged in succesfully");
		return new Authentication(username, mechanism);

	}

}
