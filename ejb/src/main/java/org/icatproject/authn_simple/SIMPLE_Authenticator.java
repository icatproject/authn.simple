package org.icatproject.authn_simple;

import java.io.File;
import java.io.FileInputStream;
import java.util.Map;
import java.util.HashMap;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_simple.SIMPLE_Authenticator")
@Remote
public class SIMPLE_Authenticator implements Authenticator {

    private static final Logger log = Logger.getLogger(SIMPLE_Authenticator.class);
    private Map<String, Passwd> passwordtable;
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

	// In principle, we could allow password to be optional.  In
	// this case, we would not add any entries into passwordtable,
	// so we would end up with a auth plugin that does not know
	// any user and thus refuses all logins.  But then, it does
	// not make sense to add the plugin to the ICAT in the first
	// place.  Thus, such a configuration is almost certainly an
	// error and that is why we require password to be set.
	String pwlist = props.getProperty("password");
	if (pwlist != null) {
	    passwordtable = new HashMap<String, Passwd>();
	    for ( String entry : pwlist.split( "," ) ) {
		String[] fields = entry.split( ":" );
		if ( fields.length == 2 ) {
		    passwordtable.put(fields[0], new Passwd(fields[1]));
		}
		else {
		    String msg = "Illegal entry " + entry + " in password property in " + f.getAbsolutePath();
		    log.fatal(msg);
		    throw new IllegalStateException(msg);
		}
	    }
	}
	else {
	    String msg = "password not defined in " + f.getAbsolutePath();
	    log.fatal(msg);
	    throw new IllegalStateException(msg);
	}

	String authips = props.getProperty("ip");
	if (authips != null) {
	    try {
		addressChecker = new AddressChecker(authips);
	    } catch (IcatException e) {
		String msg = "Problem creating AddressChecker with information from "
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
					"authn_db does not allow log in from your IP address " + remoteAddr);
	    }
	}

	String username = credentials.get("username");
	log.trace("login:" + username);
	if (username == null || username.equals("")) {
	    throw new IcatException(IcatException.IcatExceptionType.SESSION,
				    "Username cannot be null or empty.");
	}
	String password = credentials.get("password");
	if (password == null || password.equals("")) {
	    throw new IcatException(IcatException.IcatExceptionType.SESSION,
				    "Password cannot be null or empty.");
	}

	Passwd pass = passwordtable.get(username);
	if (pass == null || ! pass.verify(password)) {
	    throw new IcatException(IcatException.IcatExceptionType.SESSION,
				    "The username and password do not match.");
	}

	log.info(username + " logged in succesfully");
	return new Authentication(username, mechanism);

    }

}
