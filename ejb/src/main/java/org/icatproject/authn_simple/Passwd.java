package org.icatproject.authn_simple;

import org.apache.commons.codec.digest.Crypt;

public class Passwd
{

    private String pwHashStr;

    public Passwd(String pass)
    {
	pwHashStr = pass;
    }

    public boolean verify(String pass)
    {
	if (pwHashStr == null || pwHashStr.length() == 0)
	    return false;

	if (pwHashStr.charAt(0) == '$') {
	    return pwHashStr.equals(Crypt.crypt(pass, pwHashStr));
	}
	else {
	    return pwHashStr.equals(pass);
	}
    }

}

