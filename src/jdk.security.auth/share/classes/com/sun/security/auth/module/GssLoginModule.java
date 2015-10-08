/*
 * Copyright (c) 2000, 2017-2018 Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package com.sun.security.auth.module;

import java.io.*;
import java.text.MessageFormat;
import java.util.*;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.security.auth.spi.*;

import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import static sun.security.util.ResourcesMgr.getAuthResourceString;

/**
 * <p>This <code>LoginModule</code> authenticates users using the
 * GSS-API.</p>
 */

public class GssLoginModule implements LoginModule {

    // From initialize
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, Object> sharedState;
    private Map<String, ?> options;

    // Configuration option
    private boolean debug;
    private boolean doNotPrompt;
    private String defName;
    private String name;
    private String nametype; // username, hostbased, unspecified
    private Oid nametypeOid;

    private GSSManager manager;
    private GSSName gssName;
    private GSSCredential gssICred;
    private GSSCredential gssACred;

    private boolean useFirstPass;
    private boolean tryFirstPass;
    private boolean storePass;
    private boolean clearPass;
    private boolean initiate;
    private boolean accept;
    private boolean tryDefaultCreds;
    private boolean useDefaultCreds;

    // Module state
    private boolean succeeded;
    private boolean commitSucceeded;

    private String password;

    private static final String NAME = "javax.security.auth.login.name";
    private static final String PWD = "javax.security.auth.login.password";

    private String getWithDefault(String key, String defval) {
        String value = (String)options.get(key);
        return value != null ? value : defval;
    }

    /**
     * Initialize this <code>LoginModule</code>.
     *
     * <p>
     * @param subject the <code>Subject</code> to be authenticated.</p>
     *
     * <p>
     * @param callbackHandler a <code>CallbackHandler</code> for
     *                  communication with the end user (prompting for
     *                  usernames and passwords, for example).</p>
     *
     * <p>
     * @param sharedState shared <code>LoginModule</code> state.</p>
     *
     * <p>
     * @param options options specified in the login
     *                  <code>Configuration</code> for this particular
     *                  <code>LoginModule</code>.</p>
     */
    // Unchecked warning from (Map<String, Object>)sharedState is safe
    // since javax.security.auth.login.LoginContext passes a raw HashMap.
    // Unchecked warnings from options.get(String) are safe since we are
    // passing known keys.
    @SuppressWarnings("unchecked")
    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {

        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = (Map<String, Object>)sharedState;
        this.options = options;

        manager = GSSManager.getInstance();

        // initialize any configured options

        debug = "true".equalsIgnoreCase((String)options.get("debug"));
        doNotPrompt =
            "true".equalsIgnoreCase(getWithDefault("doNotPrompt", "true"));
        defName = (String)options.get("name");
        nametype = (String)options.get("nametype");

        if (defName == null)
            defName = System.getProperty("sun.security.gss.name");
        if (nametype == null)
            nametype = System.getProperty("sun.security.gss.nametype");
        if (nametype == null || nametype.equals("username")) {
            nametypeOid = GSSName.NT_USER_NAME;
        } else if (nametype.equals("hostbased")) {
            nametypeOid = GSSName.NT_HOSTBASED_SERVICE;
        } else if (!nametype.equals("")) {
            try {
                nametypeOid = new Oid(nametype);
            } catch (GSSException e) {
                if (debug)
                    System.out.print("Unknown name type OID " + nametype);
                nametypeOid = null;
            }
        } else {
            nametype = "<default: username>";
            nametypeOid = GSSName.NT_USER_NAME;
        }

        tryFirstPass =
            "true".equalsIgnoreCase(getWithDefault("tryFirstPass", "true"));
        useFirstPass =
            "true".equalsIgnoreCase(
                getWithDefault("useFirstPass",
                    doNotPrompt ? "true" : "false"));
        storePass =
            "true".equalsIgnoreCase((String)options.get("storePass"));
        clearPass =
            "true".equalsIgnoreCase((String)options.get("clearPass"));
        initiate =
            "true".equalsIgnoreCase((String)options.get("initiate"));
        accept =
            "true".equalsIgnoreCase((String)options.get("accept"));
        tryDefaultCreds =
            "true".equalsIgnoreCase(getWithDefault("tryDefaultCreds", "true"));
        useDefaultCreds =
            "true".equalsIgnoreCase(
                getWithDefault("useDefaultCreds",
                    doNotPrompt ? "true" : "false"));
        if (!initiate && !accept)
            initiate = true;
        if (debug) {
            System.out.print("Debug is  " + debug
                             + " doNotPrompt " + doNotPrompt
                             + " defName is " + defName
                             + " nametype is " + nametype
                             + " tryFirstPass is " + tryFirstPass
                             + " useFirstPass is " + useFirstPass
                             + " storePass is " + storePass
                             + " clearPass is " + clearPass
                             + " initiate is " + initiate
                             + " accept is " + accept
                             + " tryDefaultCreds is " + tryDefaultCreds
                             + " useDefaultCreds is " + useDefaultCreds + "\n");
        }
    }


    /**
     * Authenticate the user
     *
     * <p>
     *
     * @return true in all cases since this <code>LoginModule</code>
     *          should not be ignored.</p>
     *
     * <p>
     * @exception FailedLoginException if the authentication fails.</p>
     *
     * <p>
     * @exception LoginException if this <code>LoginModule</code>
     *          is unable to perform the authentication.</p>
     */
    public boolean login() throws LoginException {
        succeeded = false;
        try {
            if (tryFirstPass || useFirstPass) {
                attemptAuthentication(true);
                if (debug)
                    System.out.println("\t\t[GssLoginModule] " +
                                       "authentication succeeded");
                succeeded = true;
                cleanState();
                return true;
            }
        } catch (LoginException le) {
            // authentication failed -- try again below by prompting
            cleanState();
            if (debug) {
                System.out.println("\t\t[GssLoginModule] " +
                                   (tryFirstPass ? "tryFirstPass " : "") +
                                   "authentication failed with:" +
                                   le.getMessage());
            }
            if (useFirstPass)
                throw le;
        }

        // The first password didn't work or we didn't try it, try prompting
        try {
            attemptAuthentication(false);
            if (debug)
                System.out.println("\t\t[GssLoginModule] " +
                                   "authentication succeeded");
            succeeded = true;
            cleanState();
            return true;
        } catch (LoginException le2) {
            cleanState();
            if (debug) {
                System.out.println("\t\t[GssLoginModule] " +
                                   (tryFirstPass ? "tryFirstPass " : "") +
                                   "authentication failed with:" +
                                   le2.getMessage());
            }
            throw le2;
        }
    }

    private void getcreds() throws GSSException {
        if (initiate) {
            if (debug)
                System.out.println("\t\t[GssLoginModule] acquiring" +
                    ((gssName == null) ? " default" : "") +
                    " initiator credentials...");
            gssICred = manager.createCredential(gssName, password,
                    GSSCredential.DEFAULT_LIFETIME, (Oid[])null,
                    GSSCredential.INITIATE_ONLY);
            if (gssName == null)
                gssName = gssICred.getName();
            if (debug)
                System.out.println("\t\t[GssLoginModule] acquired" +
                    " initiator credentials: " + gssName);
        }
        if (accept) {
            if (debug)
                System.out.println("\t\t[GssLoginModule] acquiring" +
                    ((gssName == null) ? " default" : "") +
                    " acceptor credentials...");
            gssACred = manager.createCredential(gssName, password,
                    GSSCredential.DEFAULT_LIFETIME, (Oid[])null,
                    GSSCredential.ACCEPT_ONLY);
            // Default acceptor credentials retain a null name
            if (debug)
                System.out.println("\t\t[GssLoginModule] acquired" +
                    " acceptor credentials");
        }
    }

    private void attemptAuthentication(boolean getPasswdFromSharedState)
        throws LoginException {

        // Get a name, maybe
        if (name == null) {
            if (useDefaultCreds) {
                try {
                    getcreds();
                    return;
                } catch (GSSException e) {
                    throw new LoginException(e.getMessage());
                }
            }
            if (tryDefaultCreds) {
                try {
                    getcreds();
                    return;
                } catch (GSSException e) { }
            }

            promptForName(getPasswdFromSharedState);
            if (name == null)
                throw new LoginException ("Unable to determine a GSS name");
        }

        try {
            gssName = manager.createName(name, nametypeOid);
        } catch (GSSException e) {
            throw new LoginException ("Unable to import GSS name");
        }

        promptForPass(getPasswdFromSharedState);

        try {
            getcreds();
        } catch (GSSException e) {
            throw new LoginException(e.getMessage());
        }
    }

    private void promptForName(boolean getPasswdFromSharedState)
        throws LoginException {
        if (getPasswdFromSharedState) {
            // use the name saved by a module earlier in the stack
            name = (String)sharedState.get(NAME);
            if (name == null || name.length() == 0)
                name = defName;
            if (debug) {
                System.out.println("\t\t[GssLoginModule] username from" +
		    " shared state is " + name);
            }
            if (name != null && name.length() > 0)
                return;
        }

        if (doNotPrompt)
            return; // name may be null

        if (callbackHandler == null)
            throw new LoginException("No CallbackHandler "
                                     + "available "
                                     + "to prompt for authentication "
                                     + "information from the user");

        try {
            String defUsername = System.getProperty("user.name");

            Callback[] callbacks = new Callback[1];
            MessageFormat form = new MessageFormat(
                                   getAuthResourceString(
                                   "GSS.name.defName."));
            Object[] source =  {defUsername};
            callbacks[0] = new NameCallback(form.format(source));
            callbackHandler.handle(callbacks);
            name = ((NameCallback)callbacks[0]).getName();
            if (name != null && name.length() == 0)
                name = null;
            if (name == null && defUsername != null &&
                    defUsername.length() != 0)
                name = defUsername;
        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.getMessage());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException
                (uce.getMessage()
                 +" not available to garner "
                 +" authentication information "
                 +" from the user");
        }
        // name may still be null, which we take to mean "use default
        // credentials"
    }

    private void promptForPass(boolean getPasswdFromSharedState)
        throws LoginException {

        char[] pw;

        if (getPasswdFromSharedState) {
            // use the password saved by the first module in the stack
            pw = (char[])sharedState.get(PWD);
            if (pw == null) {
                if (debug)
                    System.out.println("\t\t[GssLoginModule] password from" +
			" shared state is null");
                throw new LoginException
                    ("Password can not be obtained from sharedstate ");
            }
            password = new String(pw);
            return;
        }
        if (doNotPrompt)
            throw new LoginException("Unable to prompt for password\n");

        if (callbackHandler == null) {
            throw new LoginException("No CallbackHandler "
                                     + "available "
                                     + "to garner authentication "
                                     + "information from the user");
        }
        try {
            Callback[] callbacks = new Callback[1];
            MessageFormat form = new MessageFormat(
                                     getAuthResourceString(
                                     "Kerberos.password.for.username."));
            Object[] source = {name};
            callbacks[0] = new PasswordCallback(form.format(source), false);
            callbackHandler.handle(callbacks);
            char[] tmpPassword = ((PasswordCallback)
                                  callbacks[0]).getPassword();
            if (tmpPassword == null)
                throw new LoginException("No password provided");
            password = new String(tmpPassword);
            ((PasswordCallback)callbacks[0]).clearPassword();

            // clear tmpPassword
            for (int i = 0; i < tmpPassword.length; i++)
                tmpPassword[i] = ' ';
        } catch (java.io.IOException ioe) {
            throw new LoginException(ioe.getMessage());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException(uce.getMessage()
                                     +" not available to garner "
                                     +" authentication information "
                                     + "from the user");
        }
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication succeeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
     * LoginModules succeeded).</p>
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> method), then this method associates a
     * <code>GSSName</code>
     * with the <code>Subject</code> located in the
     * <code>LoginModule</code>. It adds GSS Credentials to the
     * the Subject's private credentials set. If this LoginModule's own
     * authentication attempted failed, then this method removes
     * any state that was originally saved.</p>
     *
     * <p>
     *
     * @exception LoginException if the commit fails.</p>
     *
     * <p>
     * @return true if this LoginModule's own login and commit
     *          attempts succeeded, or false otherwise.</p>
     */

    public boolean commit() throws LoginException {
        if (succeeded == false)
            return false;

        succeeded = false;
        if (initiate && (gssICred == null)) {
            gssName = null;
            gssICred = null;
            gssACred = null;
            throw new LoginException("Null Initiator Credential");
        }
        if (accept && (gssACred == null)) {
            gssName = null;
            gssICred = null;
            gssACred = null;
            throw new LoginException("Null Acceptor Credential");
        }
        if (subject.isReadOnly()) {
            gssName = null;
            gssICred = null;
            gssACred = null;
            throw new LoginException("Subject is Readonly");
        }

        try {
            if (initiate && gssName == null)
                gssName = gssICred.getName();
        } catch (GSSException e) {}
        try {
            if (accept && gssName == null)
                gssName = gssACred.getName();
        } catch (GSSException e) {}

        Set<Object> privCredSet = subject.getPrivateCredentials();
        Set<java.security.Principal> princSet = subject.getPrincipals();

        if (gssName != null && !princSet.contains(gssName))
            princSet.add(gssName);
        if (gssICred != null && !privCredSet.contains(gssICred))
            privCredSet.add(gssICred);
        if (gssACred != null && !privCredSet.contains(gssACred))
            privCredSet.add(gssACred);

        succeeded = true;
        commitSucceeded = true;
        if (debug)
            System.out.println("\t\t[GssLoginModule] commit Succeeded");
        return true;
    }

    /**
     * <p> This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
     * LoginModules did not succeed).</p>
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * <code>login</code> and <code>commit</code> methods),
     * then this method cleans up any state that was originally
     * saved.</p>
     *
     * <p>
     *
     * @exception LoginException if the abort fails.</p>
     *
     * <p>
     * @return false if this LoginModule's own login and/or commit attempts
     *          failed, and true otherwise.</p>
     */

    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * <p>Logout the user.</p>
     *
     * <p>This method removes the <code>GSSName</code> and
     * <code>GSSCredential</code> added by the <code>commit</code> method.</p>
     *
     * <p>
     *
     * @exception LoginException if the logout fails.</p>
     *
     * <p>
     * @return true in all cases since this <code>LoginModule</code>
     *          should not be ignored.</p>
     */
    public boolean logout() throws LoginException {
        if (subject.isReadOnly())
            throw new LoginException("Subject is Readonly");

        subject.getPrincipals().remove(gssName);
        Iterator<Object> it = subject.getPrivateCredentials().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof GSSCredential)
                it.remove();
        }

        succeeded = false;
        commitSucceeded = false;
        if (debug)
            System.out.println("\t\t[GSSLoginModule]: logged out Subject");
        return true;
    }

    /**
     * Clean out the state
     */
    private void cleanState() {

        // save input as shared state only if
        // authentication succeeded
        if (succeeded) {
            if (storePass &&
                !sharedState.containsKey(NAME) &&
                !sharedState.containsKey(PWD)) {
                sharedState.put(NAME, name);
                sharedState.put(PWD, password);
            }
        } else {
            // remove temp results for the next try
            gssName = null;
            gssICred = null;
            gssACred = null;
        }
        name = null;
        password = null;
        if (clearPass) {
            sharedState.remove(NAME);
            sharedState.remove(PWD);
        }
    }
}
