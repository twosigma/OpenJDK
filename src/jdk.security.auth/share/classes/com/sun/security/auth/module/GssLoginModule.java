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

import java.text.MessageFormat;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import javax.security.auth.Subject;
import javax.security.auth.SubjectDomainCombiner;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import static sun.security.util.ResourcesMgr.getAuthResourceString;

/**
 * <p>This {@code LoginModule} authenticates users using a GSS-API
 * mechanism.</p>
 *
 * <p> The configuration entry for {@code GssLoginModule} has
 * several options that control the authentication process and
 * additions to the {@code Subject}'s private credential
 * set. Irrespective of these options, the {@code Subject}'s
 * principal set and private credentials set are updated only when
 * {@code commit} is called.
 * When {@code commit} is called, the {@code GSSName} is added to the
 * {@code Subject}'s principal set. If {@code initiate} is true, the
 * initiator credential will be added to the {@code Subject}'s private
 * credentials.</p>
 *
 * <p> If the configuration entry for {@code GssLoginModule}
 * has the option {@code accept} set to true, then acceptor credential
 * will be added to the subject's private credentials.</p>
 *
 * <p> This {@code LoginModule} recognizes the {@code doNotPrompt}
 * option. If set to true the user will not be prompted for their password.</p>
 *
 * <p> When using the GSS-API Kerberos mechanism, the user can specify
 * the location of the ticket cache by using the option
 * {@code ticketCache} in the configuration entry. Similarly, a keytab
 * can be specified using the option {@code keyTab} in the
 * configuration entry.</p>
 *
 * <p> Other credential store options can be specified as
 * {@code credStoreKeyValue_KEY}, where {@code KEY} is the name of a
 * credential store key supported by the GSS-API mechanism provider.
 * When using platform native GSS-API providers, consult their
 * documentation (for example, look for the {@code gss_acquire_cred_from()}
 * and {@code gss_store_cred_into()} functions).</p>
 *
 * <p> The principal name can be specified in the configuration entry
 * by using the option {@code name} and {@code nameType}. The principal name
 * can either be a simple user name, a service name such as
 * {@code host@mission.eng.sun.com}. The principal can also
 * be set using the system property
 * {@systemProperty sun.security.gss.name}, and its name-type can be set
 * with {@systemProperty sun.security.gss.nametype}.
 * These properties are checked during login if the name and name-type
 * are not set in the configuration.  In the case where the principal
 * property is not set and the principal entry also does not exist, the
 * user is prompted for the name.</p>
 *
 * <p> The following is a list of configuration options supported
 * for {@code GssLoginModule}:
 * <blockquote><dl>
 * <dt>{@code doNotPrompt}:</dt>
 * <dd>Set this to true if you do not want to be
 * prompted for the password
 * if credentials can not be obtained from the cache, the keytab,
 * or through shared state.(Default is false)
 * If set to true, credential must be obtained through cache, keytab,
 * or shared state. Otherwise, authentication will fail.</dd>
 * <dt>{@code ticketCache}:</dt>
 * <dd>Set this to the name of the ticket cache file that contains
 * user's TGT.</dd>
 * <dt>{@code keyTab}:</dt>
 * <dd>Set this to the file name of the keytab to get principal's secret
 * key(s).</dd>
 * <dt>{@code name}:</dt>
 * <dd>The name of the principal that should be used. The principal can
 * be a simple username such as "{@code testuser}" or a service name
 * such as "{@code host@testhost.eng.sun.com}". You can use the
 * {@code principal} option to set the principal when there are
 * credentials for multiple principals in the {@code keyTab} or when you
 * want a specific ticket cache only. The principal can also be set
 * using the system property {@code sun.security.gss.name}. The value
 * from the configuration takes precedence.</dd>
 * <dt>{@code nametype}:</dt>
 * <dd>This is the type of the name. This can be "{@code username}",
 * "{@code hostbased}", or an OID, and defaults to "{@code username}".</dd>
 * <dt>{@code initiate}:</dt>
 * <dd>Set this to true, if you need to acquire initiator
 * credentials.</dd>
 * <dt>{@code accept}:</dt>
 * <dd>Set this to true, if you need to acquire acceptor
 * credentials. Either or both of {@code initiate} and {@code accept}
 * may be set to true. If both are false then {@code initiate} will be
 * treated as true.</dd>
 * </dl></blockquote></p>
 *
 * <p> This {@code LoginModule} also recognizes the following additional
 * {@code Configuration}
 * options that enable you to share username and passwords across different
 * authentication modules:
 * <blockquote><dl>
 *
 *    <dt>{@code useFirstPass}:</dt>
 *                   <dd>if, true, this LoginModule retrieves the
 *                   username and password from the module's shared state,
 *                   using "javax.security.auth.login.name" and
 *                   "javax.security.auth.login.password" as the respective
 *                   keys. The retrieved values are used for authentication.
 *                   If authentication fails, no attempt for a retry
 *                   is made, and the failure is reported back to the
 *                   calling application.</dd>
 *
 *    <dt>{@code tryFirstPass}:</dt>
 *                   <dd>if, true, this LoginModule retrieves the
 *                   the username and password from the module's shared
 *                   state using "javax.security.auth.login.name" and
 *                   "javax.security.auth.login.password" as the respective
 *                   keys.  The retrieved values are used for
 *                   authentication.
 *                   If authentication fails, the module uses the
 *                   CallbackHandler to retrieve a new username
 *                   and password, and another attempt to authenticate
 *                   is made. If the authentication fails,
 *                   the failure is reported back to the calling application</dd>
 *
 *    <dt>{@code storePass}:</dt>
 *                   <dd>if, true, this LoginModule stores the username and
 *                   password obtained from the CallbackHandler in the
 *                   modules shared state, using
 *                   "javax.security.auth.login.name" and
 *                   "javax.security.auth.login.password" as the respective
 *                   keys.  This is not performed if existing values already
 *                   exist for the username and password in the shared
 *                   state, or if authentication fails.</dd>
 *
 *    <dt>{@code clearPass}:</dt>
 *                   <dd>if, true, this LoginModule clears the
 *                   username and password stored in the module's shared
 *                   state  after both phases of authentication
 *                   (login and commit) have completed.</dd>
 * </dl></blockquote></p>
 * <p>If the principal system property or key is already provided, the value of
 * "javax.security.auth.login.name" in the shared state is ignored.</p>
 *
 * <p>Note that if any step fails, it will fallback to the next step.
 * There's only one exception, if the shared state step fails and
 * {@code useFirstPass = true}, no user prompt is made.</p>
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

    private boolean useNative; // sun.security.jgss.native property

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

    private String password = null;
    private Map<String,String> store = new HashMap<String,String>();

    private static final String NAME = "javax.security.auth.login.name";
    private static final String PWD = "javax.security.auth.login.password";

    /**
     * Creates a {@code GssLoginModule}.
     */
    public GssLoginModule() { }

    private String getString(String key) {
        return (String)options.get(key);
    }
    private boolean getBool(String key) {
        String value = (String)options.get(key);
        return value != null ? Boolean.parseBoolean(value) : false;
    }
    private boolean getBoolWithDefault(String key, boolean defval) {
        String value = (String)options.get(key);
        return value != null ? Boolean.parseBoolean(value) : defval;
    }

    private void storeAddKeyValue(String key, String value) {
        store.put(key, value);
    }

    private void storeAddOption(String optionName, String key) {
        if (options.containsKey(optionName)) {
            storeAddKeyValue(key, getString(optionName));
        }
    }

    private void storeAddOptions() {
        for (String key : options.keySet()) {
            if (!key.startsWith("credStoreKeyValue_"))
                continue;
            storeAddOption(key, key.substring("credStoreKeyValue_".length()));
        }
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

        /*
         * When sun.security.jgss.native=false (i.e., not using the system's
         * native C/ELF/DLL GSS implementation) then there's nothing for this
         * login module to do.  Otherwise we'd get into an infinite recursion
         * problem due to re-entering GssLoginModule like this:
         *
         * Application -> LoginContext -> GssLoginModule -> Krb5 ->
         *      GSSUtil.login -> LoginContext -> GssLoginModule -> ...
         *
         * It stands to reason that when sun.security.jgss.native=false the
         * login modules corresponding to the actual GSS mechanisms coded in
         * Java are the ones that should be acquiring their corresponding
         * credentials.
         *
         * A policy like "let the application use GSS credentials but not the
         * raw, underlying Krb5 credentials" when
         * sun.security.jgss.native=false" could be expressible by adding a
         * module option to Krb5LoginModule that causes it to add only GSS
         * credentials to the Subject, not Krb5 credentials.
         *
         * (It has never been possible to express such a policy, so we lose
         * nothing by punting here when sun.security.jgss.native=false.)
         */
        useNative = Boolean.getBoolean("sun.security.jgss.native");
        if (!useNative)
            return;

        manager = GSSManager.getInstance();

        // initialize any configured options

        debug = getBool("debug");
        doNotPrompt = getBool("doNotPrompt");
        defName = getString("name");
        nametype = getString("nametype");

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

        storeAddOptions();
        storeAddOption("keyTab", "keytab");
        storeAddOption("clientKeyTab", "client_keytab");
        storeAddOption("ticketCache", "ccache");
        storeAddOption("replayCache", "rcache");

        tryFirstPass = getBool("tryFirstPass");
        useFirstPass = getBoolWithDefault("useFirstPass", doNotPrompt);
        storePass = getBool("storePass");
        clearPass = getBool("clearPass");
        initiate = getBool("initiate");
        accept = getBool("accept");
        tryDefaultCreds = getBool("tryDefaultCreds");
        useDefaultCreds = getBoolWithDefault("useDefaultCreds", doNotPrompt);
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
            System.out.print("Credential store options are:");
            if (store.size() == 0) {
                System.out.print(" <none>");
            } else {
                for (var e : store.entrySet()) {
                    System.out.print(" " + e.getKey() + "=" + e.getValue() + ";");
                }
            }
            System.out.println("");
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

        /*
         * See commentary in initialize().  By returning false we cause
         * LoginContext to ignore this module.
         */
        if (!useNative)
            return false;
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
            if (password == null && store.size() == 0) {
                if (debug)
                    System.out.println("\t\t[GssLoginModule] acquiring" +
                        ((gssName == null) ? " default" : "") +
                        " initiator credentials...");
                gssICred = manager.createCredential(gssName,
                        GSSCredential.DEFAULT_LIFETIME, (Oid[])null,
                        GSSCredential.INITIATE_ONLY);
            } else if (password != null) {
                if (debug)
                    System.out.println("\t\t[GssLoginModule] acquiring" +
                        " initiator credentials using a password...");
                gssICred = manager.createCredential(gssName, password,
                        GSSCredential.DEFAULT_LIFETIME, (Oid[])null,
                        GSSCredential.INITIATE_ONLY);
            } else {
                if (debug)
                    System.out.println("\t\t[GssLoginModule] acquiring" +
                        ((gssName == null) ? " default" : "") +
                        " initiator credentials using a specified" +
                        " credential store...");
                gssICred = manager.createCredential(gssName, store,
                        GSSCredential.DEFAULT_LIFETIME, (Oid[])null,
                        GSSCredential.INITIATE_ONLY);
            }
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
        if (gssName == null && gssICred != null)
            gssName = gssICred.getName();
        if (gssName == null && gssACred != null)
            gssName = gssACred.getName();
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

            MessageFormat form = new MessageFormat(
                                   getAuthResourceString(
                                   "username."));
            Object[] source =  {defUsername};
            Callback[] callbacks = {new NameCallback(form.format(source))};
            callbackHandler.handle(callbacks);
            NameCallback callback = (NameCallback)callbacks[0];
            name = callback.getName();
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
            throw new LoginException("Unable to prompt for password");

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
                                     "password."));
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
            Arrays.fill(tmpPassword, ' ');
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

        if (!useNative)
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
        /*
         * See commentary in initialize().  By returning false we cause
         * LoginContext to ignore this module.
         */
        if (!useNative)
            return false;

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
