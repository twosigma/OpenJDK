/*
 * Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.
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
import java.security.Principal;
import java.text.MessageFormat;
import java.util.*;

import javax.security.auth.*;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KeyTab;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.security.auth.spi.*;

import sun.security.krb5.*;
import sun.security.jgss.krb5.Krb5Util;
import sun.security.krb5.Credentials;
import sun.security.util.HexDumpEncoder;
import static sun.security.util.ResourcesMgr.getAuthResourceString;

/**
 * This {@code LoginModule} authenticates users using
 * Kerberos protocols.
 *
 * <p> The configuration entry for {@code Krb5LoginModule} has
 * several options that control the authentication process and
 * additions to the {@code Subject}'s private credential
 * set. Irrespective of these options, the {@code Subject}'s
 * principal set and private credentials set are updated only when
 * {@code commit} is called.
 * When {@code commit} is called, the {@code KerberosPrincipal}
 * is added to the {@code Subject}'s principal set (unless the
 * {@code principal} is specified as "*"). If {@code isInitiator}
 * is true, the {@code KerberosTicket} is
 * added to the {@code Subject}'s private credentials.
 *
 * <p> If the configuration entry for {@code KerberosLoginModule}
 * has the option {@code storeKey} set to true, then
 * {@code KerberosKey} or {@code KeyTab} will also be added to the
 * subject's private credentials. {@code KerberosKey}, the principal's
 * key(s) will be derived from user's password, and {@code KeyTab} is
 * the keytab used when {@code useKeyTab} is set to true. The
 * {@code KeyTab} object is restricted to be used by the specified
 * principal unless the principal value is "*".
 *
 * <p> This {@code LoginModule} recognizes the {@code doNotPrompt}
 * option. If set to true the user will not be prompted for the password.
 *
 * <p> The user can  specify the location of the ticket cache by using
 * the option {@code ticketCache} in the configuration entry.
 *
 * <p>The user can specify the keytab location by using
 * the option {@code keyTab}
 * in the configuration entry.
 *
 * <p> The principal name can be specified in the configuration entry
 * by using the option {@code principal}. The principal name
 * can either be a simple user name, a service name such as
 * {@code host/mission.eng.sun.com}, or "*". The principal can also
 * be set using the system property {@systemProperty sun.security.krb5.principal}.
 * This property is checked during login. If this property is not set, then
 * the principal name from the configuration is used. In the
 * case where the principal property is not set and the principal
 * entry also does not exist, the user is prompted for the name.
 * When this property of entry is set, and {@code useTicketCache}
 * is set to true, only TGT belonging to this principal is used.
 *
 * <p> The following is a list of configuration options supported
 * for {@code Krb5LoginModule}:
 * <blockquote><dl>
 * <dt>{@code refreshKrb5Config}:</dt>
 * <dd> Set this to true, if you want the configuration
 * to be refreshed before the {@code login} method is called.</dd>
 * <dt>{@code useTicketCache}:</dt>
 * <dd>Set this to true, if you want the
 * TGT to be obtained from the ticket cache. Set this option
 * to false if you do not want this module to use the ticket cache.
 * (Default is False).
 * This module will search for the ticket
 * cache in the following locations: On Linux
 * it will look for the ticket cache in /tmp/krb5cc_{@code uid}
 * where the uid is numeric user identifier. If the ticket cache is
 * not available in the above location, or if we are on a
 * Windows platform, it will look for the cache as
 * {user.home}{file.separator}krb5cc_{user.name}.
 * You can override the ticket cache location by using
 * {@code ticketCache}.
 * For Windows, if a ticket cannot be retrieved from the file ticket cache,
 * it will use Local Security Authority (LSA) API to get the TGT.
 * <dt>{@code ticketCache}:</dt>
 * <dd>Set this to the name of the ticket
 * cache that  contains user's TGT.
 * If this is set,  {@code useTicketCache}
 * must also be set to true; Otherwise a configuration error will
 * be returned.</dd>
 * <dt>{@code renewTGT}:</dt>
 * <dd>Set this to true, if you want to renew the TGT when it's more than
 * half-way expired (the time until expiration is less than the time
 * since start time). If this is set, {@code useTicketCache} must also be
 * set to true; otherwise a configuration error will be returned.</dd>
 * <dt>{@code doNotPrompt}:</dt>
 * <dd>Set this to true if you do not want to be
 * prompted for the password
 * if credentials can not be obtained from the cache, the keytab,
 * or through shared state.(Default is false)
 * If set to true, credential must be obtained through cache, keytab,
 * or shared state. Otherwise, authentication will fail.</dd>
 * <dt>{@code useKeyTab}:</dt>
 * <dd>Set this to true if you
 * want the module to get the principal's key from the
 * the keytab.(default value is False)
 * If {@code keytab} is not set then
 * the module will locate the keytab from the
 * Kerberos configuration file.
 * If it is not specified in the Kerberos configuration file
 * then it will look for the file
 * {@code {user.home}{file.separator}}krb5.keytab.</dd>
 * <dt>{@code keyTab}:</dt>
 * <dd>Set this to the file name of the
 * keytab to get principal's secret key.</dd>
 * <dt>{@code storeKey}:</dt>
 * <dd>Set this to true to if you want the keytab or the
 * principal's key to be stored in the Subject's private credentials.
 * For {@code isInitiator} being false, if {@code principal}
 * is "*", the {@link KeyTab} stored can be used by anyone, otherwise,
 * it's restricted to be used by the specified principal only.</dd>
 * <dt>{@code principal}:</dt>
 * <dd>The name of the principal that should
 * be used. The principal can be a simple username such as
 * "{@code testuser}" or a service name such as
 * "{@code host/testhost.eng.sun.com}". You can use the
 * {@code principal}  option to set the principal when there are
 * credentials for multiple principals in the
 * {@code keyTab} or when you want a specific ticket cache only.
 * The principal can also be set using the system property
 * {@code sun.security.krb5.principal}. In addition, if this
 * system property is defined, then it will be used. If this property
 * is not set, then the principal name from the configuration will be
 * used.
 * The principal name can be set to "*" when {@code isInitiator} is false.
 * In this case, the acceptor is not bound to a single principal. It can
 * act as any principal an initiator requests if keys for that principal
 * can be found. When {@code isInitiator} is true, the principal name
 * cannot be set to "*".
 * </dd>
 * <dt>{@code isInitiator}:</dt>
 * <dd>Set this to true, if initiator. Set this to false, if acceptor only.
 * (Default is true).
 * Note: Do not set this value to false for initiators.</dd>
 * </dl></blockquote>
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
 * </dl></blockquote>
 * <p>If the principal system property or key is already provided, the value of
 * "javax.security.auth.login.name" in the shared state is ignored.
 * <p>When multiple mechanisms to retrieve a ticket or key is provided, the
 * preference order is:
 * <ol>
 * <li>ticket cache
 * <li>keytab
 * <li>shared state
 * <li>user prompt
 * </ol>
 *
 * <p>Note that if any step fails, it will fallback to the next step.
 * There's only one exception, if the shared state step fails and
 * {@code useFirstPass = true}, no user prompt is made.
 * <p>Examples of some configuration values for Krb5LoginModule in
 * JAAS config file and the results are:
 * <blockquote>
 * <pre>{@code
 * doNotPrompt = true}</pre>
 * This is an illegal combination since none of {@code useTicketCache,
 * useKeyTab, useFirstPass} and {@code tryFirstPass}
 * is set and the user can not be prompted for the password.
 *
 * <pre>{@code
 * ticketCache = <filename>}</pre>
 * This is an illegal combination since {@code useTicketCache}
 * is not set to true and the ticketCache is set. A configuration error
 * will occur.
 *
 * <pre>{@code
 * renewTGT = true}</pre>
 * This is an illegal combination since {@code useTicketCache} is
 * not set to true and renewTGT is set. A configuration error will occur.
 *
 * <pre>{@code
 * storeKey = true  useTicketCache = true  doNotPrompt = true}</pre>
 * This is an illegal combination since  {@code storeKey} is set to
 * true but the key can not be obtained either by prompting the user or from
 * the keytab, or from the shared state. A configuration error will occur.
 *
 * <pre>{@code
 * keyTab = <filename>  doNotPrompt = true}</pre>
 * This is an illegal combination since useKeyTab is not set to true and
 * the keyTab is set. A configuration error will occur.
 *
 * <pre>{@code
 * debug = true}</pre>
 * Prompt the user for the principal name and the password.
 * Use the authentication exchange to get TGT from the KDC and
 * populate the {@code Subject} with the principal and TGT.
 * Output debug messages.
 *
 * <pre>{@code
 * useTicketCache = true  doNotPrompt = true}</pre>
 * Check the default cache for TGT and populate the {@code Subject}
 * with the principal and TGT. If the TGT is not available,
 * do not prompt the user, instead fail the authentication.
 *
 * <pre>{@code
 * principal = <name>  useTicketCache = true  doNotPrompt = true}</pre>
 * Get the TGT from the default cache for the principal and populate the
 * Subject's principal and private creds set. If ticket cache is
 * not available or does not contain the principal's TGT
 * authentication will fail.
 *
 * <pre>{@code
 * useTicketCache = true
 * ticketCache = <file name>
 * useKeyTab = true
 * keyTab = <keytab filename>
 * principal = <principal name>
 * doNotPrompt = true}</pre>
 * Search the cache for the principal's TGT. If it is not available
 * use the key in the keytab to perform authentication exchange with the
 * KDC and acquire the TGT.
 * The Subject will be populated with the principal and the TGT.
 * If the key is not available or valid then authentication will fail.
 *
 * <pre>{@code
 * useTicketCache = true  ticketCache = <filename>}</pre>
 * The TGT will be obtained from the cache specified.
 * The Kerberos principal name used will be the principal name in
 * the Ticket cache. If the TGT is not available in the
 * ticket cache the user will be prompted for the principal name
 * and the password. The TGT will be obtained using the authentication
 * exchange with the KDC.
 * The Subject will be populated with the TGT.
 *
 * <pre>{@code
 * useKeyTab = true  keyTab=<keytab filename>  principal = <principal name>  storeKey = true}</pre>
 * The key for the principal will be retrieved from the keytab.
 * If the key is not available in the keytab the user will be prompted
 * for the principal's password. The Subject will be populated
 * with the principal's key either from the keytab or derived from the
 * password entered.
 *
 * <pre>{@code
 * useKeyTab = true  keyTab = <keytabname>  storeKey = true  doNotPrompt = false}</pre>
 * The user will be prompted for the service principal name.
 * If the principal's
 * longterm key is available in the keytab , it will be added to the
 * Subject's private credentials. An authentication exchange will be
 * attempted with the principal name and the key from the Keytab.
 * If successful the TGT will be added to the
 * Subject's private credentials set. Otherwise the authentication will fail.
 *
 * <pre>{@code
 * isInitiator = false  useKeyTab = true  keyTab = <keytabname>  storeKey = true  principal = *}</pre>
 * The acceptor will be an unbound acceptor and it can act as any principal
 * as long that principal has keys in the keytab.
 *
 * <pre>{@code
 * useTicketCache = true
 * ticketCache = <file name>
 * useKeyTab = true
 * keyTab = <file name>
 * storeKey = true
 * principal = <principal name>}</pre>
 * The client's TGT will be retrieved from the ticket cache and added to the
 * {@code Subject}'s private credentials. If the TGT is not available
 * in the ticket cache, or the TGT's client name does not match the principal
 * name, Java will use a secret key to obtain the TGT using the authentication
 * exchange and added to the Subject's private credentials.
 * This secret key will be first retrieved from the keytab. If the key
 * is not available, the user will be prompted for the password. In either
 * case, the key derived from the password will be added to the
 * Subject's private credentials set.
 *
 * <pre>{@code
 * isInitiator = false}</pre>
 * Configured to act as acceptor only, credentials are not acquired
 * via AS exchange. For acceptors only, set this value to false.
 * For initiators, do not set this value to false.
 *
 * <pre>{@code
 * isInitiator = true}</pre>
 * Configured to act as initiator, credentials are acquired
 * via AS exchange. For initiators, set this value to true, or leave this
 * option unset, in which case default value (true) will be used.
 *
 * </blockquote>
 *
 * @author Ram Marti
 */

public class Krb5LoginModule implements LoginModule {

    // initial state
    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, Object> sharedState;
    private Map<String, ?> options;

    // configurable option
    private boolean debug = false;
    private boolean storeKey = false;
    private boolean doNotPrompt = false;
    private boolean useTicketCache = false;
    private boolean useKeyTab = false;
    private String ticketCacheName = null;
    private String keyTabName = null;
    private String princName = null;

    private boolean useFirstPass = false;
    private boolean tryFirstPass = false;
    private boolean storePass = false;
    private boolean clearPass = false;
    private boolean refreshKrb5Config = false;
    private boolean renewTGT = false;

    // specify if initiator.
    // perform authentication exchange if initiator
    private boolean isInitiator = true;

    // the authentication status
    private boolean succeeded = false;
    private boolean commitSucceeded = false;
    private String username;

    // Encryption keys calculated from password. Assigned when storekey == true
    // and useKeyTab == false (or true but not found)
    private EncryptionKey[] encKeys = null;

    KeyTab ktab = null;

    private Credentials cred = null;

    private PrincipalName principal = null;
    private KerberosKey[] kerbKeys = null;
    private StringBuffer krb5PrincName = null;
    private boolean unboundServer = false;
    private char[] password = null;

    private static final String NAME = "javax.security.auth.login.name";
    private static final String PWD = "javax.security.auth.login.password";

    /**
     * Creates a {@code Krb5LoginModule}.
     */
    public Krb5LoginModule() {}

    /**
     * Initialize this {@code LoginModule}.
     *
     * @param subject the {@code Subject} to be authenticated.
     *
     * @param callbackHandler a {@code CallbackHandler} for
     *                  communication with the end user (prompting for
     *                  usernames and passwords, for example).
     *
     * @param sharedState shared {@code LoginModule} state.
     *
     * @param options options specified in the login
     *                  {@code Configuration} for this particular
     *                  {@code LoginModule}.
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

        // initialize any configured options

        debug = "true".equalsIgnoreCase((String)options.get("debug"));
        storeKey = "true".equalsIgnoreCase((String)options.get("storeKey"));
        doNotPrompt = "true".equalsIgnoreCase((String)options.get
                                              ("doNotPrompt"));
        useTicketCache = "true".equalsIgnoreCase((String)options.get
                                                 ("useTicketCache"));
        useKeyTab = "true".equalsIgnoreCase((String)options.get("useKeyTab"));
        ticketCacheName = (String)options.get("ticketCache");
        keyTabName = (String)options.get("keyTab");
        if (keyTabName != null) {
            keyTabName = sun.security.krb5.internal.ktab.KeyTab.normalize(
                         keyTabName);
        }
        princName = (String)options.get("principal");
        refreshKrb5Config =
            "true".equalsIgnoreCase((String)options.get("refreshKrb5Config"));
        renewTGT =
            "true".equalsIgnoreCase((String)options.get("renewTGT"));

        // check isInitiator value
        String isInitiatorValue = ((String)options.get("isInitiator"));
        if (isInitiatorValue == null) {
            // use default, if value not set
        } else {
            isInitiator = "true".equalsIgnoreCase(isInitiatorValue);
        }

        tryFirstPass =
            "true".equalsIgnoreCase
            ((String)options.get("tryFirstPass"));
        useFirstPass =
            "true".equalsIgnoreCase
            ((String)options.get("useFirstPass"));
        storePass =
            "true".equalsIgnoreCase((String)options.get("storePass"));
        clearPass =
            "true".equalsIgnoreCase((String)options.get("clearPass"));
        if (debug) {
            System.out.print("Debug is  " + debug
                             + " storeKey " + storeKey
                             + " useTicketCache " + useTicketCache
                             + " useKeyTab " + useKeyTab
                             + " doNotPrompt " + doNotPrompt
                             + " ticketCache is " + ticketCacheName
                             + " isInitiator " + isInitiator
                             + " KeyTab is " + keyTabName
                             + " refreshKrb5Config is " + refreshKrb5Config
                             + " principal is " + princName
                             + " tryFirstPass is " + tryFirstPass
                             + " useFirstPass is " + useFirstPass
                             + " storePass is " + storePass
                             + " clearPass is " + clearPass + "\n");
        }
    }


    /**
     * Authenticate the user
     *
     * @return true in all cases since this {@code LoginModule}
     *          should not be ignored.
     *
     * @exception FailedLoginException if the authentication fails.
     *
     * @exception LoginException if this {@code LoginModule}
     *          is unable to perform the authentication.
     */
    public boolean login() throws LoginException {

        /*
         * Perhaps we should wrap this in a method that returns false if this
         * throws and sun.security.jgss.native=true.  Or perhaps the wrapper
         * could see if it can acquire comparable GSS credentials and then
         * store those in the subject in commit() in that case (and then
         * GSSUtil/Krb5Util code could be changed to look for those).
         *
         * See related commentary in GssLoginModule.
         */

        if (refreshKrb5Config) {
            try {
                if (debug) {
                    System.out.println("Refreshing Kerberos configuration");
                }
                sun.security.krb5.Config.refresh();
            } catch (KrbException ke) {
                LoginException le = new LoginException(ke.getMessage());
                le.initCause(ke);
                throw le;
            }
        }

        // -Dsun.security.krb5.principal takes precedence over login module
        // "principal" option
        //
        // XXX This seems misplaced.  This is configuration reading, and that
        // clearly belongs in initialize().  It's not like it's very likely
        // that this sequence of events takes place anywhere, much less that we
        // should cater to it:
        //
        //  lc.initialize();
        //  System.setProperty("sun.security.krb5.principal", ...);
        //  lc.login();
        String principalProperty = System.getProperty
            ("sun.security.krb5.principal");
        if (principalProperty != null) {
            krb5PrincName = new StringBuffer(principalProperty);
        } else if (princName != null) {
            krb5PrincName = new StringBuffer(princName);
        }

        // XXX This really belongs in initialize()
        validateConfiguration();

        // XXX This really belongs in validateConfiguration()
        if (krb5PrincName != null && krb5PrincName.toString().equals("*")) {
            unboundServer = true;
        }

        if (tryFirstPass) {
            try {
                attemptAuthentication(true);
                if (debug)
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "authentication succeeded");
                succeeded = true;
                cleanState();
                return true;
            } catch (LoginException le) {
                // authentication failed -- try again below by prompting
                cleanState();
                if (debug) {
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "tryFirstPass failed with:" +
                                       le.getMessage());
                }
            }
        } else if (useFirstPass) {
            try {
                attemptAuthentication(true);
                succeeded = true;
                cleanState();
                return true;
            } catch (LoginException e) {
                // authentication failed -- clean out state
                if (debug) {
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "authentication failed \n" +
                                       e.getMessage());
                }
                succeeded = false;
                cleanState();
                throw e;
            }
        }

        // attempt the authentication by getting the username and pwd
        // by prompting or configuration i.e. not from shared state

        try {
            attemptAuthentication(false);
            succeeded = true;
            cleanState();
            return true;
        } catch (LoginException e) {
            // authentication failed -- clean out state
            if (debug) {
                System.out.println("\t\t[Krb5LoginModule] " +
                                   "authentication failed \n" +
                                   e.getMessage());
            }
            succeeded = false;
            cleanState();
            throw e;
        }
    }
    /**
     * process the configuration options
     * Get the TGT either out of
     * cache or from the KDC using the password entered
     * Check the  permission before getting the TGT
     */

    private void attemptAuthentication(boolean getPasswdFromSharedState)
        throws LoginException {

        /*
         * Check the creds cache to see whether
         * we have TGT for this client principal
         */
        if (krb5PrincName != null) {
            try {
                principal = new PrincipalName
                    (krb5PrincName.toString(),
                     PrincipalName.KRB_NT_PRINCIPAL);
            } catch (KrbException e) {
                LoginException le = new LoginException(e.getMessage());
                le.initCause(e);
                throw le;
            }
        }

        try {
            // This means "from the traditional FILE ccache"
            if (useTicketCache) {
                if (debug)
                    System.out.println("Trying to acquire TGT from Cache");
                cred = getCredsFromCCache(principal, renewTGT, ticketCacheName);
                if (cred != null) {
                    if (principal == null)
                        principal = cred.getClient();
                    if (!isCurrent(cred)) {
                        cred = null;
                        if (debug)
                            System.out.println("Credentials are" +
                                    " no longer valid");
                    }
                }

                if (cred != null) {
                    // get the principal name from the ticket cache
                    if (principal == null) {
                        principal = cred.getProxy() != null
                                ? cred.getProxy().getClient()
                                : cred.getClient();
                   }
                }
                if (debug) {
                    System.out.println("Principal is " + principal);
                    if (cred == null) {
                        System.out.println
                            ("null credentials from Ticket Cache");
                    }
                } else if (debug) {
                    System.out.println("Could not find cached credentials");
                }
            }

            if (cred == null) {
                // !useTicketCache || credentials not found || expired

                if (principal == null) {
                    promptForName(getPasswdFromSharedState);
                    principal = new PrincipalName
                        (krb5PrincName.toString(),
                         PrincipalName.KRB_NT_PRINCIPAL);
                }

                if (useKeyTab) {
                    ktab = getKtab(keyTabName, principal, unboundServer);
                    if (isInitiator &&
                            Krb5Util.keysFromJavaxKeyTab(ktab, principal).length
                                == 0) {
                        ktab = null;
                        if (debug) {
                            System.out.println
                                ("Key for the principal " +
                                 principal  +
                                 " not available in " +
                                 ((keyTabName == null) ?
                                  "default key tab" : keyTabName));
                        }
                    }
                }

                KrbAsReqBuilder builder;

                if (ktab == null) {
                    promptForPass(getPasswdFromSharedState);
                    builder = new KrbAsReqBuilder(principal, password);
                    if (isInitiator || storeKey) {
                        // Even if isInitiator=false, if we want to accept with
                        // long-term key derived from the password, then in
                        // principle (and decidedly for new enctypes) we need
                        // to do an AS exchange to get the PA etype info for
                        // the derivation.  (For older enctypes this is bad, as
                        // we will attempt to talk the a KDC we might not be
                        // able to reach, then timeout...  If this is not
                        // desired, the user can reconfigure the module.)
                        cred = builder.action().getCreds();
                        if (storeKey) {
                            encKeys = builder.getKeys(isInitiator);
                            // When encKeys is empty, the login actually fails.
                            // For compatibility, exception is thrown in commit().
                        }
                    }
                } else {
                    builder = new KrbAsReqBuilder(principal, ktab);
                    if (isInitiator) {
                        cred = builder.action().getCreds();
                    }
                }
                builder.destroy();

                if (debug) {
                    System.out.println("principal is " + principal);
                    HexDumpEncoder hd = new HexDumpEncoder();
                    if (ktab != null) {
                        System.out.println("Will use keytab");
                    } else if (storeKey) {
                        for (int i = 0; i < encKeys.length; i++) {
                            // Printing keys here just because debug is a bad
                            // idea: stdout might be a file that gets sent to
                            // loggers, and...  yeah, no.
                            System.out.println("EncryptionKey: keyType=" +
                                encKeys[i].getEType());
                        }
                    }
                }

                if (isInitiator && (cred == null)) {
                    throw new LoginException
                        ("TGT Can not be obtained from the KDC ");
                }

            }
        } catch (KrbException e) {
            LoginException le = new LoginException(e.getMessage());
            le.initCause(e);
            throw le;
        } catch (IOException ioe) {
            LoginException ie = new LoginException(ioe.getMessage());
            ie.initCause(ioe);
            throw ie;
        }
    }

    private void promptForName(boolean getPasswdFromSharedState)
        throws LoginException {
        krb5PrincName = new StringBuffer("");
        if (getPasswdFromSharedState) {
            // use the name saved by the first module in the stack
            username = (String)sharedState.get(NAME);
            if (debug) {
                System.out.println
                    ("username from shared state is " + username + "\n");
            }
            if (username == null) {
                System.out.println
                    ("username from shared state is null\n");
                throw new LoginException
                    ("Username can not be obtained from sharedstate ");
            }
            if (debug) {
                System.out.println
                    ("username from shared state is " + username + "\n");
            }
            if (username != null && username.length() > 0) {
                krb5PrincName.insert(0, username);
                return;
            }
        }

        if (doNotPrompt) {
            throw new LoginException
                ("Unable to obtain Principal Name for authentication ");
        } else {
            if (callbackHandler == null)
                throw new LoginException("No CallbackHandler "
                                         + "available "
                                         + "to garner authentication "
                                         + "information from the user");
            try {
                String defUsername = System.getProperty("user.name");

                Callback[] callbacks = new Callback[1];
                MessageFormat form = new MessageFormat(
                                       getAuthResourceString(
                                       "Kerberos.username.defUsername."));
                Object[] source =  {defUsername};
                callbacks[0] = new NameCallback(form.format(source));
                callbackHandler.handle(callbacks);
                username = ((NameCallback)callbacks[0]).getName();
                if (username == null || username.length() == 0)
                    username = defUsername;
                krb5PrincName.insert(0, username);

            } catch (java.io.IOException ioe) {
                throw new LoginException(ioe.getMessage());
            } catch (UnsupportedCallbackException uce) {
                throw new LoginException
                    (uce.getMessage()
                     +" not available to garner "
                     +" authentication information "
                     +" from the user");
            }
        }
    }

    private void promptForPass(boolean getPasswdFromSharedState)
        throws LoginException {

        if (getPasswdFromSharedState) {
            // use the password saved by the first module in the stack
            password = (char[])sharedState.get(PWD);
            if (password == null) {
                if (debug) {
                    System.out.println
                        ("Password from shared state is null");
                }
                throw new LoginException
                    ("Password can not be obtained from sharedstate ");
            }
            if (debug) {
                System.out.println
                    ("password is " + new String(password));
            }
            return;
        }
        if (doNotPrompt) {
            throw new LoginException
                ("Unable to obtain password from user\n");
        } else {
            if (callbackHandler == null)
                throw new LoginException("No CallbackHandler "
                                         + "available "
                                         + "to garner authentication "
                                         + "information from the user");
            try {
                Callback[] callbacks = new Callback[1];
                String userName = krb5PrincName.toString();
                MessageFormat form = new MessageFormat(
                                         getAuthResourceString(
                                         "Kerberos.password.for.username."));
                Object[] source = {userName};
                callbacks[0] = new PasswordCallback(
                                                    form.format(source),
                                                    false);
                callbackHandler.handle(callbacks);
                char[] tmpPassword = ((PasswordCallback)
                                      callbacks[0]).getPassword();
                if (tmpPassword == null) {
                    throw new LoginException("No password provided");
                }
                password = new char[tmpPassword.length];
                System.arraycopy(tmpPassword, 0,
                                 password, 0, tmpPassword.length);
                ((PasswordCallback)callbacks[0]).clearPassword();


                // clear tmpPassword
                for (int i = 0; i < tmpPassword.length; i++)
                    tmpPassword[i] = ' ';
                tmpPassword = null;
                if (debug) {
                    System.out.println("\t\t[Krb5LoginModule] " +
                                       "user entered username: " +
                                       krb5PrincName);
                    System.out.println();
                }
            } catch (java.io.IOException ioe) {
                throw new LoginException(ioe.getMessage());
            } catch (UnsupportedCallbackException uce) {
                throw new LoginException(uce.getMessage()
                                         +" not available to garner "
                                         +" authentication information "
                                         + "from the user");
            }
        }
    }

    private void validateConfiguration() throws LoginException {
        if (doNotPrompt && !useTicketCache && !useKeyTab
                && !tryFirstPass && !useFirstPass)
            throw new LoginException
                ("Configuration Error"
                 + " - either doNotPrompt should be "
                 + " false or at least one of useTicketCache, "
                 + " useKeyTab, tryFirstPass and useFirstPass"
                 + " should be true");
        if (ticketCacheName != null && !useTicketCache)
            throw new LoginException
                ("Configuration Error "
                 + " - useTicketCache should be set "
                 + "to true to use the ticket cache"
                 + ticketCacheName);
        if (keyTabName != null & !useKeyTab)
            throw new LoginException
                ("Configuration Error - useKeyTab should be set to true "
                 + "to use the keytab" + keyTabName);
        if (storeKey && doNotPrompt && !useKeyTab
                && !tryFirstPass && !useFirstPass)
            throw new LoginException
                ("Configuration Error - either doNotPrompt should be set to "
                 + " false or at least one of tryFirstPass, useFirstPass "
                 + "or useKeyTab must be set to true for storeKey option");
        if (renewTGT && !useTicketCache)
            throw new LoginException
                ("Configuration Error"
                 + " - either useTicketCache should be "
                 + " true or renewTGT should be false");
        if (krb5PrincName != null && krb5PrincName.toString().equals("*")) {
            if (isInitiator) {
                throw new LoginException
                    ("Configuration Error"
                    + " - principal cannot be * when isInitiator is true");
            }
        }
    }

    private Credentials getCredsFromCCache(PrincipalName princ, boolean renewTGT, String ccacheName)
        throws KrbException, IOException {
        // ticketCacheName == null implies the default cache
        // princ == null implies the cache's default princ(XXX?)
        Credentials creds = Credentials.acquireTGTFromCache(princ, ccacheName);
        if (creds == null)
            return null;
        if (renewTGT && timeToRenew(creds))
            creds = possiblyRenewCreds(creds);
        // It's the caller's job to deal with expired creds
        return creds;
    }

    private KeyTab getKtab(String keyTabName, PrincipalName principal,
            boolean unboundServer)
    {
        KerberosPrincipal kp = unboundServer ? null :
            new KerberosPrincipal(principal.getName());;
        return (keyTabName == null)
            ? KeyTab.getInstance(kp) // default keytab
            : KeyTab.getInstance(kp, new File(keyTabName));
    }

    private static boolean isCurrent(Credentials creds)
    {
        Date endTime = creds.getEndTime();
        if (endTime != null) {
            return (System.currentTimeMillis() <= endTime.getTime());
        }
        return true;
    }

    private static boolean timeToRenew(Credentials creds)
    {
        if (!creds.isRenewable())
            return false;

        Date endTime = creds.getEndTime();

        // endtime is required, so it can't be null.  We only have to check
        // because it's Java and we could express that this can't be null.
        // Strictly speaking we can leave out this test.
        if (endTime == null)
            return false;

        // There's no point trying to renew a TGT we will be able to renew but
        // with no additional lifetime.  And there's no point trying to renew
        // non-renewable tickets.
        Date renewTill = creds.getRenewTill();
        if (renewTill == null || renewTill.getTime() <= endTime.getTime())
            return false;

        // NOTE WELL: We must use the *start* time, not the auth time, because
        //            the auth time refers to when the AS exchange was done,
        //            not to when the TGS exchange was done.  For very
        //            long-lived TGTs using authTime here means renewing all
        //            the time!
        Date startTime = creds.getStartTime();
        long now = System.currentTimeMillis();
        // Start time can be null
        if (startTime != null)
            // past the mid between start and end
            return now - startTime.getTime() > endTime.getTime() - now;
        // will it expire in less than 2 hours?
        return now <= endTime.getTime() - 1000*3600*2L;
    }

    private Credentials possiblyRenewCreds(Credentials creds)
        throws KrbException, IOException
    {
        if (!creds.isRenewable())
            return creds;

        if (System.currentTimeMillis() > cred.getRenewTill().getTime())
            return creds;

        try {
            creds = creds.renew().setProxy(creds.getProxy());
            if (debug)
                System.out.println("Renewed Kerberos Ticket");
        } catch (Exception e) {
            if (debug)
                System.out.println("Ticket could not be renewed : "
                                + e.getMessage());
        }
        return creds;
    }

    /**
     * This method is called if the LoginContext's
     * overall authentication succeeded
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
     * LoginModules succeeded).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * {@code login} method), then this method associates a
     * {@code Krb5Principal}
     * with the {@code Subject} located in the
     * {@code LoginModule}. It adds Kerberos Credentials to the
     *  the Subject's private credentials set. If this LoginModule's own
     * authentication attempted failed, then this method removes
     * any state that was originally saved.
     *
     * @exception LoginException if the commit fails.
     *
     * @return true if this LoginModule's own login and commit
     *          attempts succeeded, or false otherwise.
     */

    public boolean commit() throws LoginException {
        /*
         * Let us add the Krb5 Creds to the Subject's
         * private credentials. The credentials are of type
         * KerberosKey or KerberosTicket
         */
        if (succeeded == false) {
            cleanKerberosCred();
            return false;
        }

        if (isInitiator && (cred == null)) {
            cleanKerberosCred();
            succeeded = false;
            throw new LoginException("Null Client Credential");
        }

        if (subject.isReadOnly()) {
            cleanKerberosCred();
            succeeded = false;
            throw new LoginException("Subject is Readonly");
        }

        try {
            setupSubject(subject, unboundServer ? null : principal, ktab,
                    storeKey && encKeys != null ? encKeys : null);
            if (debug)
                System.out.println("Added Kerberos credentials to subject");
            return true;
        } catch (Exception e) {
            cleanKerberosCred();
            succeeded = false;
            throw new LoginException(e.getMessage());
        }
    }

    /**
     * Store the given Kerberos crendentials in the given subject.
     *
     * @param subject the {@code Subject} to store the credentials into
     *
     * @param principal the {@code PrincipalName} for the credentials; use null to refer to all principals in the keytab
     *
     * @param ktab a {@code KeyTab} keytab to use for acting as a service (may be null)
     *
     * @param encKeys long-term secret keys for the principal (if acting as a server with the keys derived from a password)
     *
     */
    private void setupSubject(Subject subject, PrincipalName principal,
            KeyTab ktab, EncryptionKey[] encKeys)
        throws LoginException {

        KerberosTicket kerbTicket = null;

        // create Kerberos Ticket
        if (isInitiator) {
          kerbTicket = Krb5Util.credsToTicket(cred);
          if (cred.getProxy() != null) {
            KerberosSecrets.getJavaxSecurityAuthKerberosAccess()
              .kerberosTicketSetProxy(kerbTicket,Krb5Util.credsToTicket(cred.getProxy()));
          }
        }
        /*
         * Add the Principal (authenticated identity)
         * to the Subject's principal set and
         * add the credentials (TGT or Service key) to the
         * Subject's private credentials
         */

        if (kerbTicket == null && encKeys == null && ktab == null)
            throw new LoginException("No Kerberos credentials provided to " +
                    "store in subject");

        Set<Object> privCredSet = subject.getPrivateCredentials();
        Set<Principal> princSet = subject.getPrincipals();

        KerberosPrincipal princ = null;
        if (principal != null) {
            princ = new KerberosPrincipal(principal.getName());
            if (!princSet.contains(princ))
                princSet.add(princ);
        }

        if (kerbTicket != null && !privCredSet.contains(kerbTicket))
            privCredSet.add(kerbTicket);

        if (ktab != null && !privCredSet.contains(ktab))
            privCredSet.add(ktab);

        if (encKeys == null)
            return;

        if (encKeys.length == 0)
            throw new LoginException("Cannot store empty long-term " +
                    "keyset in Subject");

        if (princ == null)
            throw new LoginException("Cannot store Kerberos long-term keys " +
                    "for wild-card principal in Subject");

        for (int i = 0; i < encKeys.length; i ++) {
            Integer temp = encKeys[i].getKeyVersionNumber();
            KerberosKey kerbKey = new KerberosKey(princ,
                    encKeys[i].getBytes(),
                    encKeys[i].getEType(),
                    (temp == null?
                     0: temp.intValue()));
            if (!privCredSet.contains(kerbKey))
                privCredSet.add(kerbKey);
        }
    }

    /**
     * This method is called if the LoginContext's
     * overall authentication failed.
     * (the relevant REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL
     * LoginModules did not succeed).
     *
     * <p> If this LoginModule's own authentication attempt
     * succeeded (checked by retrieving the private state saved by the
     * {@code login} and {@code commit} methods),
     * then this method cleans up any state that was originally saved.
     *
     * @exception LoginException if the abort fails.
     *
     * @return false if this LoginModule's own login and/or commit attempts
     *          failed, and true otherwise.
     */

    public boolean abort() throws LoginException {
        if (succeeded == false) {
            return false;
        } else if (succeeded == true && commitSucceeded == false) {
            // login succeeded but overall authentication failed
            succeeded = false;
            cleanKerberosCred();
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    /**
     * Logout the user.
     *
     * <p> This method removes the {@code Krb5Principal}
     * that was added by the {@code commit} method.
     *
     * @exception LoginException if the logout fails.
     *
     * @return true in all cases since this {@code LoginModule}
     *          should not be ignored.
     */
    public boolean logout() throws LoginException {

        if (debug) {
            System.out.println("\t\t[Krb5LoginModule]: " +
                "Entering logout");
        }

        if (subject.isReadOnly()) {
            cleanKerberosCred();
            throw new LoginException("Subject is Readonly");
        }

        Iterator<Principal> itp = subject.getPrincipals().iterator();
        while (itp.hasNext()) {
            Object o = itp.next();
            if (o instanceof KerberosPrincipal)
                itp.remove();
        }

        Iterator<Object> it = subject.getPrivateCredentials().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof KerberosTicket ||
                    o instanceof KerberosKey ||
                    o instanceof KeyTab) {
                it.remove();
            }
        }
        // clean the kerberos ticket and keys
        cleanKerberosCred();

        succeeded = false;
        commitSucceeded = false;
        if (debug) {
            System.out.println("\t\t[Krb5LoginModule]: " +
                               "logged out Subject");
        }
        return true;
    }

    /**
     * Clean Kerberos credentials
     */
    private void cleanKerberosCred() throws LoginException {
        // Clean the ticket and server key
        try {
            if (kerbKeys != null) {
                for (int i = 0; i < kerbKeys.length; i++) {
                    kerbKeys[i].destroy();
                }
            }
        } catch (DestroyFailedException e) {
            throw new LoginException
                ("Destroy Failed on Kerberos Private Credentials");
        }
        for (int i = 0; i < kerbKeys.length; i++) {
            encKeys[i].destroy();
            encKeys[i] = null;
        }
        kerbKeys = null;
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
                sharedState.put(NAME, username);
                sharedState.put(PWD, password);
            }
        } else {
            // remove temp results for the next try
            encKeys = null;
            ktab = null;
            principal = null;
        }
        username = null;
        password = null;
        if (krb5PrincName != null && krb5PrincName.length() != 0)
            krb5PrincName.delete(0, krb5PrincName.length());
        krb5PrincName = null;
        if (clearPass) {
            sharedState.remove(NAME);
            sharedState.remove(PWD);
        }
    }
}
