/*
 * Copyright 2012-2025 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.sso.entraid;

import org.codelibs.fess.exception.FessSystemException;

/**
 * Thrown when the parent groups of one group could not be resolved from Microsoft Graph.
 *
 * <p>This is internal control flow for the asynchronous parent group walk rather than a login
 * outcome: {@link EntraIdAuthenticator#getParentGroup} raises it instead of handing back an empty
 * result, so that "this lookup was not answered" is distinguishable from "this group has no
 * parents", and the walk can stop asking a Microsoft Graph that has stopped answering. It is
 * always caught by {@link EntraIdAuthenticator#processParentGroup} and never reaches the login
 * path.
 *
 * <p>It deliberately lives here rather than in {@code org.codelibs.fess.exception} next to
 * {@code SsoLoginException} and friends: those are failures the user is shown, and several of
 * them are caught by name while a login is being resolved. Keeping this one in the Entra ID
 * package, where its only thrower and its only catcher are, keeps it out of reach of those
 * handlers and states that it is not a login failure. It is unchecked because it has to travel
 * out of a {@code Callable} passed to a Guava cache loader, which converts a checked exception
 * into {@code ExecutionException} and would hide it.
 */
public class ParentGroupLookupException extends FessSystemException {

    /** Serial version UID for serialization compatibility. */
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new ParentGroupLookupException with the specified detail message and cause.
     *
     * @param message The detail message naming the group whose parents could not be resolved.
     * @param cause The failure Microsoft Graph or the transport reported.
     */
    public ParentGroupLookupException(final String message, final Throwable cause) {
        super(message, cause);
    }

}
