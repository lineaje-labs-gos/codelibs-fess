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
package org.codelibs.fess.app.web.base.login;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.codelibs.fess.app.web.base.login.EntraIdCredential.EntraIdUser;
import org.codelibs.fess.helper.SystemHelper;
import org.codelibs.fess.sso.entraid.EntraIdAuthenticator;
import org.codelibs.fess.unit.UnitFessTestCase;
import org.codelibs.fess.util.ComponentUtil;
import org.junit.jupiter.api.Test;

import com.microsoft.aad.msal4j.IAccount;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.ITenantProfile;

public class EntraIdUserPermissionTest extends UnitFessTestCase {

    private static IAuthenticationResult authResult() {
        return authResult(new Date(Long.MAX_VALUE), "access-token");
    }

    private static IAuthenticationResult authResult(final Date expiresOn, final String accessToken) {
        final IAccount account = new IAccount() {
            private static final long serialVersionUID = 1L;

            @Override
            public String homeAccountId() {
                return "home-account-id";
            }

            @Override
            public String environment() {
                return "login.microsoftonline.com";
            }

            @Override
            public String username() {
                return "taro@contoso.onmicrosoft.com";
            }

            @Override
            public Map<String, ITenantProfile> getTenantProfiles() {
                return Collections.emptyMap();
            }
        };
        return new IAuthenticationResult() {
            private static final long serialVersionUID = 1L;

            @Override
            public String accessToken() {
                return accessToken;
            }

            @Override
            public String idToken() {
                return "id-token";
            }

            @Override
            public IAccount account() {
                return account;
            }

            @Override
            public ITenantProfile tenantProfile() {
                return null;
            }

            @Override
            public String environment() {
                return "login.microsoftonline.com";
            }

            @Override
            public String scopes() {
                return "https://graph.microsoft.com/.default";
            }

            @Override
            public Date expiresOnDate() {
                return expiresOn;
            }
        };
    }

    /**
     * Builds an EntraIdUser without letting its constructor talk to Microsoft Graph.
     */
    private EntraIdUser newUser() {
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                // the test drives setGroups/setRoles itself
            }
        }, EntraIdAuthenticator.class.getCanonicalName());
        return new EntraIdUser(authResult());
    }

    @Test
    public void test_getPermissions_doesNotPinAStaleValueWhenTheAsyncLookupLands() throws Exception {
        // scheduleParentGroupLookup runs on a TimeoutManager thread while the user is already
        // logged in and searching. getPermissions() is a check-then-act -- read `permissions ==
        // null`, read `groups`, write `permissions` -- so a reader that started before the async
        // task can finish after it and overwrite the fresh value with one computed from the
        // direct groups alone. Nothing sets `permissions` back to null after that, so the parent
        // group permissions stay missing for the rest of the session.
        final CountDownLatch readerIsInside = new CountDownLatch(1);
        final CountDownLatch asyncTaskIsDone = new CountDownLatch(1);
        ComponentUtil.register(new SystemHelper() {
            @Override
            public String getSearchRoleByGroup(final String name) {
                if ("direct-group".equals(name)) {
                    // The reader has read `groups` and is now mid-computation.
                    readerIsInside.countDown();
                    try {
                        asyncTaskIsDone.await(10L, TimeUnit.SECONDS);
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                return super.getSearchRoleByGroup(name);
            }
        }, "systemHelper");

        final EntraIdUser user = newUser();
        user.setGroups(new String[] { "direct-group" });
        user.setRoles(new String[0]);

        final Thread reader = new Thread(() -> user.getPermissions());
        reader.start();
        assertTrue(readerIsInside.await(10L, TimeUnit.SECONDS));

        // What scheduleParentGroupLookup does once the parent groups arrive, on its own thread so
        // that it can be made to wait for the reader rather than deadlocking with it.
        final Thread asyncLookup = new Thread(() -> {
            user.setGroups(new String[] { "direct-group", "parent-group" });
            user.setRoles(new String[0]);
            user.resetPermissions();
        });
        asyncLookup.start();
        // Give the async task time to get as far as it is able to before the reader finishes.
        Thread.sleep(200L);

        asyncTaskIsDone.countDown();
        reader.join(10000L);
        asyncLookup.join(10000L);

        final String[] permissions = user.getPermissions();
        assertTrue("parent-group missing from " + Arrays.toString(permissions),
                Arrays.stream(permissions).anyMatch(p -> p.contains("parent-group")));
    }

    @Test
    public void test_refresh_renewsOnceWhenConcurrentRequestsShareTheUser() throws Exception {
        // Lastaflute keeps the FessUserBean -- and therefore one EntraIdUser -- as a session
        // attribute, and FessBaseAction.godHandPrologue calls refresh() on every action request,
        // so all the requests a session has in flight arrive in the REFRESH_MARGIN window
        // together. Each of them used to see a renewed access token and run updateMemberOf, which
        // is a synchronous Microsoft Graph GET /me/memberOf on a request thread plus another
        // scheduled parent group lookup. Doubling the Graph traffic at every token rollover is
        // exactly what the per-request guard was added to remove.
        ComponentUtil.register(new SystemHelper(), "systemHelper");
        final long now = ComponentUtil.getSystemHelper().getCurrentTimeAsLong();
        // Inside REFRESH_MARGIN, so refresh() really attempts the silent acquisition.
        final IAuthenticationResult initial = authResult(new Date(now + 30 * 1000L), "access-token");

        final AtomicInteger memberOfCalls = new AtomicInteger();
        final CountDownLatch winnerIsAcquiring = new CountDownLatch(1);
        final CountDownLatch loserIsDone = new CountDownLatch(1);
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                memberOfCalls.incrementAndGet();
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                // Hold the acquisition open the way a real MSAL4J round trip does, so the second
                // request reaches refresh() while this one is still inside it.
                winnerIsAcquiring.countDown();
                try {
                    loserIsDone.await(10L, TimeUnit.SECONDS);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return authResult(new Date(now + 30 * 1000L), "renewed-access-token");
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(initial);
        // The constructor resolves the memberships once; only what refresh() adds is under test.
        memberOfCalls.set(0);

        final AtomicBoolean winnerResult = new AtomicBoolean();
        final Thread winner = new Thread(() -> winnerResult.set(user.refresh()));
        winner.start();
        assertTrue(winnerIsAcquiring.await(10L, TimeUnit.SECONDS));

        // The session's second concurrent request. Its token has not expired, so it must be let
        // through rather than blocked behind the acquisition, and it must not renew again.
        assertTrue(user.refresh());
        loserIsDone.countDown();
        winner.join(10000L);

        assertTrue(winnerResult.get());
        assertEquals(1, memberOfCalls.get(), "a concurrent refresh must not make a second Microsoft Graph round trip");
        // Last-writer-wins used to be able to leave the older of the two results in place.
        assertEquals("renewed-access-token", user.getAuthenticationResult().accessToken());
    }

    @Test
    public void test_refresh_stillRenewsOnEveryRollover() throws Exception {
        // The counterpart of the test above: the guard must only suppress a *concurrent* renewal.
        // A sequential refresh has to keep re-reading the directory, otherwise a session would
        // never pick up a group change again, and the flag has to be released on the way out.
        ComponentUtil.register(new SystemHelper(), "systemHelper");
        final long now = ComponentUtil.getSystemHelper().getCurrentTimeAsLong();
        final IAuthenticationResult initial = authResult(new Date(now + 30 * 1000L), "access-token");

        final AtomicInteger memberOfCalls = new AtomicInteger();
        final AtomicReference<IAuthenticationResult> next = new AtomicReference<>();
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                memberOfCalls.incrementAndGet();
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                return next.get();
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(initial);
        memberOfCalls.set(0);

        next.set(authResult(new Date(now + 30 * 1000L), "second-access-token"));
        assertTrue(user.refresh());
        assertEquals(1, memberOfCalls.get(), "the first rollover must re-read the directory");

        next.set(authResult(new Date(now + 30 * 1000L), "third-access-token"));
        assertTrue(user.refresh());
        assertEquals(2, memberOfCalls.get(), "the guard must be released once the acquisition is over");
        assertEquals("third-access-token", user.getAuthenticationResult().accessToken());
    }

    /**
     * Registers a SystemHelper whose clock the test drives, the way EntraIdAuthenticatorTest does.
     */
    private void registerClock(final AtomicLong clock) {
        ComponentUtil.register(new SystemHelper() {
            @Override
            public long getCurrentTimeAsLong() {
                return clock.get();
            }
        }, "systemHelper");
    }

    @Test
    public void test_refresh_attemptsARenewalWhenTheTokenHasExpired() {
        // FessBaseAction.godHandPrologue discards this result, so returning false without asking
        // MSAL4J for anything never ended the session: it left it holding a dead access token and
        // taking the same early exit on every later request, which is what stopped its group
        // memberships from ever being re-read again. MSAL4J's silent flow spends the cached
        // refresh token, which outlives the access token by hours, so an expired access token is
        // precisely the case worth one attempt.
        final AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        registerClock(clock);
        final AtomicInteger acquisitions = new AtomicInteger();
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                // the constructor must not reach Microsoft Graph
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                acquisitions.incrementAndGet();
                return null;
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() - 1L), "expired-access-token"));

        // The acquisition failed, so the token really is dead and refresh() says so.
        assertFalse(user.refresh());
        assertEquals(1, acquisitions.get(), "an expired access token must not be given up on without asking MSAL4J");
    }

    @Test
    public void test_refresh_recoversASessionWhoseTokenExpired() {
        // The user was idle across the expiry -- with REFRESH_MARGIN in place their last request
        // can easily have fallen before the renewal window -- and comes back. The cached refresh
        // token is still good, so the session carries on with a live token and re-read groups.
        final AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        registerClock(clock);
        final AtomicInteger memberOfCalls = new AtomicInteger();
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                memberOfCalls.incrementAndGet();
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                return authResult(new Date(clock.get() + 60 * 60 * 1000L), "renewed-access-token");
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() - 1L), "expired-access-token"));
        // The constructor resolves the memberships once; only what refresh() adds is under test.
        memberOfCalls.set(0);

        assertTrue(user.refresh());
        assertEquals("renewed-access-token", user.getAuthenticationResult().accessToken());
        assertEquals(1, memberOfCalls.get(), "a recovered session must re-read its group memberships");
    }

    @Test
    public void test_refresh_holdsOffAFailingRenewalUntilTheThrottleLapses() {
        // A revoked refresh token, a disabled account, and an account a logout on another session
        // evicted from the shared MSAL4J cache all fail for good, and refresh() runs on every
        // action request. Retrying unconditionally would put back exactly the per-request round
        // trip REFRESH_MARGIN was introduced to remove.
        final AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        registerClock(clock);
        final AtomicInteger acquisitions = new AtomicInteger();
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                // the constructor must not reach Microsoft Graph
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                acquisitions.incrementAndGet();
                return null;
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() - 1L), "expired-access-token"));

        assertFalse(user.refresh());
        assertEquals(1, acquisitions.get(), "the first request after the expiry must attempt a renewal");

        // The rest of the requests this session makes inside the interval.
        assertFalse(user.refresh());
        clock.addAndGet(EntraIdUser.RENEWAL_THROTTLE_INTERVAL - 1L);
        assertFalse(user.refresh());
        assertEquals(1, acquisitions.get(), "a renewal that failed must not be retried on every request");

        // ... and the first one after it.
        clock.addAndGet(1L);
        assertFalse(user.refresh());
        assertEquals(2, acquisitions.get(), "the throttle must lapse rather than give up for good");
    }

    @Test
    public void test_refresh_doesNotStampedeWhenConcurrentRequestsFindAnExpiredToken() throws Exception {
        // The concurrency guard has to cover the expired token as well, not just the renewal
        // window: godHandPrologue calls refresh() on every action request, so the requests a
        // session has in flight when it comes back after the expiry arrive here together, and
        // each of them would otherwise run its own acquisition and its own synchronous Microsoft
        // Graph call behind updateMemberOf.
        final AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        registerClock(clock);
        final AtomicInteger acquisitions = new AtomicInteger();
        final AtomicInteger memberOfCalls = new AtomicInteger();
        final CountDownLatch winnerIsAcquiring = new CountDownLatch(1);
        final CountDownLatch loserIsDone = new CountDownLatch(1);
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                memberOfCalls.incrementAndGet();
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                acquisitions.incrementAndGet();
                // Hold the acquisition open the way a real MSAL4J round trip does, so the second
                // request reaches refresh() while this one is still inside it.
                winnerIsAcquiring.countDown();
                try {
                    loserIsDone.await(10L, TimeUnit.SECONDS);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return authResult(new Date(clock.get() + 60 * 60 * 1000L), "renewed-access-token");
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() - 1L), "expired-access-token"));
        memberOfCalls.set(0);

        final AtomicBoolean winnerResult = new AtomicBoolean();
        final Thread winner = new Thread(() -> winnerResult.set(user.refresh()));
        winner.start();
        assertTrue(winnerIsAcquiring.await(10L, TimeUnit.SECONDS));

        // The session's second concurrent request. It holds nothing valid, so it reports that,
        // but it must not start a second acquisition of its own.
        assertFalse(user.refresh());
        assertEquals(1, acquisitions.get(), "a concurrent refresh must not start a second silent acquisition");
        loserIsDone.countDown();
        winner.join(10000L);

        assertTrue(winnerResult.get());
        assertEquals(1, memberOfCalls.get(), "a concurrent refresh must not make a second Microsoft Graph round trip");
        assertEquals("renewed-access-token", user.getAuthenticationResult().accessToken());
    }

    @Test
    public void test_refresh_holdsOffAfterAnExceptionToo() {
        // The exception path has to back off as well, otherwise the failure it now reports at
        // WARN -- refreshTokenSilently swallows its own, so in production this is updateMemberOf
        // or the component lookup throwing -- is written once per request rather than once per
        // interval, which is exactly the noise the throttle is there to prevent.
        final AtomicLong clock = new AtomicLong(1_700_000_000_000L);
        registerClock(clock);
        final AtomicInteger acquisitions = new AtomicInteger();
        ComponentUtil.register(new EntraIdAuthenticator() {
            @Override
            public void updateMemberOf(final EntraIdUser user) {
                // the constructor must not reach Microsoft Graph
            }

            @Override
            public IAuthenticationResult refreshTokenSilently(final EntraIdUser user) {
                acquisitions.incrementAndGet();
                throw new IllegalStateException("the directory could not be reached");
            }
        }, EntraIdAuthenticator.class.getCanonicalName());

        final EntraIdUser user = new EntraIdUser(authResult(new Date(clock.get() - 1L), "expired-access-token"));

        assertFalse(user.refresh());
        assertFalse(user.refresh());
        assertEquals(1, acquisitions.get(), "a renewal that threw must not be retried on every request");

        clock.addAndGet(EntraIdUser.RENEWAL_THROTTLE_INTERVAL);
        assertFalse(user.refresh());
        assertEquals(2, acquisitions.get(), "the throttle must lapse rather than give up for good");
    }
}
