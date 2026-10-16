# Copyright 2025 SUPSI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""GET /auth/{provider}/login and GET /auth/{provider}/callback.

This is the handshake oidc_user_crud.py was always missing -- see its own
module docstring. Two generic, provider-parameterized routes handle all
five providers (Google, Microsoft, GitHub, ORCID, SWITCH edu-ID) instead of
five separate implementations, since the OAuth/OIDC redirect-and-callback
shape is identical across providers; only claim extraction differs (see
app.oidc_providers.normalize_claims).

Flow
----
1. GET /auth/{provider}/login?networks=<JSON list of grants>
   The caller (whatever frontend is driving this) may let the user pick the
   Networks and the RBAC role they want -- optional, mirroring the
   ``networks`` field of POST /Register. An OAuth login is a plain browser redirect
   with no request body, so that selection is stashed in the server-side
   session (see the SessionMiddleware registration in app.main) before
   redirecting to the provider, the same place Authlib already stores its
   own state/nonce.
2. Provider redirects back to /auth/{provider}/callback with a code.
3. Exchange the code for a token; extract identity claims.
4. Read the requested networks back out of the session.
5. Look up (auth_provider, external_sub_id):
   - Unknown identity            -> create_pending_oidc_user(), tell the
     caller to wait for admin approval. No token issued here -- OIDC login
     does not bypass the manual-approval-only design any more than
     POST /Register does (see admin_approval.py / admin_rejection.py).
   - Known identity, still pending -> same "wait for approval" response.
   - Known identity, approved      -> issue a normal access token via the
     same create_access_token() path /Login uses.
"""

import json
import logging

from app.db.network_grant_crud import normalise_requested
from app.models.networks import GrantList
from app.db.oidc_user_crud import (
    OidcUsernameCollisionError,
    create_pending_oidc_user,
    get_user_by_provider_sub,
)
from app.oauth import create_access_token
from app.oidc_providers import ENABLED_PROVIDERS, normalize_claims, oauth
from app.utils.utils import sanitize_username
from app.v1.endpoints.openapi_responses import (
    BAD_GATEWAY_PROVIDER_CLAIMS,
    BAD_REQUEST_OIDC_CALLBACK,
    CONFLICT_PROVIDER_USERNAME,
    DB_UNAVAILABLE,
    INTERNAL,
    NOT_FOUND_PROVIDER,
    OIDC_REGISTRATION_PENDING,
    TOKEN_OK,
    merge,
)
from asyncpg.exceptions import (
    PostgresConnectionError,
    TooManyConnectionsError,
    UniqueViolationError,
)
from fastapi import APIRouter, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter, ValidationError

v1 = APIRouter()
logger = logging.getLogger(__name__)

# Session keys used to carry the user's selection across the redirect round
# trip -- namespaced so they can't collide with whatever Authlib itself
# stores in the same session (its state/nonce bookkeeping).
_SESSION_NETWORKS_KEY = "istsos_oidc_requested_networks"

# The session cookie is client-visible and limited to ~4 KB: keep the
# requested list small.
_MAX_NETWORKS_PARAM = 1500
_GRANT_LIST = TypeAdapter(GrantList)


def _claims_options_for(provider: str) -> dict | None:
    """Per-provider overrides for Authlib's ID-token claim validation.

    Authlib's default, if this returns None, is an exact string match
    between the token's `iss` claim and the discovery document's `issuer`
    field. That breaks specifically for multi-tenant Microsoft/Entra
    apps: the discovery document's `issuer` is a literal, unsubstituted
    template -- "https://login.microsoftonline.com/{tenantid}/v2.0" -- but
    a real token's `iss` has an actual tenant GUID in that position, so
    the exact match always fails with InvalidClaimError, on every login,
    regardless of credentials. Confirmed live: a real Microsoft login
    completed the full redirect+consent+code exchange correctly and only
    failed at this one claims-validation step.

    The fix is to validate the *shape* of `iss` instead of an exact
    string, which is what every OIDC library ends up doing for
    multi-tenant Microsoft apps.
    """
    if provider == "microsoft":
        return {
            "iss": {
                "essential": True,
                "validate": lambda claims, value: (
                    isinstance(value, str)
                    and value.startswith("https://login.microsoftonline.com/")
                    and value.endswith("/v2.0")
                ),
            }
        }
    return None


def _client_for(provider: str):
    if provider not in ENABLED_PROVIDERS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Unknown or unconfigured identity provider '{provider}'. "
                f"Enabled providers: {', '.join(ENABLED_PROVIDERS) or 'none'}."
            ),
        )
    return oauth.create_client(provider)


@v1.api_route(
    "/auth/{provider}/login",
    methods=["GET"],
    tags=["External Authentication"],
    status_code=status.HTTP_302_FOUND,
    summary="Start an external-identity login (browser only)",
    description=(
        "Redirects the browser to the identity provider's consent screen.\n\n"
        "**Cannot be completed with Try it out.** Swagger issues an XHR "
        "from this page's own origin, and the provider will reject it with "
        "a CORS error before any redirect happens. Copy the constructed "
        "URL and open it in a browser tab instead.\n\n"
        "`networks` is optional and mirrors the `networks` field of "
        "`POST /Register`: a JSON list of grants, e.g. "
        "`[{\"network_name\": [\"psos\"], \"role\": \"viewer\"}]`. A "
        "redirect has no request body, so the selection is stashed in the "
        "session here and read back by `/callback`. It is only a request; "
        "an administrator decides what is granted."
    ),
    responses=merge(
        {
            302: {
                "description": "Redirect to the provider's consent screen.",
                "headers": {
                    "location": {
                        "schema": {"type": "string"},
                        "description": "The provider's authorization URL.",
                    }
                },
            },
            400: {
                "description": "`networks` is not valid JSON, or not a valid list of grants.",
                "content": {
                    "application/json": {
                        "example": {
                            "detail": "networks must be a JSON list of "
                            "{network_name, role} objects: Invalid role."
                        }
                    }
                },
            },
        },
        NOT_FOUND_PROVIDER,
    ),
)
async def oidc_login(
    request: Request,
    provider: str = Path(
        ...,
        description=(
            "One of: google, microsoft, github, orcid, eduid -- subject "
            "to which providers this deployment has configured. An "
            "unconfigured or unknown name returns 404."
        ),
        examples=["google"],
    ),
    networks: str | None = Query(
        None,
        max_length=_MAX_NETWORKS_PARAM,
        description=(
            "JSON list of requested grants, each `{network_name: [...], "
            "role: ...}` (`network_name: []` asks for all Networks). A "
            "stated preference, not a grant -- the account is created as "
            "'pending' regardless. Optional."
        ),
        examples=['[{"network_name": ["IDROLOGIA"], "role": "viewer"}]'],
    ),
):
    client = _client_for(provider)

    requested: list[dict] | None = None
    if networks is not None:
        try:
            grants = _GRANT_LIST.validate_python(json.loads(networks))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "networks must be a JSON list of {network_name, role} "
                    f"objects: {str(exc).splitlines()[0][:120]}"
                ),
            )
        requested = normalise_requested(grants)

    # Stash the selection in the session now -- it has to survive the
    # round trip to the external provider and back, and a GET redirect has
    # no request body to carry it in directly.
    request.session[_SESSION_NETWORKS_KEY] = requested

    redirect_uri = request.url_for("oidc_callback", provider=provider)
    return await client.authorize_redirect(request, redirect_uri)


@v1.api_route(
    "/auth/{provider}/callback",
    methods=["GET"],
    tags=["External Authentication"],
    name="oidc_callback",
    summary="Identity-provider redirect target (browser only)",
    description=(
        "The identity provider redirects the browser here after consent, "
        "with a `code` and `state` query string this API's OAuth client "
        "consumes automatically.\n\n"
        "**Not callable from Try it out.** It requires a genuine "
        "provider-issued `code` and the session cookie `/auth/{provider}"
        "/login` set moments earlier -- there is no way to fabricate "
        "either from this page.\n\n"
        "On success, either issues a bearer token (account already "
        "approved) or reports that the account is pending -- external "
        "login never bypasses manual admin approval."
    ),
    responses=merge(
        TOKEN_OK,
        OIDC_REGISTRATION_PENDING,
        BAD_REQUEST_OIDC_CALLBACK,
        CONFLICT_PROVIDER_USERNAME,
        BAD_GATEWAY_PROVIDER_CLAIMS,
        DB_UNAVAILABLE,
        INTERNAL,
    ),
)
async def oidc_callback(
    request: Request,
    provider: str = Path(
        ...,
        description="Must match the provider name used at /login.",
        examples=["google"],
    ),
):
    client = _client_for(provider)

    try:
        token = await client.authorize_access_token(
            request, claims_options=_claims_options_for(provider)
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception(
            "OIDC token exchange failed for provider %r", provider
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Identity provider login failed or was cancelled.",
        )

    try:
        claims = await normalize_claims(provider, token, client)
    except (KeyError, TypeError):
        logger.exception(
            "OIDC provider %r returned an unexpected claim shape", provider
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Identity provider returned an unexpected response.",
        )

    # normalize_claims() derives "username" from whatever the provider
    # sent (preferred_username/email/name/sub) with no format guarantee at
    # all -- a Google display name with a space, an ORCID iD full of
    # hyphens, an email address. There is no form step here for a real
    # person to retype something invalid, unlike local registration, so
    # this sanitizes into something validate_username() accepts instead of
    # rejecting a sincere signup over formatting outside the applicant's
    # control. See sanitize_username()'s own docstring for the algorithm.
    claims["username"] = sanitize_username(
        claims["username"], claims["external_sub_id"]
    )

    # Pop rather than get: this session is single-use for this handshake,
    # and popping avoids a stale selection leaking into a second, unrelated
    # login attempt in the same browser session. Both values are optional.
    requested_networks = request.session.pop(_SESSION_NETWORKS_KEY, None)

    try:
        existing = await get_user_by_provider_sub(
            claims["auth_provider"], claims["external_sub_id"]
        )

        if existing is None:
            try:
                await create_pending_oidc_user(
                    username=claims["username"],
                    email=claims["email"],
                    auth_provider=claims["auth_provider"],
                    external_sub_id=claims["external_sub_id"],
                    requested_networks=requested_networks,
                )
            except OidcUsernameCollisionError:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Username '{claims['username']}' is already taken "
                        "by an unrelated account. Account linking is not "
                        "yet supported -- contact an administrator."
                    ),
                )
            except UniqueViolationError:
                # (auth_provider, external_sub_id) already exists -- a
                # concurrent callback beat us to the insert. Re-fetch
                # rather than treat this as a failure.
                existing = await get_user_by_provider_sub(
                    claims["auth_provider"], claims["external_sub_id"]
                )
                if existing is None:
                    raise
            else:
                return JSONResponse(
                    status_code=status.HTTP_202_ACCEPTED,
                    content={
                        "message": (
                            "Registration submitted via "
                            f"{claims['auth_provider']}. An administrator "
                            "must approve this account before you can log "
                            "in."
                        )
                    },
                )

        if existing["role"] == "pending":
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "message": (
                        "Your account is still pending administrator "
                        "approval."
                    )
                },
            )

        access_token, expire = create_access_token(
            data={"sub": existing["username"], "role": existing["role"]}
        )
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": expire,
            },
        )

    except HTTPException:
        raise
    except (PostgresConnectionError, TooManyConnectionsError):
        logger.exception("Database unavailable during OIDC login")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"message": "Database temporarily unavailable."},
        )
    except Exception:
        logger.exception("Unexpected error during OIDC login")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"message": "Internal server error."},
        )
