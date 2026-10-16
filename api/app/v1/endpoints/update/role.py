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

"""PATCH /Users/{id}/networks — administrator-only access change endpoint.

Authorization
-------------
Only users with ``role == 'administrator'`` may call this endpoint.
Any other caller receives HTTP 403 before any database interaction occurs.

The endpoint replaces an active user's complete list of grants (which
Networks, with which role, and which custom policy); a user who wants more
or less access asks an administrator, who is the sole gatekeeper. All DB
logic + edge-case guards live in ``role_crud.update_user_networks``.
"""

import logging

from app.db.role_crud import update_user_networks
from app.models.error import DetailError
from app.models.networks import NetworksUpdateRequest
from app.oauth import get_current_user
from app.v1.endpoints.openapi_responses import (
    ADMIN_ERRORS,
    BAD_REQUEST_PENDING_ROLE,
    CONFLICT_LAST_ADMIN,
    NOT_FOUND_USER,
    merge,
    response,
)
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response

v1 = APIRouter()
logger = logging.getLogger(__name__)


@v1.api_route(
    "/Users/{user_id}/networks",
    methods=["PATCH"],
    tags=["Users"],
    summary="Replace a user's Networks, roles and policies (admin only)",
    description=(
        "Replace the **complete** list of grants of an existing, active "
        "user. Each grant is `{network_name: [...], role, policy}`; "
        "`network_name: []` grants all Networks, `policy` is only for the "
        "`custom` role. Where several grants cover a Network the user holds "
        "the union. Restricted to administrators. Pending users must be "
        "approved first. Saving grants on an administrator account demotes "
        "it to a regular member (the last administrator cannot be demoted). "
        "Roles: viewer, editor, obs_manager, sensor, qc, custom."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses=merge(
        {
            204: {
                "description": (
                    "Access replaced. No response body. Also returned "
                    "(with no database mutation) if the list is identical "
                    "to the current one -- a deliberate no-op guard."
                )
            },
            400: {
                "description": (
                    "A grant is invalid: unknown or ambiguous Network name, "
                    "unknown policy, overlapping grants of the same role, "
                    "or the user is still pending."
                ),
                "content": {
                    "application/json": {
                        "example": {"detail": "No Network named: 'nowhere'."}
                    }
                },
            },
            500: response(
                DetailError,
                "Unexpected database error during the update.",
                {"detail": "Internal server error."},
            ),
        },
        ADMIN_ERRORS,
        NOT_FOUND_USER,
        BAD_REQUEST_PENDING_ROLE,
        CONFLICT_LAST_ADMIN,
    ),
)
async def patch_user_networks(
    user_id: int,
    payload: NetworksUpdateRequest,
    current_user=Depends(get_current_user),
):
    # ------------------------------------------------------------------
    # Authorization: administrators only.
    # ------------------------------------------------------------------
    if current_user.get("role") != "administrator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can change a user's access.",
        )

    # Delegate all business logic and guards to the CRUD layer.
    await update_user_networks(
        user_id=user_id,
        grants=payload.networks,
        actor_id=current_user.get("id"),
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
