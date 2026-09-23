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

"""Pydantic schemas for PATCH /Users/{target_user_id}/policy-approval.

Design decisions
----------------
* ``assigned_role`` is validated via ``validate_rbac_role`` at model
  instantiation time (field_validator), so the endpoint handler never
  receives an unknown or internal role (e.g. 'pending', 'administrator').

* ``dataset_id`` is a plain string (a Network name). The model does not
  validate it; the endpoint handler checks it against the Network table
  before writing it to ``User.dataset_id``.

* The model intentionally carries no auth context; the endpoint handler
  enforces the administrator check via Depends(get_current_user).
"""

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.rbac_roles import ASSIGNABLE_ROLES, validate_rbac_role


class AdminApprovalRequest(BaseModel):
    """Request body for PATCH /Users/{target_user_id}/policy-approval.

    Fields
    ------
    assigned_role:   The application-layer RBAC role to grant to the target
                     user.  Optional -- if omitted, the endpoint falls back
                     to the ``requested_role`` the applicant stated at
                     registration (see register_request.py). Supplying a
                     value here always overrides that default; the
                     administrator is the final gatekeeper either way. Must
                     be one of the assignable roles defined in
                     ``VALID_RBAC_ROLES`` (viewer, editor, obs_manager,
                     sensor, qc, custom) if given.  The internal
                     'pending' state and 'administrator' may NOT be set
                     through this endpoint.
    dataset_id:      Name of the Network to scope the user to. Optional --
                     omit for unrestricted access, or to keep whatever the
                     applicant requested. Written to User.dataset_id and
                     forwarded to AuditLog. Must match an existing Network.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "assigned_role": "viewer",
                    "dataset_id": "IDROLOGIA",
                }
            ]
        }
    )

    assigned_role: str | None = Field(
        default=None,
        description=(
            "RBAC role to grant. Omit to approve with the role the "
            "applicant requested at registration. `administrator` and "
            "`pending` are rejected -- see the model docstring."
        ),
        examples=["viewer"],
        # See app/models/role.py for why this is json_schema_extra and not
        # a Literal/Enum type: the validator normalises with
        # .strip().lower() after Pydantic's own coercion, and an enum type
        # would reject non-canonical casing before that ever runs.
        json_schema_extra={"enum": ASSIGNABLE_ROLES},
    )
    dataset_id: str | None = Field(
        default=None,
        description=(
            "Name of the Network to scope this user to. Omit to leave the "
            "applicant's requested value unchanged, or send an empty string "
            "to clear any scope. Must match an existing Network."
        ),
        examples=["IDROLOGIA"],
    )

    @field_validator("assigned_role")
    @classmethod
    def role_must_be_valid(cls, v: str | None) -> str | None:
        """Pass the value through validate_rbac_role, unless omitted.

        None means "use the applicant's requested_role" -- resolved by the
        endpoint handler, which has the DB row this model doesn't. Only a
        supplied value is validated here.

        Raises ``ValueError`` (which Pydantic converts to a 422 response)
        if the role is not one of the permitted assignable roles.
        """
        if v is None:
            return None
        return validate_rbac_role(v)


class ApprovalResponse(BaseModel):
    """Documentation-only: the body PATCH .../policy-approval returns on
    success. Built as a plain dict in the handler -- see app/models/error.py."""

    message: str = Field(examples=["User 'jdoe' (id=42) has been approved with role 'viewer'."])
    user_id: int = Field(examples=[42])
    granted_role: str = Field(examples=["viewer"])
    dataset_id: str | None = Field(default=None, examples=["IDROLOGIA"])
