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

"""Pydantic schemas for PATCH /Users/{user_id}/policy-approval.

Design decisions
----------------
* An approval is ONE decision per user covering every grant, saved in one
  transaction. The administrator either sends the final list of grants
  (``networks``) or explicitly asks to approve exactly what the applicant
  requested (``approve_as_requested``). There is no silent default: an
  approval that does nothing but click through must say so.
* The administrator's list replaces the request completely. The applicant's
  request is only a hint; it is kept on the user for the record.
* Unknown fields are rejected (422): a silently ignored field is how an
  administrator's role override once went unnoticed for months.
"""

from typing import Annotated

from app.models.networks import MAX_GRANTS, NetworkGrant
from pydantic import BaseModel, ConfigDict, Field, model_validator


class AdminApprovalRequest(BaseModel):
    """Request body for PATCH /Users/{user_id}/policy-approval.

    Send exactly one of:

    ``networks``
        The grants to give the user -- a list of ``{network_name, role,
        policy}``. ``network_name: []`` grants all Networks. Replaces
        whatever the applicant asked for.

    ``approve_as_requested``
        ``true`` to grant exactly the applicant's own request.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "networks": [
                        {"network_name": [], "role": "viewer", "policy": ""},
                        {
                            "network_name": ["psos", "acsot"],
                            "role": "custom",
                            "policy": "policyname1",
                        },
                    ]
                },
                {"approve_as_requested": True},
            ]
        },
    )

    networks: (
        Annotated[list[NetworkGrant], Field(max_length=MAX_GRANTS)] | None
    ) = Field(
        default=None,
        description=(
            "The final list of grants. Replaces the applicant's request. "
            "At least one grant is required."
        ),
    )
    approve_as_requested: bool | None = Field(
        default=None,
        description="`true` to approve exactly what the applicant requested.",
    )

    @model_validator(mode="after")
    def _exactly_one(self):
        has_list = self.networks is not None
        as_requested = self.approve_as_requested is True
        if has_list == as_requested:
            raise ValueError(
                "Send exactly one of 'networks' or 'approve_as_requested': true."
            )
        return self


class ApprovalResponse(BaseModel):
    """Documentation-only: the body PATCH .../policy-approval returns on
    success. Built as a plain dict in the handler -- see app/models/error.py."""

    message: str = Field(examples=["User 'jdoe' (id=42) has been approved."])
    user_id: int = Field(examples=[42])
    username: str = Field(examples=["jdoe"])
    status: str = Field(examples=["active"])
    requested: list[dict] = Field(
        description="What the applicant asked for.",
        examples=[[{"network_name": ["psos"], "role": "viewer"}]],
    )
    granted: list[dict] = Field(
        description="What was actually granted (the saved grants).",
        examples=[[{"network_name": ["psos"], "role": "viewer", "policy": ""}]],
    )
    effective: list[dict] = Field(
        description=(
            "What the user ends up holding per Network ('*' = every Network). "
            "Grants add up."
        ),
        examples=[[{"network_name": "psos", "roles": ["viewer"]}]],
    )
    warnings: list[str] = Field(
        description="Things worth a second look, e.g. a custom grant with no policy.",
        examples=[[]],
    )
