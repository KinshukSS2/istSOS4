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

"""The ``networks`` grant list shared by every endpoint that assigns access.

A user's access is a list of grants. Each grant names the Networks it
covers, the role the user holds in them and, for the ``custom`` role only, the
policy that defines what that role may do::

    "networks": [
      { "network_name": [],                "role": "viewer", "policy": ""            },
      { "network_name": ["psos", "acsot"], "role": "custom", "policy": "policyname1" }
    ]

* ``network_name: []`` means *all Networks*. It is only honoured when an
  administrator saves it; an applicant's ``[]`` is just a request.
* Several grants may cover the same Network; the user then holds the union of
  what they allow.
* Unknown fields are rejected (422). Silently ignoring a misspelt field is how
  an administrator's role override went unnoticed for months.
"""

import re
from typing import Annotated

from app.rbac_roles import ASSIGNABLE_ROLES, validate_rbac_role
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

MAX_GRANTS = 20
MAX_NETWORKS_PER_GRANT = 100


class NetworkGrant(BaseModel):
    """One entry of the ``networks`` list."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"network_name": ["psos", "acsot"], "role": "editor", "policy": ""}
            ]
        },
    )

    network_name: list[str] = Field(
        description=(
            "Names of the Networks this grant covers. An empty list means "
            "**all** Networks (only an administrator can save that). Ignored "
            "when the deployment runs with NETWORK=0."
        ),
        examples=[["psos", "acsot"]],
        max_length=MAX_NETWORKS_PER_GRANT,
    )
    role: str = Field(
        description="The role held in those Networks.",
        examples=["viewer"],
        json_schema_extra={"enum": ASSIGNABLE_ROLES},
    )
    policy: str = Field(
        default="",
        description=(
            "Name of the custom policy. Only for the `custom` role; must be "
            "empty or omitted for every other role."
        ),
        examples=[""],
    )

    @field_validator("role")
    @classmethod
    def _role_ok(cls, v: str) -> str:
        return validate_rbac_role(v)

    @field_validator("network_name")
    @classmethod
    def _names_ok(cls, v: list[str]) -> list[str]:
        cleaned = [n.strip() for n in v]
        if any(not n for n in cleaned):
            raise ValueError("network_name entries must be non-empty strings")
        if any(_CONTROL_CHARS.search(n) for n in cleaned):
            raise ValueError("network_name must not contain control characters")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("network_name lists the same Network twice")
        return cleaned

    @field_validator("policy")
    @classmethod
    def _policy_trim(cls, v: str) -> str:
        v = v.strip()
        if _CONTROL_CHARS.search(v):
            raise ValueError("policy must not contain control characters")
        return v

    @model_validator(mode="after")
    def _policy_only_for_custom(self):
        if self.policy and self.role != "custom":
            raise ValueError("policy is only allowed on a 'custom' grant")
        return self


GrantList = Annotated[list[NetworkGrant], Field(max_length=MAX_GRANTS)]


class NetworksUpdateRequest(BaseModel):
    """Body of PATCH /Users/{user_id}/networks: the user's complete new list
    of grants. It replaces every existing grant in one transaction."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "networks": [
                        {"network_name": ["psos"], "role": "editor", "policy": ""}
                    ]
                }
            ]
        },
    )

    networks: GrantList = Field(
        min_length=1,
        description=(
            "The user's complete new access. Replaces all existing grants. "
            "`network_name: []` grants all Networks."
        ),
    )
