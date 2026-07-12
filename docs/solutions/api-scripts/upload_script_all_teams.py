#!/usr/bin/env python3
"""Upload a shell script to every team on a Fleet server via the API.

First make sure the environment variable exists:
> export FLEET_API_TOKEN="your_token"
"""

import os
import pathlib
import sys

import requests

type JsonValue = (
    bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None
)

api_token = os.getenv("FLEET_API_TOKEN")
if not api_token:
    sys.exit("No token found in the environment")

#############################
# ENTER YOUR INFORMATION HERE
#############################
base_url = "https://your-Fleet-server.com"  # no trailing slash
api_path = "api/v1/fleet"
script_path = "script.sh"  # relative path to this file (example is a script in the same directory)
#
# END

REQUEST_TIMEOUT = 30


def get_all_results(
    endpoint: str,
    key: str,
    headers: dict[str, str] | None = None,
    params: dict[str, str | int] | None = None,
    per_page: int = 10,
) -> list[dict[str, JsonValue]]:
    """Generic GET request that handles pagination."""
    all_results = []
    page = 0

    if params is None:
        params = {}

    endpoint = f"{base_url}/{api_path}/{endpoint}"
    headers = {"Authorization": f"Bearer {api_token}"}
    params["per_page"] = per_page

    while True:
        params["page"] = page

        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        results = response.json().get(key, [])

        if not results:
            break

        all_results.extend(results)

        if len(results) < per_page:
            break

        page += 1

    return all_results


def upload_script(script_path: str, team_id: int) -> requests.Response:
    """Upload a script to team if not already present.

    Patch it if present.
    """
    headers = {"Authorization": f"Bearer {api_token}"}
    script_name = pathlib.Path(script_path).name

    # Check if script already exists in this team
    existing_scripts = get_all_results(
        "scripts",
        "scripts",
        params={"team_id": team_id},
    )

    existing_script_id = None
    for script in existing_scripts:
        if script.get("name") == script_name:
            existing_script_id = script.get("id")
            break

    with pathlib.Path(script_path).open("rb") as script_file:
        files = {
            "script": (
                script_name,
                script_file,
                "application/octet-stream",
            ),
        }

        if existing_script_id:
            # Script exists - PATCH to update
            endpoint = f"{base_url}/{api_path}/scripts/{existing_script_id}"
            response = requests.patch(
                endpoint,
                headers=headers,
                files=files,
                timeout=REQUEST_TIMEOUT,
            )
            action = "updated"
        else:
            # Script doesn't exist - POST to create
            endpoint = f"{base_url}/{api_path}/scripts"
            files["team_id"] = (None, str(team_id))  # Add team_id to form data
            response = requests.post(
                endpoint,
                headers=headers,
                files=files,
                timeout=REQUEST_TIMEOUT,
            )
            action = "created"

    response.raise_for_status()
    print(f"Script '{script_name}' {action} for team_id {team_id}")

    return response


if __name__ == "__main__":
    all_teams = get_all_results("teams", "teams")
    all_team_ids = {team["id"]: team["name"] for team in all_teams}
    for team_id in all_team_ids:
        response = upload_script(script_path, team_id)
