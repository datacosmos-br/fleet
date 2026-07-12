#!/usr/bin/env python3
"""Update the minimum osquery version options in the Fleet frontend constants.

Fetches the osquery release tags from the GitHub API and inserts any new
versions into MIN_OSQUERY_VERSION_OPTIONS in frontend/utilities/constants.tsx.
"""

import http.client
import json
import os
import pathlib
import re

# Use GITHUB_WORKSPACE to get the root of your repository
repo_root = os.environ.get("GITHUB_WORKSPACE", "")
FILE_PATH = pathlib.Path(repo_root) / "frontend" / "utilities" / "constants.tsx"


def fetch_osquery_versions() -> list[str]:
    """Return the tag names of all osquery releases from the GitHub API."""
    conn = http.client.HTTPSConnection("api.github.com")
    conn.request(
        "GET",
        "/repos/osquery/osquery/releases",
        headers={"User-Agent": "Fleet/osquery-checker"},
    )
    resp = conn.getresponse()
    content = resp.read()
    conn.close()

    return [release["tag_name"] for release in json.loads(content.decode("utf-8"))]


def update_min_osquery_version_options(new_versions: list[str]) -> None:
    """Insert any new osquery versions into the frontend constants file."""
    content = FILE_PATH.read_text(encoding="utf-8")

    # Extract current versions
    current_versions = re.findall(
        r'\{ label: "(\d+\.\d+\.\d+) \+", value: "(\d+\.\d+\.\d+)" \}',
        content,
    )
    current_versions = [v[1] for v in current_versions]

    # Find new versions
    versions_to_add = [v for v in new_versions if v not in current_versions]

    if versions_to_add:
        # Prepare new entries
        new_entries = "\n".join(
            f'  {{ label: "{v} +", value: "{v}" }},' for v in versions_to_add
        )

        # Insert new entries after the first element
        updated_content = re.sub(
            r'(export const MIN_OSQUERY_VERSION_OPTIONS = \[\n  \{ label: "All", value: "" \},\n)',
            f"\\1{new_entries}\n",
            content,
        )

        # Write updated content back to file
        FILE_PATH.write_text(updated_content, encoding="utf-8")

        print(f"Added new versions: {versions_to_add}")
    else:
        print("No new versions to add.")


if __name__ == "__main__":
    new_versions = fetch_osquery_versions()
    update_min_osquery_version_options(new_versions)
