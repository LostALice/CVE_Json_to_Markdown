# Code by AkinoAlice@TyrantRey

import json
import os
from pathlib import Path

MARKDOWN_PATH = "./markdown/"


def json_to_markdown(json_data):
    cve_id = json_data["cveMetadata"]["cveId"]
    cna = json_data["containers"]["cna"]

    description = next(
        (d["value"] for d in cna["descriptions"] if d["lang"] == "en"), ""
    )

    affected_sections = []
    for aff in cna.get("affected", []):
        vendor = aff.get("vendor", "Unknown")
        product = aff.get("product", "Unknown")
        platforms = ", ".join(aff.get("platforms", []))
        versions = "\n".join(
            [
                f"    - {v['version']} - {v.get('status', '')}, <= {v.get('lessThanOrEqual', '')}"
                for v in aff.get("versions", [])
            ]
        )
        affected_sections.append(
            f"- **Vendor**: {vendor}\n  **Product**: {product}\n  **Platforms**: {platforms}\n  **Versions**:\n{versions}"
        )

    impacts = "\n".join(
        [
            f"- {i['descriptions'][0]['value']} (CAPEC ID: {i.get('capecId')})"
            for i in cna.get("impacts", [])
        ]
    )

    cvss = cna.get("metrics", [{}])[0].get("cvssV3_1", {})
    cvss_info = (
        f"- **Base Score**: {cvss.get('baseScore', '')} ({cvss.get('baseSeverity', '')})\n"
        f"- **Vector**: {cvss.get('vectorString', '')}\n"
        f"- **Attack Vector**: {cvss.get('attackVector', '')}\n"
        f"- **Attack Complexity**: {cvss.get('attackComplexity', '')}\n"
        f"- **Privileges Required**: {cvss.get('privilegesRequired', '')}\n"
        f"- **User Interaction**: {cvss.get('userInteraction', '')}\n"
        f"- **Scope**: {cvss.get('scope', '')}\n"
        f"- **Confidentiality Impact**: {cvss.get('confidentialityImpact', '')}\n"
        f"- **Integrity Impact**: {cvss.get('integrityImpact', '')}\n"
        f"- **Availability Impact**: {cvss.get('availabilityImpact', '')}"
    )

    problem_types = "\n".join(
        [
            f"- {pt['descriptions'][0]['description']} (CWE ID: {pt['descriptions'][0].get('cweId')})"
            for pt in cna.get("problemTypes", [])
        ]
    )

    references = "\n".join(
        [f"- [{r['url']}]({r['url']})" for r in cna.get("references", [])]
    )

    solutions = "\n".join(
        [f"- {sol['value']}" for sol in cna.get("solutions", []) if sol["lang"] == "en"]
    )

    markdown = f"""# {cve_id}

## Description
{description}

## Affected Products
{chr(10).join(affected_sections)}

## Impact
{impacts}

## CVSS v3.1 Metrics
{cvss_info}

## Problem Type
{problem_types}

## References
{references}

## Solution
{solutions}
"""
    return markdown


def convert(input_file: str, output_file: str):
    with open("./json/" + input_file, "r", encoding="utf-8") as f:
        json_data = json.load(f)

    markdown = json_to_markdown(json_data)
    Path("./markdown/" + output_file).write_text(markdown, encoding="utf-8")
    print(f"Markdown file written to {output_file}")


if __name__ == "__main__":
    for json_file_name in os.listdir("./json"):
        markdown_file_name = json_file_name.split(".")[0] + ".md"
        convert(json_file_name, markdown_file_name)
