"""
Base utilities for CVE API mapping tests
"""
import json
import os
from typing import Dict, List, Any
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def load_lib2cve_data(file_path: str = "/home/s3zer0/system-security/DB/lib2cve2api.json") -> Dict:
    """Load the lib2cve2api.json data"""
    with open(file_path, 'r') as f:
        return json.load(f)

def extract_cve_info(library_name: str, version: str, data: Dict) -> Dict[str, Any]:
    """Extract CVE and API information for a specific library and version"""
    if library_name not in data:
        return {"cves": [], "apis": {}}

    if version not in data[library_name]:
        return {"cves": [], "apis": {}}

    lib_data = data[library_name][version]
    return {
        "cves": lib_data.get("cves", []),
        "apis": lib_data.get("apis", {})
    }

def format_api_list(apis: Dict[str, List[str]]) -> str:
    """Format API list for prompt"""
    api_lines = []
    for module, api_list in apis.items():
        for api in api_list:
            api_lines.append(api)
    return "\n".join(api_lines)

def get_mock_cve_descriptions() -> Dict[str, str]:
    """
    Return mock CVE descriptions for testing
    실제 서비스에서는 CVE 데이터베이스나 NVD API에서 가져와야 함
    """
    return {
        "CVE-2020-14343": "A vulnerability was discovered in the PyYAML library caused by a flaw in the yaml.load() function. By persuading a victim to open a specially-crafted YAML file, a remote attacker could execute arbitrary code on the system.",
        "CVE-2023-30861": "Flask is a lightweight WSGI web application framework. When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by the proxy to other clients.",
        "CVE-2021-33503": "An issue was discovered in urllib3 before 1.26.5. When provided with a URL containing many @ characters, the authority regular expression exhibits catastrophic backtracking.",
        "CVE-2022-42969": "The py library before 1.11.0 for Python allows remote attackers to conduct Local File Inclusion attacks via py.path.svnwc.XMLWCStatus, py.path.svnurl.XMLInfo, py.path.svnwc.XMLEntries, py.path.svnurl.XMLLog, or py.xml.html",
        "CVE-2019-16865": "An issue was discovered in Pillow before 6.2.0. When reading specially crafted invalid image files, the library can either allocate very large amounts of memory or take an extremely long period of time to process the image.",
    }

def create_prompt(library_name: str, library_version: str, api_list: str, cve_descriptions: Dict[str, str]) -> str:
    """Create the prompt for LLM"""
    cve_desc_text = "\n".join([f"{cve_id}: {desc}" for cve_id, desc in cve_descriptions.items()])

    system_prompt = """### System Prompt / Role Definition ###
You are a top-level cybersecurity analyst specializing in static code analysis. Your mission is to identify API functions from the provided API list that are directly related to vulnerabilities described in the given CVE (Common Vulnerabilities and Exposures) report set. Your analysis must be accurate, technically sound, and provide clear justification.

### Context Information ###
- Library Name: {library_name}
- Library Version: {library_version}
- Target API List:
{api_list}
- Target CVE Descriptions:
{cve_descriptions}

### Task Instructions ###
1. Carefully read and analyze each "Target CVE Description" provided above.
2. For each CVE, select API functions from the "Target API List" ONLY that are directly related to vulnerable functionality explicitly mentioned or strongly implied in the description.
3. For each CVE, provide a concise but technically accurate explanation in ENGLISH for why you selected the APIs. Your explanation should quote specific phrases from the CVE description to justify your selection.
4. If you determine that no APIs in the list are related to a specific CVE, leave the API list empty for that CVE. Do not guess or create non-existent APIs.
5. IMPORTANT: All explanations in the "reason" field must be written in ENGLISH only.

### Output Format Specification ###
Your final output must be a single valid JSON object that complies with the schema specified below. Do not include any explanatory text, markdown formatting (```json...```), or apologies outside the JSON object.

{{
  "CVE-ID_1": {{
    "apis": ["module.api1", "module.api2"],
    "reason": "The phrase '...' in the CVE description indicates that module.api1 and module.api2 can create arbitrary objects during deserialization."
  }},
  "CVE-ID_2": {{
    "apis": ["module.api3"],
    "reason": "CVE-ID_2 explicitly mentions a buffer overflow occurring in module.api3."
  }}
}}"""

    return system_prompt.format(
        library_name=library_name,
        library_version=library_version,
        api_list=api_list,
        cve_descriptions=cve_desc_text
    )

def save_response(response: str, output_file: str):
    """Save LLM response to file"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(response)

def parse_llm_response(response: str) -> Dict:
    """Parse LLM response and extract JSON"""
    try:
        # Remove any markdown code blocks if present
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            response = response[start:end].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            response = response[start:end].strip()

        return json.loads(response)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON response: {e}")
        return {}