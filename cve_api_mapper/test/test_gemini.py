"""
Google Gemini API test for CVE to API mapping
"""
import os
import json
from typing import Dict, Any
from dotenv import load_dotenv
from google import genai
from google.genai import types
from base_utils import (
    load_lib2cve_data,
    extract_cve_info,
    format_api_list,
    get_mock_cve_descriptions,
    create_prompt,
    save_response,
    parse_llm_response
)

class GeminiMapper:
    def __init__(self, api_key: str = None):
        """Initialize Gemini client"""
        load_dotenv()  # Load .env file
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable or api_key parameter is required")

        self.client = genai.Client(api_key=self.api_key)
        self.model = "gemini-2.5-pro"

    def map_cves_to_apis(self, library_name: str, library_version: str,
                         api_list: str, cve_descriptions: Dict[str, str]) -> Dict:
        """
        Send prompt to Gemini and get CVE to API mapping
        """
        prompt = create_prompt(library_name, library_version, api_list, cve_descriptions)

        # Add explicit JSON instruction for Gemini
        json_instruction = "\n\nIMPORTANT: Return ONLY a valid JSON object without any markdown formatting, code blocks, or explanatory text."

        try:
            # Configure generation parameters for more consistent JSON output
            config = types.GenerateContentConfig(
                temperature=0.1,
                max_output_tokens=4000,
                response_mime_type="application/json",  # Force JSON response
                thinking_config=types.ThinkingConfig(thinking_budget=0)  # Disable thinking for simpler tasks
            )

            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt + json_instruction,
                config=config
            )

            response_text = response.text
            return parse_llm_response(response_text)

        except Exception as e:
            print(f"Error calling Gemini API: {e}")
            return {}

def test_gemini_mapping():
    """Test Gemini CVE to API mapping"""
    print("=" * 50)
    print("Testing Google Gemini CVE to API Mapping")
    print("=" * 50)

    # Load data
    data = load_lib2cve_data()

    # Test with PyYAML as example
    library_name = "PyYAML"
    library_version = "5.3.1"

    # Extract CVE and API info
    lib_info = extract_cve_info(library_name, library_version, data)

    if not lib_info["apis"]:
        print(f"No API information found for {library_name} {library_version}")
        return

    # Format API list
    api_list = format_api_list(lib_info["apis"])

    # Get CVE descriptions (using mock data for now)
    cve_descriptions = get_mock_cve_descriptions()

    # Filter only relevant CVEs
    relevant_cves = {cve: desc for cve, desc in cve_descriptions.items()
                     if cve in lib_info["cves"]}

    if not relevant_cves:
        print(f"No matching CVE descriptions found for {library_name} {library_version}")
        relevant_cves = {"CVE-2020-14343": cve_descriptions.get("CVE-2020-14343", "")}

    print(f"Library: {library_name} {library_version}")
    print(f"CVEs to analyze: {list(relevant_cves.keys())}")
    print(f"Number of APIs available: {sum(len(apis) for apis in lib_info['apis'].values())}")

    # Initialize mapper
    try:
        mapper = GeminiMapper()

        # Get mapping
        print("\nSending request to Gemini...")
        result = mapper.map_cves_to_apis(
            library_name=library_name,
            library_version=library_version,
            api_list=api_list,
            cve_descriptions=relevant_cves
        )

        # Save and display results
        output_file = f"output/gemini_2.5_pro_{library_name}_{library_version}_mapping.json"
        save_response(json.dumps(result, indent=2), output_file)

        print(f"\nResults saved to: {output_file}")
        print("\nMapping Results:")
        print(json.dumps(result, indent=2))

        # Validate results
        print("\n" + "=" * 50)
        print("Validation:")
        for cve_id, mapping in result.items():
            api_count = len(mapping.get("apis", []))
            print(f"  {cve_id}: {api_count} APIs mapped")
            if mapping.get("reason"):
                print(f"    Reason: {mapping['reason'][:100]}...")

    except ValueError as e:
        print(f"\nError: {e}")
        print("Please set the GOOGLE_API_KEY environment variable:")
        print("  export GOOGLE_API_KEY='your-api-key-here'")

    except Exception as e:
        print(f"\nUnexpected error: {e}")

def batch_test_libraries():
    """Test multiple libraries from lib2cve2api.json"""
    print("=" * 50)
    print("Batch Testing Gemini CVE to API Mapping")
    print("=" * 50)

    data = load_lib2cve_data()
    cve_descriptions = get_mock_cve_descriptions()

    # Initialize mapper
    try:
        mapper = GeminiMapper()
    except ValueError as e:
        print(f"Error: {e}")
        return

    results = {}

    # Test first 3 libraries as example
    for i, (library_name, versions) in enumerate(data.items()):
        if i >= 3:  # Limit to 3 libraries for testing
            break

        for version, version_data in versions.items():
            if not version_data.get("apis"):
                continue

            print(f"\nProcessing {library_name} {version}...")

            lib_info = extract_cve_info(library_name, version, data)
            api_list = format_api_list(lib_info["apis"])

            # Get relevant CVEs
            relevant_cves = {cve: desc for cve, desc in cve_descriptions.items()
                           if cve in lib_info["cves"]}

            if not relevant_cves:
                print(f"  No CVE descriptions available, skipping...")
                continue

            # Get mapping
            result = mapper.map_cves_to_apis(
                library_name=library_name,
                library_version=version,
                api_list=api_list,
                cve_descriptions=relevant_cves
            )

            results[f"{library_name}_{version}"] = result
            print(f"  Mapped {len(result)} CVEs")

    # Save all results
    output_file = "output/gemini_batch_results.json"
    save_response(json.dumps(results, indent=2), output_file)
    print(f"\nBatch results saved to: {output_file}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--batch":
        batch_test_libraries()
    else:
        test_gemini_mapping()

    print("\nTo run batch test: python test_gemini.py --batch")