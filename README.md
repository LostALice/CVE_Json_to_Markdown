# CVE JSON to Markdown Converter

This repository provides a Python script that converts CVE JSON files into structured and readable Markdown format. It's especially useful for security researchers, analysts, and developers who want a clean summary of CVE data.

## Features

- Converts CVE JSON files (e.g., from MITRE or NVD) to Markdown
- Extracts key information such as:
  - CVE ID and description
  - Affected vendors/products/platforms/versions
  - CVSS v3.1 score details
  - Problem types (CWE)
  - References and suggested solutions
- Supports batch conversion of all JSON files in the `./json` directory

## Directory Structure

```
.
├── json/            # Input folder containing CVE JSON files
├── markdown/        # Output folder for converted Markdown files
├── convert.py       # Conversion script
└── README.md        # This file
```

## Usage

1. **Place CVE JSON files** in the `./json` folder.

2. **Run the script**:
   ```bash
   python main.py
   ```

3. **Find the output** in the `./markdown` folder. Each JSON will be converted to a `.md` file with the same base filename.

## Example

Input JSON:
```json
{
  "cveMetadata": {
    "cveId": "CVE-2023-12345"
  },
  "containers": {
    "cna": {
      "descriptions": [{"lang": "en", "value": "Example vulnerability."}],
      ...
    }
  }
}
```

Output Markdown:
```markdown
# CVE-2023-12345

## Description
Example vulnerability.

## Affected Products
- **Vendor**: ...
...
```

## Author

Created by **AkinoAlice @TyrantRey**

## License

This project is released under the MIT License.

---