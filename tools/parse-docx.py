import json
from docx import Document

def parse_docx_tables(docx_path):
    doc = Document(docx_path)
    all_rows = []
    last_category = ""

    for table in doc.tables:
        for row in table.rows[1:]:  # Skip header row
            cells = [cell.text.strip() for cell in row.cells]
            if len(cells) < 3:
                cells += [""] * (3 - len(cells))  # Ensure 3 elements

            category = cells[0] if cells[0] else last_category
            question = cells[1]
            additional_info = cells[2]

            if category:  # Update last_category only when present
                last_category = category

            row_data = {
                "category": category,
                "question": question,
                "additionalInformation": additional_info
            }
            all_rows.append(row_data)

    return all_rows

# Paths
docx_path = './laakitse.docx'
output_path = './docx_parse.txt'

# Parse and save
parsed_data = parse_docx_tables(docx_path)
with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(parsed_data, f, indent=2, ensure_ascii=False)

print(f"Saved JSON to {output_path}")
