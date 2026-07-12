#!/usr/bin/env python3
"""Diff the recommendation sections of two CIS Benchmark PDFs.

For example: generate a diff of the Win10 & W11 benchmarks.
Requires installation of the PyMuPDF dep (pip3 install PyMuPDF).
cmd line example: python3 ./CIS-Benchmark-diff.py File1.pdf File2.pdf
"""

import difflib
import pathlib
import re
import sys
from datetime import UTC, datetime

import fitz  # PyMuPDF

# Script name plus the two PDF paths.
REQUIRED_ARGC = 3


def is_start_of_new_item(line: str) -> bool:
    """Check if a line starts with a number pattern like '1', '1.1', up to '100.7.32'."""
    return bool(re.match(r"\d{1,3}(?:\.\d{1,2}){0,2}", line.strip()))


def remove_trailing_whitespace(text: str) -> str:
    """Remove trailing whitespace from each line in the text."""
    return "\n".join(line.rstrip() for line in text.split("\n"))


def correct_word_wrapping(text: str) -> str:
    """Correct word wrapping issues in the extracted text.

    Each line should start with a number pattern from '1' to '100.7.32'.
    """
    lines = text.split("\n")
    corrected_lines = []
    for line in lines:
        if corrected_lines and not is_start_of_new_item(line):
            # Append this line to the previous one
            corrected_lines[-1] += " " + line
        else:
            corrected_lines.append(line)
    return "\n".join(corrected_lines)


def extract_recommendations_fitz(
    pdf_path: str,
    start_phrase: str,
    end_phrase: str,
) -> str:
    """Extract a specific section from a PDF file."""
    doc = fitz.open(pdf_path)
    recommendations = ""
    capture = False

    for page in doc:
        text_blocks = page.get_text("blocks")
        for block in text_blocks:
            block_text = block[4].strip()  # Extract text from the block
            if block_text:
                # Check for the start and end of the section
                if start_phrase in block_text and not capture:
                    capture = True
                elif end_phrase in block_text and capture:
                    capture = False
                    break

                if capture:
                    recommendations += block_text + "\n"

    # Cleanup process
    recommendations_cleaned = re.sub(
        r"Page\s+\d{1,3}",
        "",
        recommendations,
    )  # Remove "Page <number>" lines
    recommendations_cleaned = re.sub(
        r"\.{2,}\s*\d+",
        "",
        recommendations_cleaned,
    )  # Remove periods followed by page numbers
    recommendations_cleaned = re.sub(
        r"\s+\d{2,4}\s*$",
        "",
        recommendations_cleaned,
        flags=re.MULTILINE,
    )  # Remove 2 to 4 digit numbers at the end of lines
    recommendations_corrected = correct_word_wrapping(
        recommendations_cleaned,
    )  # Correct word wrapping
    return remove_trailing_whitespace(
        recommendations_corrected,
    )  # Remove trailing whitespace


def create_custom_diff(text1: str, text2: str) -> str:
    """Create a custom diff of two texts with custom labels."""
    text1_lines = text1.splitlines()
    text2_lines = text2.splitlines()

    # Generate a diff without additional context lines
    diff = difflib.unified_diff(
        text1_lines,
        text2_lines,
        lineterm="",
        fromfile="file1",
        tofile="file2",
        n=0,
    )  # 'n=0' for no context lines

    # Customizing diff output to replace '+' and '-' with 'file1' and 'file2'
    custom_diff = []
    for line in diff:
        if line.startswith("-"):
            custom_diff.append("file1: " + line[1:])
        elif line.startswith("+"):
            custom_diff.append("file2: " + line[1:])
        else:
            custom_diff.append(line)

    return "\n".join(custom_diff)


def main(file1: str, file2: str) -> None:
    """Extract recommendations from both PDFs and write the diff outputs."""
    # Start and end phrases for the extraction
    start_phrase = "Recommendations ..."
    end_phrase = "Appendix: Summary Table ..."

    # Extract recommendations from both PDFs
    recommendations_file1 = extract_recommendations_fitz(
        file1,
        start_phrase,
        end_phrase,
    )
    recommendations_file2 = extract_recommendations_fitz(
        file2,
        start_phrase,
        end_phrase,
    )

    # Write the cleaned and corrected data to a file
    with pathlib.Path("cleaned.txt").open("w", encoding="utf-8") as file:
        file.write("Cleaned Data from file 1 PDF:\n\n")
        file.write(recommendations_file1)
        file.write("\n\nCleaned Data from file 2 PDF:\n\n")
        file.write(recommendations_file2)
    print("Cleaned data file created: cleaned.txt")

    # Perform the custom diff
    diff_result = create_custom_diff(recommendations_file1, recommendations_file2)

    # Write the diff result to a file with a timestamp
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    with pathlib.Path("cis_benchmarks_diff.txt").open("w", encoding="utf-8") as file:
        file.write(f"Diff generated on: {timestamp}\n\n")
        file.write(diff_result)
    print("Diff file created: cis_benchmarks_diff.txt")


if __name__ == "__main__":
    if len(sys.argv) != REQUIRED_ARGC:
        print(
            "Usage: python script.py <path_to_cis_benchmark_1_pdf> <path_to_cis_benchmark_2_pdf>",
        )
        sys.exit(1)

    file1 = sys.argv[1]
    file2 = sys.argv[2]
    main(file1, file2)
