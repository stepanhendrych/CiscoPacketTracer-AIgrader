"""Core grading pipeline for PT-AI-Grader."""

import argparse
import csv
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from PTexplorer import decrypt_pkt_file


# ---------------------------------------------------------------------------
# Config & constants
# ---------------------------------------------------------------------------

MODEL_CONTEXT_MAP: dict[str, int] = {
    "nvidia/nemotron-3-super-120b-a12b": 131072,
    # Extend with known models as needed.
}

PROMPT_TEMPLATE_SCHEMA = """\
You are a strict grading-schema parser for a Cisco Packet Tracer assignment.

TASK:
Parse the following grading text into a structured JSON object matching this exact schema:
{{
  "criteria": [
    {{"id": "c1", "description": "...", "max_points": 1}}
  ],
  "grading_scale": [
    {{"min_points": 0, "max_points": 1, "grade": "5"}}
  ],
  "max_total_points": 4
}}

RULES:
- Assign stable, short ids: c1, c2, c3, ...
- max_points must be integer.
- grading_scale must cover 0..max_total_points without gaps.
- Output ONLY valid JSON. No markdown, no explanations.

INPUT GRADING TEXT:
{criteria_text}

TEMPLATE REFERENCE (for context only; do not copy into schema):
{template_xml}
"""

PROMPT_TEMPLATE_GRADE_SINGLE = """\
You are a strict, deterministic grader for a Cisco Packet Tracer assignment.

TASK:
Evaluate the STUDENT SUBMISSION against the CRITERIA and the TEMPLATE REFERENCE.

CRITERIA (JSON):
{criteria_json}

TEMPLATE REFERENCE:
{template_xml}

STUDENT SUBMISSION (XML):
{student_xml}

OUTPUT RULES:
- Output ONLY valid JSON matching this schema:
{{
  "criteria": [
    {{"id": "c1", "awarded_points": 1, "max_points": 1, "met": true, "comment": "..."}}
  ],
  "total_points": 4,
  "max_points": 4,
  "grade": "1",
  "feedback": "..."
}}
- awarded_points must be between 0 and max_points inclusive.
- met must be true if awarded_points == max_points.
- Be concise in comments.
"""

PROMPT_TEMPLATE_GRADE_CHUNK = """\
This is chunk {chunk_idx} of {chunk_total} from a student Packet Tracer submission.

TASK:
Evaluate the criteria you can verify from THIS CHUNK ONLY.

CRITERIA (JSON):
{criteria_json}

TEMPLATE REFERENCE (abbreviated if needed):
{template_xml}

STUDENT SUBMISSION CHUNK {chunk_idx}/{chunk_total}:
{student_xml_chunk}

OUTPUT RULES:
- Return ONLY valid JSON:
{{
  "findings": [
    {{"id": "c1", "status": "met|not_met|unknown", "evidence": "..."}}
  ]
}}
- If a criterion spans across chunks, set status="unknown".
- Do NOT invent evidence not present in this chunk.
"""

PROMPT_TEMPLATE_REDUCE = """\
You are reducing chunk-wise evaluation findings into a final grade.

TASK:
Merge the following findings into one final result per criterion.

CRITERIA (JSON):
{criteria_json}

FINDINGS FROM CHUNKS (JSON array):
{findings_json}

OUTPUT RULES:
- Output ONLY valid JSON matching this schema:
{{
  "criteria": [
    {{"id": "c1", "awarded_points": 1, "max_points": 1, "met": true, "comment": "..."}}
  ],
  "total_points": 4,
  "max_points": 4,
  "grade": "1",
  "feedback": "..."
}}
- awarded_points must be between 0 and max_points inclusive.
- For "unknown" findings, award 0 points and note "cross-chunk evidence".
"""


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def get_env() -> dict[str, Any]:
    """Load and validate required env vars."""
    load_dotenv()
    required = ["LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"]
    missing = [k for k in required if not os.getenv(k)]
    if missing:
        print(f"Error: missing env vars {missing}", file=sys.stderr)
        sys.exit(1)
    temperature = float(os.getenv("LLM_TEMPERATURE", "0.0"))
    context_tokens = int(os.getenv("LLM_CONTEXT_TOKENS", "0"))
    if context_tokens == 0:
        context_tokens = MODEL_CONTEXT_MAP.get(os.getenv("LLM_MODEL", ""), 131072)
    return {
        "api_key": os.environ["LLM_API_KEY"],
        "base_url": os.environ["LLM_BASE_URL"],
        "model": os.environ["LLM_MODEL"],
        "temperature": temperature,
        "context_tokens": context_tokens,
    }


def build_client() -> OpenAI:
    """Build OpenAI-compatible client from env."""
    cfg = get_env()
    return OpenAI(
        api_key=cfg["api_key"],
        base_url=cfg["base_url"],
    )


# ---------------------------------------------------------------------------
# Folder validation
# ---------------------------------------------------------------------------

def validate_assignment_folder(folder: Path) -> tuple[Path, Path, Path, list[Path]]:
    """Validate structure and return (criteria, template, submitted_dir, student_files)."""
    if not folder.is_dir():
        raise NotADirectoryError(f"Assignment folder not found: {folder}")
    criteria = folder / "criteria.txt"
    template = folder / "template.pkt"
    submitted_dir = folder / "submitted"
    for p in (criteria, template, submitted_dir):
        if not p.exists():
            raise FileNotFoundError(f"Required path missing: {p}")
    student_files = sorted(submitted_dir.glob("*.pkt"))
    if not student_files:
        raise ValueError(f"No .pkt files in {submitted_dir}")
    return criteria, template, submitted_dir, student_files


# ---------------------------------------------------------------------------
# Token estimation & chunking
# ---------------------------------------------------------------------------

def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return max(1, len(text) // 4)


def split_text_into_chunks(text: str, max_tokens: int) -> list[str]:
    """
    Split text into chunks by character count to stay under max_tokens.
    Naive split; acceptable baseline for XML.
    """
    chars_per_chunk = max_tokens * 4
    if len(text) <= chars_per_chunk:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + chars_per_chunk, len(text))
        chunks.append(text[start:end])
        start = end
    return chunks


# ---------------------------------------------------------------------------
# LLM call wrappers with retry / backoff
# ---------------------------------------------------------------------------

def _call_llm_json(
    client: OpenAI,
    model: str,
    temperature: float,
    system_prompt: str,
    user_prompt: str,
    *,
    max_retries: int = 3,
    backoff_base: float = 2.0,
) -> dict[str, Any]:
    """Call LLM with json_object response_format and retry on invalid JSON."""
    last_err: Exception | None = None
    for attempt in range(max_retries):
        try:
            resp = client.chat.completions.create(
                model=model,
                temperature=temperature,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            content = resp.choices[0].message.content.strip()
            return json.loads(content)
        except Exception as e:
            last_err = e
            if attempt < max_retries - 1:
                sleep = backoff_base * (2 ** attempt)
                logging.warning(
                    "LLM call failed (attempt %d): %s. Retrying in %.1fs...",
                    attempt + 1, e, sleep,
                )
                time.sleep(sleep)
    raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_err}")


def _call_llm_with_backoff(
    client: OpenAI,
    model: str,
    temperature: float,
    system_prompt: str,
    user_prompt: str,
    *,
    max_retries: int = 5,
    backoff_base: float = 1.0,
) -> dict[str, Any]:
    """
    Wrap LLM call with rate-limit backoff (429 / transient) + JSON parse retry.
    """
    last_err: Exception | None = None
    for attempt in range(max_retries):
        try:
            return _call_llm_json(
                client, model, temperature, system_prompt, user_prompt,
                max_retries=3,
            )
        except Exception as e:
            last_err = e
            sleep = backoff_base * (2 ** attempt)
            logging.warning(
                "LLM transient error (attempt %d): %s. Backing off %.1fs...",
                attempt + 1, e, sleep,
            )
            time.sleep(sleep)
    raise RuntimeError(f"LLM call failed after {max_retries} retries: {last_err}")


# ---------------------------------------------------------------------------
# Phase 1: Criteria schema
# ---------------------------------------------------------------------------

def parse_criteria_schema(
    client: OpenAI,
    cfg: dict[str, Any],
    criteria_text: str,
    template_xml: str,
) -> dict[str, Any]:
    """Phase 1: one LLM call to produce structured criteria schema."""
    user_prompt = PROMPT_TEMPLATE_SCHEMA.format(
        criteria_text=criteria_text,
        template_xml=template_xml[:8000],
    )
    schema = _call_llm_with_backoff(
        client=client,
        model=cfg["model"],
        temperature=cfg["temperature"],
        system_prompt="You are a strict JSON-only parser.",
        user_prompt=user_prompt,
    )
    required = ("criteria", "grading_scale", "max_total_points")
    if not all(k in schema for k in required):
        raise ValueError(f"Schema JSON missing required keys: {required}")
    return schema


# ---------------------------------------------------------------------------
# Phase 2: Student evaluation
# ---------------------------------------------------------------------------

def compute_grade(points: int, grading_scale: list[dict[str, Any]]) -> str:
    """Deterministically compute grade from points and grading_scale."""
    for entry in grading_scale:
        if entry.get("min_points", -1) <= points <= entry.get("max_points", -1):
            return str(entry.get("grade", ""))
    return ""


def evaluate_student(
    client: OpenAI,
    cfg: dict[str, Any],
    criteria_schema: dict[str, Any],
    template_xml: str,
    student_xml: str,
) -> dict[str, Any]:
    """Evaluate one student submission with size-guard and map-reduce chunking."""
    criteria_list = criteria_schema["criteria"]
    criteria_json = json.dumps(criteria_list, ensure_ascii=False)
    grading_scale_json = json.dumps(criteria_schema["grading_scale"], ensure_ascii=False)
    max_total = criteria_schema["max_total_points"]
    grading_scale = criteria_schema["grading_scale"]

    reference_prompt = (
        f"CRITERIA:\n{criteria_json}\n\n"
        f"GRADING_SCALE:\n{grading_scale_json}\n"
        f"MAX_TOTAL_POINTS: {max_total}\n\n"
        f"TEMPLATE REFERENCE:\n{template_xml}\n"
    )

    ref_tokens = estimate_tokens(reference_prompt)
    student_tokens = estimate_tokens(student_xml)
    answer_reserve = 2000
    limit = int(cfg["context_tokens"] * 0.8)
    available_for_student = limit - ref_tokens - answer_reserve

    if student_tokens <= available_for_student or available_for_student < 1000:
        # Single-call path
        user_prompt = PROMPT_TEMPLATE_GRADE_SINGLE.format(
            criteria_json=criteria_json,
            template_xml=template_xml,
            student_xml=student_xml,
        )
        result = _call_llm_with_backoff(
            client=client,
            model=cfg["model"],
            temperature=cfg["temperature"],
            system_prompt=(
                "You are a strict, deterministic grader. "
                "Always respond with valid JSON only."
            ),
            user_prompt=user_prompt,
        )
    else:
        # Chunked map-reduce path
        chunk_max_tokens = max(500, (available_for_student // 2) // 4 * 4)
        chunks = split_text_into_chunks(student_xml, chunk_max_tokens)
        findings: list[dict[str, Any]] = []

        for idx, chunk in enumerate(chunks, start=1):
            user_prompt = PROMPT_TEMPLATE_GRADE_CHUNK.format(
                chunk_idx=idx,
                chunk_total=len(chunks),
                criteria_json=criteria_json,
                template_xml=template_xml[:4000],
                student_xml_chunk=chunk,
            )
            chunk_result = _call_llm_with_backoff(
                client=client,
                model=cfg["model"],
                temperature=cfg["temperature"],
                system_prompt=(
                    "You are a strict evaluator. "
                    "Always respond with valid JSON only."
                ),
                user_prompt=user_prompt,
            )
            for f in chunk_result.get("findings", []):
                findings.append(f)

        reduce_prompt = PROMPT_TEMPLATE_REDUCE.format(
            criteria_json=criteria_json,
            findings_json=json.dumps(findings, ensure_ascii=False),
        )
        result = _call_llm_with_backoff(
            client=client,
            model=cfg["model"],
            temperature=cfg["temperature"],
            system_prompt=(
                "You are a strict reducer. "
                "Always respond with valid JSON only."
            ),
            user_prompt=reduce_prompt,
        )

    # Deterministic post-processing: fix total_points and grade from awarded_points
    awarded = 0
    for c in result.get("criteria", []):
        try:
            awarded += int(c.get("awarded_points", 0))
        except (TypeError, ValueError):
            pass
    result["total_points"] = awarded
    result["max_points"] = max_total
    result["grade"] = compute_grade(awarded, grading_scale)
    return result


# ---------------------------------------------------------------------------
# CSV writing
# ---------------------------------------------------------------------------

CRITERIA_COLUMN_HEADER = "{id}: {description} ({max_points})"


def write_results_csv(
    out_path: Path,
    schema: dict[str, Any],
    results: list[dict[str, Any]],
) -> None:
    """Write results.csv with dynamic columns from schema."""
    criteria = schema["criteria"]
    headers = ["student_file", "total_points", "max_points", "grade"]
    for c in criteria:
        headers.append(CRITERIA_COLUMN_HEADER.format(**c))
    headers.append("feedback")

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row: dict[str, Any] = {
                "student_file": r.get("student_file", ""),
                "total_points": r.get("total_points", ""),
                "max_points": r.get("max_points", ""),
                "grade": r.get("grade", ""),
                "feedback": r.get("feedback", ""),
            }
            for c in criteria:
                cid = c["id"]
                found = next(
                    (x for x in r.get("criteria", []) if x["id"] == cid),
                    None,
                )
                if found is not None:
                    row[CRITERIA_COLUMN_HEADER.format(**c)] = found.get("awarded_points", "")
                else:
                    row[CRITERIA_COLUMN_HEADER.format(**c)] = ""
            writer.writerow(row)


# ---------------------------------------------------------------------------
# Resume support
# ---------------------------------------------------------------------------

def load_resume_set(csv_path: Path) -> set[str]:
    """Return set of student files already present in results.csv."""
    if not csv_path.exists():
        return set()
    done: set[str] = set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("student_file"):
                done.add(row["student_file"])
    return done


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Grade Cisco Packet Tracer assignments using LLM.",
    )
    parser.add_argument(
        "assignment_folder",
        nargs="?",
        default="assigment_example",
        help="Folder containing criteria.txt, template.pkt, and submitted/*.pkt",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip students already present in results.csv",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override LLM model from .env",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output CSV path (default: <assignment_folder>/results.csv)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    folder = Path(args.assignment_folder)
    criteria_path, template_path, submitted_dir, student_files = validate_assignment_folder(folder)

    cfg = get_env()
    if args.model:
        cfg["model"] = args.model

    client = build_client()

    criteria_text = criteria_path.read_text(encoding="utf-8")
    template_xml = decrypt_pkt_file(str(template_path))
    logging.info("Template decrypted (%d chars)", len(template_xml))

    logging.info("Phase 1: parsing criteria schema...")
    schema = parse_criteria_schema(client, cfg, criteria_text, template_xml)
    logging.info(
        "Schema parsed: %d criteria, max %d pts",
        len(schema["criteria"]),
        schema["max_total_points"],
    )

    out_path = Path(args.out) if args.out else folder / "results.csv"
    done = load_resume_set(out_path) if args.resume else set()

    results: list[dict[str, Any]] = []
    for sf in student_files:
        name = sf.name
        if name in done:
            logging.info("Resume: skipping %s", name)
            continue
        try:
            logging.info("Evaluating %s...", name)
            student_xml = decrypt_pkt_file(str(sf))
            result = evaluate_student(client, cfg, schema, template_xml, student_xml)
            result["student_file"] = name
            results.append(result)
        except Exception as e:  # noqa: BLE001
            logging.exception("Failed to grade %s: %s", name, e)
            results.append({
                "student_file": name,
                "criteria": [],
                "total_points": "",
                "max_points": schema["max_total_points"],
                "grade": "",
                "feedback": f"ERROR: {e}",
            })

    write_results_csv(out_path, schema, results)
    logging.info("Results written to %s (%d rows)", out_path, len(results))


if __name__ == "__main__":
    run()
