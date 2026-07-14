# PT-AI-Grader

Automated grading system for Cisco Packet Tracer (`.pkt`) assignments. It decrypts `.pkt` files locally into XML, sends them to an LLM alongside grading criteria and a teacher's template solution, and produces a `results.csv` with per-criterion scores, total points, and a deterministic grade.

---

## Main Idea

Network teachers often spend hours manually checking running-configs, IP addresses, and topologies when grading Packet Tracer submissions. This tool automates that:

1. Decrypts binary `.pkt` files to readable XML locally (no Packet Tracer needed).
2. Parses `criteria.txt` into a structured grading schema via LLM.
3. Evaluates each student submission against the schema + teacher's `template.pkt`.
4. Writes `results.csv` with a breakdown per criterion, total points, and grade.

---

## Project Structure

```text
PT-AI-Grader/
│
├── .env.example          # Environment variables template
├── .gitignore
├── .python-version
├── LICENSE
├── PTexplorer.py         # Decrypts .pkt files to XML
├── grader.py             # Main grading pipeline (CLI)
├── main.py               # Thin entry point calling grader.run()
├── pyproject.toml        # Dependencies and project metadata
├── uv.lock               # Lock file for reproducible installs
├── README.md
│
└── assigment_example/    # Example assignment
    ├── criteria.txt      # Free-text grading criteria + scale
    ├── template.pkt      # Teacher's reference solution
    └── submitted/        # Student submissions
        ├── student1_*.pkt
        ├── student2_*.pkt
        └── student3_*.pkt
```

---

## Installation

```bash
git clone https://github.com/stepanhendrych/CiscoPacketTracer-AIgrader
cd ciscoPacketTracer-AIgrader

# Recommended: uv
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Or pip
pip install -r requirements.txt  # if present
```

Create a `.env` file in the project root:

```env
LLM_API_KEY=your-api-key
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_TEMPERATURE=0.0
LLM_CONTEXT_TOKENS=131072
```

---

## Usage

### Prepare an assignment folder

```text
<assignment_folder>/
├── criteria.txt
├── template.pkt
└── submitted/
    ├── student1.pkt
    ├── student2.pkt
    └── ...
```

- `criteria.txt` — free text describing what to evaluate and point weights.
- `template.pkt` — teacher's correct solution (reference).
- `submitted/` — student `.pkt` files.

### Run

```bash
python grader.py assigment_example
```

Options:

- `--resume` — skip students already present in `results.csv`
- `--model MODEL` — override the model from `.env`
- `--out PATH` — custom output CSV path (default: `<assignment_folder>/results.csv`)

Output: `<assignment_folder>/results.csv`

---

## How It Works

### 1. Decryption

`PTexplorer.decrypt_pkt_file(path)` reads the binary `.pkt` file and returns the decrypted XML as a string.

### 2. Phase 1 — Criteria schema

One LLM call parses `criteria.txt` (plus a trimmed `template.pkt`) into a structured schema:

```json
{
  "criteria": [
    {"id": "c1", "description": "There is first PT8200 router", "max_points": 1}
  ],
  "grading_scale": [
    {"min_points": 0, "max_points": 1, "grade": "5"},
    {"min_points": 2, "max_points": 3, "grade": "3"},
    {"min_points": 4, "max_points": 4, "grade": "1"}
  ],
  "max_total_points": 4
}
```

The CSV columns are derived from this schema, so changing `criteria.txt` automatically changes the output columns.

### 3. Phase 2 — Student evaluation

For each student file:

1. Build a reference block: criteria JSON + grading scale + teacher XML.
2. Estimate token count (rough heuristic: ~4 chars/token).
3. **If the submission fits under 80 % of the context window**: single LLM call with the full student XML.
4. **If it exceeds the limit**: split the student XML into chunks, evaluate each chunk separately (`met` / `not_met` / `unknown`), then run a final reduction call to merge findings into points per criterion.

The LLM is instructed to return strict JSON only, and the client enforces `response_format={"type": "json_object"}`.

### 4. Deterministic grading

The final grade is computed in Python from `grading_scale` and the summed `awarded_points`. This ensures the grade is deterministic and not subject to LLM hallucinations about the grading scale.

### 5. CSV output

```text
student_file,total_points,max_points,grade,c1: There is first PT8200 Cisco router (1),c2: There is second PT8200 Cisco router (1),c3: The two PT8200 Cisco routers are connected to each other via a serial cable (2),feedback
student1_conneted.pkt,4,4,1,1,1,2,All criteria satisfied...
student2_disconnected.pkt,2,4,3,1,1,0,Two PT8200 routers are present but not connected...
student3_onlyOneRouter.pkt,2,4,3,1,1,0,"Two PT8200 routers are present but not connected..."
```

---

## Resilience

- **Retry on invalid JSON**: up to 3 inner retries with exponential backoff.
- **Retry on transient errors / rate limits**: up to 5 outer retries.
- **Per-student error isolation**: if one file fails to decrypt or grade, the script logs the error and writes an `ERROR` row instead of stopping.
- **Resume mode**: `--resume` skips students already present in the output CSV.

---

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `LLM_API_KEY` | Yes | — | API key for your LLM provider |
| `LLM_BASE_URL` | Yes | — | Base URL (OpenAI-compatible API) |
| `LLM_MODEL` | Yes | — | Model name |
| `LLM_TEMPERATURE` | No | `0.0` | Sampling temperature |
| `LLM_CONTEXT_TOKENS` | No | model-specific | Context window size in tokens |

Any OpenAI-compatible provider works (OpenAI, Groq, NVIDIA NIM, Mistral, local vLLM, etc.).

---

## Contributing

1. Fork the repo.
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request.

---

## License

This project is licensed under the GNU v3 License — see the [LICENSE](LICENSE) file for details.