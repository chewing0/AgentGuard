from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from agentguard.experiment_matrix import (
    BlackBoxMatrixResult,
    run_blackbox_experiment_matrix,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = Path(__file__).with_name("siliconflow-four-model-matrix.json")
DEFAULT_OUTPUT = PROJECT_ROOT / "runs" / "manual" / "siliconflow-four-model"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan or execute the 4-model x 2-repetition x 11-case "
            "SiliconFlow provider black-box matrix."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Result directory; unused unless --execute is supplied.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Make real provider calls. Without this flag only the safe plan is printed.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing output directory when executing.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = args.output if args.output.is_absolute() else PROJECT_ROOT / args.output
    result = run_blackbox_experiment_matrix(
        matrix_path=MATRIX_PATH,
        project_root=PROJECT_ROOT,
        output_dir=output,
        execute=args.execute,
        overwrite=args.overwrite,
    )
    payload = result.metrics() if isinstance(result, BlackBoxMatrixResult) else result
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
