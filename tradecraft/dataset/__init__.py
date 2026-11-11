"""
Standalone offline dataset extraction and transformation module for Tradecraft.

Transforms persisted engagement runs (`trace.jsonl`, `log.txt`, `facts.json`,
`manifest.json`) into high-quality SFT and DPO/preference training datasets
without depending on the live execution loop or reporting modules.
"""
from tradecraft.dataset.builder import (
    SUPPORTED_BEHAVIORS,
    SUPPORTED_DATASET_FORMATS,
    build_datasets_from_sources,
    evaluate_run_checklist,
    extract_dpo_records,
    extract_sft_records,
    normalize_behaviors,
    normalize_dataset_formats,
    write_datasets,
)
from tradecraft.dataset.loader import (
    RunDatasetSource,
    load_run_dataset_source,
    resolve_dataset_run_dirs,
)
from tradecraft.dataset.scrubber import apply_scrub_map, build_scrub_map

__all__ = [
    "SUPPORTED_DATASET_FORMATS",
    "SUPPORTED_BEHAVIORS",
    "RunDatasetSource",
    "load_run_dataset_source",
    "resolve_dataset_run_dirs",
    "normalize_dataset_formats",
    "normalize_behaviors",
    "evaluate_run_checklist",
    "extract_sft_records",
    "extract_dpo_records",
    "build_datasets_from_sources",
    "write_datasets",
    "build_scrub_map",
    "apply_scrub_map",
]
