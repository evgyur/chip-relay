from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import RelayConfig
from .hygiene import scan_path
from .workspace import init_run, load_manifest


@dataclass(frozen=True)
class PackResult:
    status: str
    run_id: str
    recipe_name: str
    recipe_dir: Path | None = None
    failed_gate: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "run_id": self.run_id,
            "recipe_name": self.recipe_name,
        }
        if self.recipe_dir is not None:
            payload["recipe_dir"] = str(self.recipe_dir)
        if self.failed_gate:
            payload["failed_gate"] = self.failed_gate
        return payload


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def slugify_name(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip().lower()).strip("-._")
    slug = re.sub(r"-+", "-", slug)
    if not slug:
        raise ValueError("recipe name is required")
    return slug


def pack_run(config: RelayConfig, run_dir: Path, *, name: str, force: bool = False) -> PackResult:
    manifest = load_manifest(run_dir)
    run_id = manifest.get("run_id", run_dir.name)
    recipe_name = slugify_name(name)

    if manifest.get("status") != "verified":
        return PackResult("failed", run_id, recipe_name, failed_gate="run_not_verified")

    hygiene = scan_path(run_dir)
    if hygiene.get("status") != "ok":
        return PackResult("failed", run_id, recipe_name, failed_gate="hygiene_scan")

    final_script = run_dir / "scripts" / "final.py"
    if not final_script.is_file():
        return PackResult("failed", run_id, recipe_name, failed_gate="final_script_missing")

    recipe_dir = config.recipes_dir / recipe_name
    if recipe_dir.exists():
        if not force:
            return PackResult("failed", run_id, recipe_name, recipe_dir=recipe_dir, failed_gate="recipe_exists")
        shutil.rmtree(recipe_dir)
    recipe_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(final_script, recipe_dir / "final.py")
    recipe = {
        "schema": "chip-relay-recipe-v1",
        "name": recipe_name,
        "source_run_id": run_id,
        "created_at": utc_now_text(),
        "task": manifest.get("task", {}),
        "entrypoint": "final.py",
        "artifact_policy": "script-only-no-logs-screenshots-results",
        "verification": manifest.get("verification", {}),
    }
    (recipe_dir / "recipe.json").write_text(json.dumps(recipe, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return PackResult("packed", run_id, recipe_name, recipe_dir=recipe_dir)


def list_recipes(config: RelayConfig) -> list[dict[str, Any]]:
    if not config.recipes_dir.exists():
        return []
    recipes: list[dict[str, Any]] = []
    for recipe_path in sorted(config.recipes_dir.glob("*/recipe.json")):
        try:
            payload = json.loads(recipe_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        recipes.append({
            "name": payload.get("name", recipe_path.parent.name),
            "recipe_dir": str(recipe_path.parent),
            "source_run_id": payload.get("source_run_id"),
            "created_at": payload.get("created_at"),
        })
    return recipes


def load_recipe(config: RelayConfig, name: str) -> dict[str, Any]:
    recipe_name = slugify_name(name)
    recipe_dir = config.recipes_dir / recipe_name
    payload = json.loads((recipe_dir / "recipe.json").read_text(encoding="utf-8"))
    payload["recipe_dir"] = str(recipe_dir)
    return payload


def parse_params(items: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"param must be key=value: {item}")
        key, value = item.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"param key is required: {item}")
        params[key] = value
    return params


def prepare_recipe_run(config: RelayConfig, name: str, *, params: dict[str, str] | None = None) -> tuple[str, Path]:
    recipe = load_recipe(config, name)
    recipe_dir = Path(recipe["recipe_dir"])
    title = (recipe.get("task") or {}).get("title") or f"recipe {recipe['name']}"
    run_id = f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%S%fZ')}-recipe-{recipe['name']}"
    run = init_run(config, title, run_id=run_id, template="placeholder")
    shutil.copy2(recipe_dir / "final.py", run.run_dir / "scripts" / "final.py")
    (run.run_dir / "params.json").write_text(json.dumps(params or {}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return run.run_id, run.run_dir
