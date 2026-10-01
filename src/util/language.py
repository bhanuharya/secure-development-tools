from __future__ import annotations

from pathlib import Path

EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".go": "go",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".tf": "hcl",
    ".json": "json",
    ".html": "html",
    ".xml": "xml",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "cpp",
    ".sh": "bash",
    ".swift": "swift",
    ".vue": "vue",
}

OPENGREP_LANGS = {
    "python", "java", "javascript", "typescript", "kotlin", "go",
    "yaml", "hcl", "json",
}


def detect_languages(root: str | Path, limit: int = 5000) -> list[str]:
    """Sniff languages from file extensions. Returns a sorted list, 'python' first."""
    found: set[str] = set()
    scanned = 0
    for path in Path(root).rglob("*"):
        if not path.is_file():
            continue
        scanned += 1
        if scanned > limit:
            break
        if path.name in (".git",):
            continue
        if any(part.startswith(".") for part in path.parts):
            continue
        ext = path.suffix.lower()
        lang = EXTENSION_MAP.get(ext)
        if lang:
            found.add(lang)
    priority = {"python": 0, "java": 1, "javascript": 2, "typescript": 3, "kotlin": 4, "go": 5}
    return sorted(found, key=lambda l: priority.get(l, 99))


def opengrep_languages(detected: list[str]) -> list[str]:
    return [l for l in detected if l in OPENGREP_LANGS]
