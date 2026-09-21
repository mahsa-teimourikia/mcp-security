from pathlib import Path
import subprocess


ROOT = Path(__file__).parents[1]
TRACKS = {"beginner": 5, "intermediate": 8, "advanced": 16}


def test_canonical_tracks_and_topic_count():
    curriculum = ROOT / "curriculum"
    assert not (curriculum / "enterprise").exists()
    for track, expected in TRACKS.items():
        topics = sorted(path for path in (curriculum / track).iterdir() if path.is_dir())
        assert len(topics) == expected, (track, len(topics))


def test_each_topic_is_a_complete_vertical_slice():
    for track in TRACKS:
        for topic in sorted((ROOT / "curriculum" / track).iterdir()):
            if not topic.is_dir():
                continue
            assert (topic / "README.md").is_file(), topic
            assert (topic / "lab.py").is_file(), topic
            notebooks = list(topic.glob("*.ipynb"))
            assert len(notebooks) == 1, (topic, notebooks)


def test_no_generated_python_caches_are_committed():
    tracked = subprocess.run(
        ["git", "ls-files", "*__pycache__*", "*.pyc"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert not tracked
