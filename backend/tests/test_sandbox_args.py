from app.sandbox import build_docker_args
from pathlib import Path


def test_docker_argv_is_locked_down(tmp_path: Path):
    work = tmp_path / "work"
    out = tmp_path / "out"
    argv = build_docker_args(work, out, "medguard-test")
    assert "--privileged" not in argv
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--user") + 1] == "65532:65532"
    assert "--read-only" in argv
    assert "--cap-drop" in argv
    assert "ALL" in argv
    joined = " ".join(argv)
    assert "META_API_KEY" not in joined
    assert "MONGODB_URI" not in joined
    assert "/work:ro" in joined
    assert "/out:rw" in joined
