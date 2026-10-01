"""``python -m liebert_re`` runs the same entrypoint as the ``liebert-re`` script."""
from liebert_re.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
