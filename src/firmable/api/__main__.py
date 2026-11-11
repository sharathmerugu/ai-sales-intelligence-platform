"""`python -m firmable.api [--db PATH] [--host H] [--port P]` serves the API with uvicorn."""

from __future__ import annotations

import argparse
import os

import uvicorn

from firmable.api.app import ENV_DB, create_app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m firmable.api", description=__doc__)
    parser.add_argument("--db", default=os.environ.get(ENV_DB), help=f"serving DuckDB file (default ${ENV_DB})")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args(argv)
    if not args.db:
        parser.error(f"pass --db or set {ENV_DB}")
    # Requests are logged as JSON lines by the app middleware; uvicorn access logs would duplicate them.
    uvicorn.run(create_app(args.db), host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
