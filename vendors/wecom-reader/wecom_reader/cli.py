"""CLI entry point for wecom-reader.

All commands output JSON by default. Use --table for human-readable tables.
"""

import json
import sys

import click

from .reader import WeComReader


def _json_output(data, pretty=True):
    """Print JSON to stdout."""
    kwargs = {"ensure_ascii": False}
    if pretty:
        kwargs["indent"] = 2
    click.echo(json.dumps(data, **kwargs))


@click.group()
@click.option("--db-dir", envvar="WXWORK_DB_DIR", help="WeCom data directory")
@click.option("--decrypted-dir", default="wxwork_decrypted", help="Decrypted DB output directory")
@click.pass_context
def main(ctx, db_dir, decrypted_dir):
    """wecom-reader — Read WeCom (企业微信) local chat history.

    Agent-reusable tool for querying WeCom chat data.
    All commands output JSON by default.
    """
    ctx.ensure_object(dict)
    ctx.obj["reader"] = WeComReader(db_dir=db_dir, decrypted_dir=decrypted_dir)


@main.command()
@click.option("--timeout", default=120, help="Memory scan timeout (seconds)")
@click.option("--verbose", "-v", is_flag=True, help="Print progress")
@click.pass_context
def init(ctx, timeout, verbose):
    """Extract keys and decrypt all WeCom databases.

    Requires: WXWork.exe running, admin privileges.
    """
    reader: WeComReader = ctx.obj["reader"]
    try:
        result = reader.init(timeout=timeout, verbose=verbose)
        _json_output(result)
    except Exception as e:
        _json_output({"success": False, "error": str(e)})
        sys.exit(1)


@main.command()
@click.pass_context
def status(ctx):
    """Check status of decrypted WeCom data."""
    reader: WeComReader = ctx.obj["reader"]
    _json_output(reader.status())


@main.command()
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--offset", default=0, help="Pagination offset")
@click.option("--keyword", "-k", help="Filter by keyword")
@click.option("--type", "session_type", help="Filter by type (R/S/M/O/Y)")
@click.pass_context
def sessions(ctx, limit, offset, keyword, session_type):
    """List WeCom sessions/conversations."""
    reader: WeComReader = ctx.obj["reader"]
    result = reader.list_sessions(
        limit=limit, offset=offset, keyword=keyword, session_type=session_type
    )
    _json_output({"count": len(result), "sessions": result})


@main.command()
@click.argument("session_id")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--offset", default=0, help="Pagination offset")
@click.option("--since", type=int, help="Unix timestamp filter (>=)")
@click.option("--until", type=int, help="Unix timestamp filter (<)")
@click.pass_context
def messages(ctx, session_id, limit, offset, since, until):
    """Get messages for a conversation.

    SESSION_ID: Conversation ID (e.g. R:12345, S:1_2, O:67890)
    """
    reader: WeComReader = ctx.obj["reader"]
    result = reader.get_messages(
        session_id, limit=limit, offset=offset, since=since, until=until
    )
    _json_output({"count": len(result), "messages": result})


@main.command()
@click.argument("keyword")
@click.option("--limit", "-n", default=50, help="Max results")
@click.option("--session", "session_id", help="Filter by session ID")
@click.pass_context
def search(ctx, keyword, limit, session_id):
    """Search messages by keyword."""
    reader: WeComReader = ctx.obj["reader"]
    result = reader.search_messages(keyword, conversation_id=session_id, limit=limit)
    _json_output({"count": len(result), "results": result})


@main.command()
@click.option("--keyword", "-k", help="Filter by name/account")
@click.option("--limit", "-n", default=100, help="Max results")
@click.option("--offset", default=0, help="Pagination offset")
@click.pass_context
def contacts(ctx, keyword, limit, offset):
    """List WeCom contacts."""
    reader: WeComReader = ctx.obj["reader"]
    result = reader.contacts(keyword=keyword, limit=limit, offset=offset)
    _json_output({"count": len(result), "contacts": result})


@main.command()
@click.argument("session_id")
@click.pass_context
def group_members(ctx, session_id):
    """Get group members for a conversation."""
    reader: WeComReader = ctx.obj["reader"]
    result = reader.group_members(session_id)
    _json_output({"count": len(result), "members": result})


@main.command()
@click.argument("session_id")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
@click.option("--output", "-o", help="Output file path")
@click.pass_context
def export(ctx, session_id, fmt, output):
    """Export a conversation to JSON or CSV."""
    reader: WeComReader = ctx.obj["reader"]
    messages = reader.get_messages(session_id, limit=10000)

    if fmt == "json":
        data = json.dumps(messages, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        import csv
        import io
        buf = io.StringIO()
        if messages:
            writer = csv.DictWriter(buf, fieldnames=messages[0].keys())
            writer.writeheader()
            writer.writerows(messages)
        data = buf.getvalue()

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(data)
        _json_output({"success": True, "output": output, "count": len(messages)})
    else:
        click.echo(data)


if __name__ == "__main__":
    main()
