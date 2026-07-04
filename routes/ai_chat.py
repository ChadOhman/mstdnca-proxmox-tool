import json
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Blueprint, Response, flash, jsonify, redirect, request, stream_with_context, url_for
from flask_login import current_user, login_required

from auth.audit import log_action
from models import AIChatMessage, AIChatSession, AIUsageLog, Setting, db

logger = logging.getLogger(__name__)

bp = Blueprint("ai_chat", __name__)


def _strict_same_origin_check():
    """Strict CSRF defense for state-changing /ai/* requests.

    H2: the app-wide _csrf_origin_check in app.py ALLOWS unsafe requests that
    carry no Origin/Referer header (to accommodate non-browser API clients).
    The AI endpoints are only ever driven by the browser fetch() in
    static/ai-chat.js, which always sends an Origin/Referer on same-origin POSTs.
    So for /ai/* we REQUIRE the header to be present AND same-origin, closing the
    header-absent bypass. Returns a 403 JSON response on failure, else None.
    """
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source:
        logger.warning("AI CSRF: missing Origin/Referer on %s %s", request.method, request.path)
        return jsonify({"error": "Missing Origin/Referer header"}), 403
    src = urlparse(source)
    req = urlparse(request.host_url)
    if (src.scheme, src.netloc) != (req.scheme, req.netloc):
        logger.warning("AI CSRF origin mismatch: source=%s expected=%s path=%s",
                       source, request.host_url, request.path)
        return jsonify({"error": "Cross-site request blocked"}), 403
    return None


@bp.before_request
@login_required
def _require_ai_access():
    csrf_resp = _strict_same_origin_check()
    if csrf_resp is not None:
        return csrf_resp
    if not current_user.can_use_ai:
        if request.is_json or request.headers.get("Accept") == "text/event-stream":
            return jsonify({"error": "AI assistant access denied"}), 403
        flash("You don't have permission to use the AI assistant.", "error")
        return redirect(url_for("dashboard.index"))
    if Setting.get("ai_enabled", "false") != "true":
        if request.is_json or request.headers.get("Accept") == "text/event-stream":
            return jsonify({"error": "AI assistant is not enabled"}), 503
        flash("AI assistant is not enabled.", "error")
        return redirect(url_for("dashboard.index"))


def _check_rate_limit(user_id):
    """Return True if the user has exceeded their daily request limit."""
    limit = int(Setting.get("ai_daily_request_limit", "100"))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    count = AIUsageLog.query.filter(
        AIUsageLog.user_id == user_id,
        AIUsageLog.created_at >= cutoff,
    ).count()
    return count >= limit


@bp.route("/chat", methods=["POST"])
def chat():
    """Main streaming chat endpoint. Accepts JSON, returns SSE stream."""
    data = request.get_json()
    if not data or not data.get("message", "").strip():
        return jsonify({"error": "Message is required"}), 400

    if _check_rate_limit(current_user.id):
        return jsonify({"error": "Daily request limit exceeded"}), 429

    message = data["message"].strip()
    session_id = data.get("session_id")
    page_context = data.get("page_context", {})

    # Load or create session
    session = None
    if session_id:
        session = AIChatSession.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not session:
        session = AIChatSession(user_id=current_user.id, title=message[:128])
        db.session.add(session)
        db.session.flush()

    # Save user message
    user_msg = AIChatMessage(session_id=session.id, role="user", content=message)
    db.session.add(user_msg)
    db.session.commit()

    # Get Claude client
    from clients.claude_client import get_claude_client
    client = get_claude_client()
    if not client:
        return jsonify({"error": "AI client not configured"}), 503

    # Build messages from session history
    history = AIChatMessage.query.filter_by(session_id=session.id).order_by(
        AIChatMessage.created_at
    ).all()
    messages = []
    for msg in history:
        if msg.role in ("user", "assistant"):
            messages.append({"role": msg.role, "content": msg.content})

    # Build system prompt and tools
    from core.ai_context import build_system_prompt
    from core.ai_tools import execute_tool, get_tools_for_user

    system_prompt = build_system_prompt(current_user, page_context)
    tools = get_tools_for_user(current_user)

    def generate():
        """Stream SSE events from Claude, handling tool_use loops."""
        nonlocal messages
        full_text = ""
        total_usage = {"input_tokens": 0, "output_tokens": 0}
        max_iterations = 5  # Prevent infinite tool loops

        for _iteration in range(max_iterations):
            tool_calls_in_round = []
            # B1: cache each tool's result keyed by its tool_use id so it is
            # executed EXACTLY ONCE per request. The same cached result is reused
            # when building the tool_result blocks sent back to Claude — executing
            # a state-changing tool (e.g. control_service) a second time would
            # issue a duplicate action and a duplicate audit entry.
            tool_results_by_id = {}
            round_text = ""

            try:
                for event in client.stream_chat(messages, system_prompt=system_prompt,
                                                tools=tools if tools else None):
                    if event["type"] == "text":
                        round_text += event["content"]
                        yield f"data: {json.dumps(event)}\n\n"

                    elif event["type"] == "tool_use":
                        tool_calls_in_round.append(event)
                        yield f"data: {json.dumps({'type': 'tool_call', 'name': event['name'], 'input': event['input']})}\n\n"

                        # Execute the tool exactly once and cache the result.
                        result = execute_tool(event["name"], event["input"], current_user)
                        tool_results_by_id[event["id"]] = result
                        yield f"data: {json.dumps({'type': 'tool_result', 'name': event['name'], 'result': result})}\n\n"

                    elif event["type"] == "done":
                        total_usage["input_tokens"] += event.get("usage", {}).get("input_tokens", 0)
                        total_usage["output_tokens"] += event.get("usage", {}).get("output_tokens", 0)

                    elif event["type"] == "error":
                        yield f"data: {json.dumps(event)}\n\n"
                        yield f"data: {json.dumps({'type': 'done'})}\n\n"
                        return

            except Exception:
                # M3: log the full traceback server-side; return a generic message.
                logger.exception("Chat stream error")
                generic = "The AI assistant encountered an internal error."
                yield f"data: {json.dumps({'type': 'error', 'message': generic})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                return

            full_text += round_text

            # If there were tool calls, append assistant + tool results and loop
            if tool_calls_in_round:
                # Build the assistant message content blocks
                assistant_content = []
                if round_text:
                    assistant_content.append({"type": "text", "text": round_text})
                for tc in tool_calls_in_round:
                    assistant_content.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc["input"],
                    })
                messages.append({"role": "assistant", "content": assistant_content})

                # Add tool results — reuse the cached result from the single
                # execution above; do NOT execute the tool again.
                tool_results = []
                for tc in tool_calls_in_round:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tc["id"],
                        "content": tool_results_by_id[tc["id"]],
                    })
                messages.append({"role": "user", "content": tool_results})
            else:
                # No tool calls — we're done
                break

        yield f"data: {json.dumps({'type': 'done'})}\n\n"

        # Persist assistant response and usage
        try:
            if full_text:
                assistant_msg = AIChatMessage(
                    session_id=session.id, role="assistant", content=full_text
                )
                db.session.add(assistant_msg)

            usage_log = AIUsageLog(
                user_id=current_user.id,
                session_id=session.id,
                input_tokens=total_usage["input_tokens"],
                output_tokens=total_usage["output_tokens"],
            )
            db.session.add(usage_log)

            session.updated_at = datetime.now(timezone.utc)
            db.session.commit()
        except Exception as e:
            logger.error("Failed to persist chat: %s", e)

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.route("/sessions", methods=["GET"])
def list_sessions():
    """List the current user's chat sessions."""
    sessions = (
        AIChatSession.query.filter_by(user_id=current_user.id)
        .order_by(AIChatSession.updated_at.desc())
        .limit(50)
        .all()
    )
    return jsonify([
        {
            "id": s.id,
            "title": s.title,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        }
        for s in sessions
    ])


@bp.route("/sessions", methods=["POST"])
def create_session():
    """Create a new chat session."""
    data = request.get_json() or {}
    session = AIChatSession(
        user_id=current_user.id,
        title=data.get("title", "New Chat")[:128],
    )
    db.session.add(session)
    db.session.commit()
    return jsonify({"id": session.id, "title": session.title}), 201


@bp.route("/sessions/<int:session_id>", methods=["GET"])
def get_session(session_id):
    """Load messages for a specific session."""
    session = AIChatSession.query.filter_by(
        id=session_id, user_id=current_user.id
    ).first()
    if not session:
        return jsonify({"error": "Session not found"}), 404

    messages = AIChatMessage.query.filter_by(session_id=session.id).order_by(
        AIChatMessage.created_at
    ).all()
    return jsonify({
        "id": session.id,
        "title": session.title,
        "messages": [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "tool_use": m.tool_use,
                "created_at": m.created_at.isoformat() if m.created_at else None,
            }
            for m in messages
        ],
    })


@bp.route("/sessions/<int:session_id>", methods=["DELETE"])
def delete_session(session_id):
    """Delete a chat session."""
    session = AIChatSession.query.filter_by(
        id=session_id, user_id=current_user.id
    ).first()
    if not session:
        return jsonify({"error": "Session not found"}), 404

    log_action("ai_session_delete", "ai_chat", resource_id=session.id,
               resource_name=session.title)
    db.session.delete(session)
    db.session.commit()
    return jsonify({"ok": True})
