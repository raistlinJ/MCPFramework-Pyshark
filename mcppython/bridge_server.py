"""HTTP bridge that wraps mcp-client-for-ollama's core client for automation.

This exposes a minimal FastAPI application with two endpoints:
- GET /health: returns status and enabled tools
- POST /api/chat: accepts an OpenAI-style chat payload and returns a reply

The server loads MCP configuration from the same JSON file that mcp-client-for-ollama
expects so it can attach to this project's MCP server (and any others you list).
"""
from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from mcp_client_for_ollama.client import MCPClient

from ollama import ResponseError

logger = logging.getLogger(__name__)


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: Optional[str] = None
    stream: Optional[bool] = None
    messages: List[Message]


class ChatResponse(BaseModel):
    model: str
    role: str = "assistant"
    content: str


class BridgeState:
    """Container holding the MCP client and a lock for serialized access."""

    def __init__(self) -> None:
        self.client: Optional[MCPClient] = None
        self.lock = asyncio.Lock()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run an HTTP bridge over mcp-client-for-ollama")
    parser.add_argument("--config", type=Path, required=True, help="Path to mcp-client-for-ollama JSON config")
    parser.add_argument("--model", default="gpt-oss:20b", help="Default Ollama model to use")
    parser.add_argument("--ollama-host", default="http://localhost:11434", help="Base URL for the Ollama API")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind the HTTP bridge")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind the HTTP bridge")
    return parser.parse_args()


async def _perform_model_chat(
    client: MCPClient,
    messages: List[Dict[str, Any]],
    available_tools: List[Dict[str, Any]],
    include_tools: bool,
) -> tuple[str, List[Any]]:
    """Run a streaming chat with optional tool availability and return text plus tool calls."""

    chat_params: Dict[str, Any] = {
        "model": client.model_manager.get_current_model(),
        "messages": messages,
        "stream": True,
        "options": client.model_config_manager.get_ollama_options(),
    }
    if include_tools and available_tools:
        chat_params["tools"] = available_tools

    if await client.supports_thinking_mode():
        chat_params["think"] = client.thinking_mode

    stream = await client.ollama.chat(**chat_params)
    response_text, tool_calls, metrics = await client.streaming_manager.process_streaming_response(
        stream,
        print_response=False,
        thinking_mode=client.thinking_mode,
        show_thinking=client.show_thinking,
        show_metrics=client.show_metrics,
    )

    if metrics and metrics.get("eval_count"):
        client.actual_token_count += metrics["eval_count"]

    return response_text, list(tool_calls)


async def run_query_with_fallback(client: MCPClient, query: str, system_prompt: str) -> str:
    """Execute the MCP client query but ensure a non-empty response when tools are used."""

    if client.retain_context and client.chat_history:
        messages: List[Dict[str, Any]] = []
        for entry in client.chat_history:
            messages.append({"role": "user", "content": entry["query"]})
            messages.append({"role": "assistant", "content": entry["response"]})
        messages.append({"role": "user", "content": query})
    else:
        messages = [{"role": "user", "content": query}]

    if system_prompt:
        messages.insert(0, {"role": "system", "content": system_prompt})

    tool_objects = client.tool_manager.get_enabled_tool_objects()
    available_tools = [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.inputSchema,
            },
        }
        for tool in tool_objects
    ]

    collected_outputs: List[tuple[str, str]] = []
    response_text, tool_calls = await _perform_model_chat(
        client,
        messages,
        available_tools,
        include_tools=bool(tool_objects),
    )

    iterations = 0
    while tool_calls and iterations < 3:
        iterations += 1
        for tool in tool_calls:
            tool_name = tool.function.name
            tool_args = tool.function.arguments
            server_name, actual_tool_name = tool_name.split(".", 1) if "." in tool_name else (None, tool_name)

            if not server_name or server_name not in client.sessions:
                warning_msg = f"Skipping tool call {tool_name}: unknown MCP server"
                logger.warning(warning_msg)
                collected_outputs.append((tool_name, warning_msg))
                continue

            client.tool_display_manager.display_tool_execution(tool_name, tool_args, show=client.show_tool_execution)
            should_execute = await client.hil_manager.request_tool_confirmation(tool_name, tool_args)
            if not should_execute:
                tool_response = "Tool call was skipped by automation"
            else:
                with client.console.status(f"[cyan]⏳ Running {tool_name}...[/cyan]"):
                    result = await client.sessions[server_name]["session"].call_tool(actual_tool_name, tool_args)
                tool_response = f"{result.content[0].text}"

            collected_outputs.append((tool_name, tool_response))
            client.tool_display_manager.display_tool_response(tool_name, tool_args, tool_response, show=client.show_tool_execution)
            messages.append({"role": "tool", "content": tool_response, "name": tool_name})

        response_text, tool_calls = await _perform_model_chat(
            client,
            messages,
            available_tools,
            include_tools=False,
        )

    if not response_text and collected_outputs:
        summary_prompt_lines = [
            "You executed several MCP tools. Using their outputs, provide a concise, well-structured summary of key findings and recommended follow-ups.",
            "Tool transcripts:",
        ]
        for name, output in collected_outputs:
            summary_prompt_lines.append(f"Tool {name} output:\n{output.strip()}\n")
        summary_prompt = "\n\n".join(summary_prompt_lines)

        fallback_messages = []
        if system_prompt:
            fallback_messages.append({"role": "system", "content": system_prompt})
        fallback_messages.append({"role": "user", "content": summary_prompt})

        response_text, _ = await _perform_model_chat(
            client,
            fallback_messages,
            available_tools,
            include_tools=False,
        )

    if not response_text:
        if collected_outputs:
            response_text = "\n\n".join(
                f"Tool {name} produced the following output:\n{output.strip()}" for name, output in collected_outputs
            )
        else:
            response_text = ""

    client.chat_history.append({"query": query, "response": response_text})
    return response_text


def build_app(config: Path, model: str, ollama_host: str) -> FastAPI:
    state = BridgeState()
    app = FastAPI(title="mcp-client-for-ollama bridge", version="0.1.0")

    @app.on_event("startup")
    async def startup() -> None:
        nonlocal state
        logger.info("Starting bridge with model %s using config %s", model, config)
        client = MCPClient(model=model, host=ollama_host)
        await client.connect_to_servers(None, None, str(config), False)
        client.auto_load_default_config()
        client.model_manager.set_model(model)
        client.tool_manager.enable_all_tools()
        class _NoopHil:
            def is_enabled(self) -> bool:
                return False

            def toggle(self) -> None:
                pass

            def set_enabled(self, enabled: bool) -> None:
                pass

            async def request_tool_confirmation(self, *args: object, **kwargs: object) -> bool:
                return True

        client.hil_manager = _NoopHil()  # type: ignore[assignment]
        client.show_tool_execution = False
        client.thinking_mode = False
        client.show_thinking = False
        client.retain_context = False
        state.client = client
        logger.info("Bridge connected to %d tools", len(client.tool_manager.get_enabled_tools()))

    @app.on_event("shutdown")
    async def shutdown() -> None:
        nonlocal state
        client = state.client
        if client is not None:
            logger.info("Shutting down bridge")
            await client.cleanup()
            state.client = None

    @app.get("/health")
    async def health() -> Dict[str, object]:
        client = state.client
        if client is None:
            raise HTTPException(status_code=503, detail="Bridge is not ready")
        enabled = client.tool_manager.get_enabled_tools()
        return {
            "status": "ok",
            "model": client.model_manager.get_current_model(),
            "enabled_tools": sum(enabled.values()) if enabled else 0,
        }

    @app.post("/api/chat", response_model=ChatResponse)
    async def chat(req: ChatRequest) -> ChatResponse:
        client = state.client
        if client is None:
            raise HTTPException(status_code=503, detail="Bridge is not ready")
        last_user = next((m.content for m in reversed(req.messages) if m.role == "user"), None)
        if not last_user:
            raise HTTPException(status_code=400, detail="Request must include at least one user message")
        system_prompt = next((m.content for m in req.messages if m.role == "system"), "")

        requested_model = req.model or client.model_manager.get_current_model()
        if requested_model != client.model_manager.get_current_model():
            client.model_manager.set_model(requested_model)

        async with state.lock:
            previous_prompt = client.model_config_manager.get_system_prompt()
            if system_prompt:
                client.model_config_manager.system_prompt = system_prompt
            else:
                client.model_config_manager.system_prompt = ""
            client.clear_context()
            try:
                response_text = await run_query_with_fallback(client, last_user, system_prompt)
                logger.info("Model response text repr=%r", response_text)
            except ResponseError as exc:
                logger.exception("Ollama response error")
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            finally:
                client.model_config_manager.system_prompt = previous_prompt
        return ChatResponse(model=client.model_manager.get_current_model(), content=response_text)

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args()
    if not args.config.exists():
        raise SystemExit(f"Config file not found: {args.config}")

    app = build_app(args.config, args.model, args.ollama_host)

    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
