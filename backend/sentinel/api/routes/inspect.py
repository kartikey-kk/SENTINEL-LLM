"""Inspection and chat endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from sentinel.api.deps import AdminDep, Caller, ClientDep, get_ctx
from sentinel.api.middleware import request_id_of
from sentinel.schemas import api

router = APIRouter(prefix="/api/v1", tags=["inspection"])


@router.post("/inspect/input", response_model=api.InspectInputResponse,
             summary="Inspect a prompt: detectors, risk, policy decision, sanitized text")
async def inspect_input(body: api.InspectInputRequest, request: Request, caller: Caller = ClientDep) -> api.InspectInputResponse:
    ctx = get_ctx(request)
    return await ctx.pipeline.handle_inspect_input(body, request_id=request_id_of(request), client_id=caller.client_id,
                                                   is_admin=caller.is_admin)


@router.post("/inspect/output", response_model=api.InspectOutputResponse,
             summary="Validate model output: leakage, unsafe content, structure, evidence overlap")
async def inspect_output(body: api.InspectOutputRequest, request: Request, caller: Caller = ClientDep) -> api.InspectOutputResponse:
    ctx = get_ctx(request)
    return await ctx.pipeline.handle_inspect_output(body, request_id=request_id_of(request), client_id=caller.client_id)


@router.post("/inspect/context", response_model=api.InspectContextResponse,
             summary="Scan untrusted retrieved content (RAG chunks, web pages, tool outputs)")
async def inspect_context(body: api.InspectContextRequest, request: Request, caller: Caller = ClientDep) -> api.InspectContextResponse:
    ctx = get_ctx(request)
    return await ctx.pipeline.handle_inspect_context(body, request_id=request_id_of(request), client_id=caller.client_id)


@router.post("/inspect/tool", response_model=api.InspectToolResponse,
             summary="Authorize (and optionally run) a simulated tool call")
async def inspect_tool(body: api.InspectToolRequest, request: Request, caller: Caller = ClientDep) -> api.InspectToolResponse:
    ctx = get_ctx(request)
    return await ctx.pipeline.handle_inspect_tool(body, request_id=request_id_of(request), client_id=caller.client_id)


@router.post("/inspect/tool/approve", summary="Issue an approval token for one exact tool call (admin)")
async def approve_tool(body: api.ToolApprovalRequest, request: Request, caller: Caller = AdminDep) -> dict:
    ctx = get_ctx(request)
    policy = ctx.policy_store.current
    if body.tool_name not in policy.tools.tools:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Unknown tool")
    token = ctx.tool_guard.approval_token(body.session_id, body.tool_name, body.arguments)
    await ctx.audit.log("admin", "tool.approve", target=body.tool_name, request_id=request_id_of(request),
                        details={"session_hash": ctx.audit.fingerprint(body.session_id), "argument_names": sorted(body.arguments)})
    return {"approval_token": token, "tool_name": body.tool_name, "bound_to": "session_id + tool_name + exact arguments"}


@router.post("/chat", response_model=api.ChatResponse, tags=["chat"],
             summary="Secure chat proxy: inspect -> enforce -> LLM -> validate output")
async def chat(body: api.ChatRequest, request: Request, caller: Caller = ClientDep) -> api.ChatResponse:
    ctx = get_ctx(request)
    return await ctx.pipeline.handle_chat(body, request_id=request_id_of(request), client_id=caller.client_id)
