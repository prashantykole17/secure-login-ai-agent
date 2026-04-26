from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langchain_openai import ChatOpenAI

from backend.config import Settings
from backend.repository import BankingRepository
from backend.tools import build_tools


class BankingSupportAgent:
    def __init__(self, settings: Settings, repository: BankingRepository) -> None:
        self.settings = settings
        self.repository = repository

    def _model(self) -> ChatOpenAI:
        return ChatOpenAI(
            model=self.settings.openai_model,
            api_key=self.settings.openai_api_key,
            temperature=0,
            use_responses_api=True,
        )

    def _build_graph(self, session_id: int):
        tools = build_tools(self.repository, session_id)
        tool_node = ToolNode(tools)
        llm = self._model().bind_tools(tools)
        system_prompt = self.settings.system_prompt

        def assistant(state: MessagesState) -> dict[str, list[AIMessage]]:
            response = llm.invoke([SystemMessage(content=system_prompt), *state["messages"]])
            return {"messages": [response]}

        graph = StateGraph(MessagesState)
        graph.add_node("assistant", assistant)
        graph.add_node("tools", tool_node)
        graph.add_edge(START, "assistant")
        graph.add_conditional_edges("assistant", tools_condition, {"tools": "tools", END: END})
        graph.add_edge("tools", "assistant")
        return graph.compile()

    def generate_reply(self, session_id: int, user_message: str) -> str:
        messages = self.repository.get_langchain_messages(session_id)
        graph = self._build_graph(session_id)
        result: dict[str, Any] = graph.invoke({"messages": [*messages, HumanMessage(content=user_message)]})
        final_messages = result["messages"]
        final_ai = next(
            (
                message
                for message in reversed(final_messages)
                if isinstance(message, AIMessage) and not getattr(message, "tool_calls", None)
            ),
            None,
        )
        if not final_ai:
            return "I could not produce a final answer. Please try again."
        text_attr = getattr(final_ai, "text", "")
        if callable(text_attr):
            text_value = text_attr()
        else:
            text_value = text_attr

        if isinstance(text_value, str) and text_value.strip():
            return text_value

        if isinstance(final_ai.content, str):
            return final_ai.content

        if isinstance(final_ai.content, list):
            parts: list[str] = []
            for item in final_ai.content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
                elif isinstance(item, dict) and item.get("type") == "output_text":
                    parts.append(str(item.get("text", "")))
                else:
                    parts.append(str(item))
            combined = "\n".join(part for part in parts if part.strip())
            if combined:
                return combined

        return str(final_ai.content)
