from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

from agentguard.adapters import LangGraphGatewayAdapter
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import SecurityContext
from agentguard.tools import attach_builtin_handlers


ROOT = Path(__file__).resolve().parents[1]


class LangGraphAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT)
        context = SecurityContext(
            user_id="langgraph-test",
            role="analyst",
            scopes={"file:read", "file:write", "db:read", "kb:read", "search:read", "network:api", "threat:intel"},
        )
        self.adapter = LangGraphGatewayAdapter(gateway, context, task_id="langgraph-test")

    def test_adapter_executes_framework_tool_name_through_gateway(self) -> None:
        framework_name = self.adapter.to_framework_tool_name("file.read")
        payload = json.loads(
            self.adapter.execute(
                framework_name,
                {"path": "data/demo_workspace/public/project_brief.txt"},
                step_id="lg-s1",
            )
        )
        self.assertEqual(framework_name, "agentguard__file__read")
        self.assertEqual(payload["decision"]["decision"], "allow")
        self.assertTrue(payload["result"]["ok"])
        self.assertEqual(self.adapter.steps[0].call.tool_name, "file.read")

    @unittest.skipUnless(
        importlib.util.find_spec("langchain_core") and importlib.util.find_spec("pydantic"),
        "langchain-core and pydantic are optional LangGraph adapter dependencies",
    )
    def test_as_tools_exposes_guarded_structured_tool(self) -> None:
        tool = self.adapter.as_tools(["file.read"])[0]
        output = tool.invoke({"path": "data/demo_workspace/public/../secrets.env"})
        payload = json.loads(output)
        self.assertEqual(tool.name, "agentguard__file__read")
        self.assertEqual(payload["tool_name"], "file.read")
        self.assertEqual(payload["decision"]["decision"], "block")

    @unittest.skipUnless(
        importlib.util.find_spec("langgraph") and importlib.util.find_spec("langchain_core"),
        "langgraph is an optional dependency",
    )
    def test_langgraph_state_graph_tool_node(self) -> None:
        from langchain_core.messages import AIMessage
        from langgraph.graph import END, START, MessagesState, StateGraph

        builder = StateGraph(MessagesState)
        builder.add_node("tools", self.adapter.tool_node)
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        graph = builder.compile()

        result = graph.invoke(
            {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": self.adapter.to_framework_tool_name("kb.search"),
                                "args": {"query": "gateway report recommendations", "top_k": 2},
                                "id": "call-test-kb",
                            }
                        ],
                    )
                ]
            }
        )
        payload = json.loads(result["messages"][-1].content)
        self.assertEqual(payload["tool_name"], "kb.search")
        self.assertEqual(payload["decision"]["decision"], "allow")
        self.assertEqual(self.adapter.steps[-1].step_id, "call-test-kb")


if __name__ == "__main__":
    unittest.main()
