from __future__ import annotations

import ast
from typing import Any


_MAX_AST_NODES = 128
_MAX_CONTAINER_ITEMS = 256
_MAX_STRING_CHARS = 8_192
_MAX_INTEGER_ABS = 10**12
_MAX_EXPONENT = 100


class ExpressionSandboxError(ValueError):
    pass


def evaluate_bounded_expression(code: str) -> Any:
    tree = validate_bounded_expression(code)
    allowed_functions = {
        "abs": abs,
        "min": min,
        "max": max,
        "sum": sum,
        "len": len,
        "round": round,
    }
    return eval(
        compile(tree, "<agentguard-expression-sandbox>", "eval"),
        {"__builtins__": {}},
        allowed_functions,
    )


def validate_bounded_expression(code: str) -> ast.Expression:
    if not isinstance(code, str) or not code.strip():
        raise ExpressionSandboxError("Expression must be a non-empty string")
    if len(code) > 4_096:
        raise ExpressionSandboxError("Expression exceeded the source limit")
    try:
        tree = ast.parse(code, mode="eval")
    except SyntaxError:
        raise ExpressionSandboxError("Expression syntax is invalid") from None
    nodes = list(ast.walk(tree))
    if len(nodes) > _MAX_AST_NODES:
        raise ExpressionSandboxError("Expression exceeded the AST node limit")
    allowed_nodes = (
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.BoolOp,
        ast.Compare,
        ast.Call,
        ast.Name,
        ast.Load,
        ast.Constant,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.Set,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Pow,
        ast.FloorDiv,
        ast.USub,
        ast.UAdd,
        ast.And,
        ast.Or,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
    )
    allowed_function_names = {"abs", "min", "max", "sum", "len", "round"}
    for node in nodes:
        if not isinstance(node, allowed_nodes):
            raise ExpressionSandboxError(
                f"Unsupported expression syntax: {type(node).__name__}"
            )
        if isinstance(node, ast.Name) and node.id not in allowed_function_names:
            raise ExpressionSandboxError("Expression name is not allowlisted")
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in allowed_function_names:
                raise ExpressionSandboxError("Expression function is not allowlisted")
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and len(node.elts) > _MAX_CONTAINER_ITEMS:
            raise ExpressionSandboxError("Expression container exceeded the item limit")
        if isinstance(node, ast.Dict) and len(node.keys) > _MAX_CONTAINER_ITEMS:
            raise ExpressionSandboxError("Expression dictionary exceeded the item limit")
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str) and len(node.value) > _MAX_STRING_CHARS:
                raise ExpressionSandboxError("Expression string exceeded the size limit")
            if type(node.value) is int and abs(node.value) > _MAX_INTEGER_ABS:
                raise ExpressionSandboxError("Expression integer exceeded the magnitude limit")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow):
            if not isinstance(node.right, ast.Constant) or type(node.right.value) is not int:
                raise ExpressionSandboxError("Expression exponent must be a bounded integer literal")
            if not 0 <= node.right.value <= _MAX_EXPONENT:
                raise ExpressionSandboxError("Expression exponent exceeded the limit")
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
            _validate_sequence_repetition(node)
    return tree


def _validate_sequence_repetition(node: ast.BinOp) -> None:
    pairs = ((node.left, node.right), (node.right, node.left))
    for sequence, multiplier in pairs:
        if isinstance(sequence, (ast.List, ast.Tuple, ast.Set)) or (
            isinstance(sequence, ast.Constant) and isinstance(sequence.value, (str, bytes))
        ):
            if not isinstance(multiplier, ast.Constant) or type(multiplier.value) is not int:
                raise ExpressionSandboxError("Sequence repetition requires a bounded integer literal")
            if not 0 <= multiplier.value <= _MAX_CONTAINER_ITEMS:
                raise ExpressionSandboxError("Sequence repetition exceeded the item limit")
