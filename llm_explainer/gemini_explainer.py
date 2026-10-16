"""
llm_explainer/gemini_explainer.py - Alias forwarding to analyzers/llm_explainer.py
"""

from analyzers.llm_explainer import GeminiRiskExplainer, LLMExplainer

__all__ = ["GeminiRiskExplainer", "LLMExplainer"]
