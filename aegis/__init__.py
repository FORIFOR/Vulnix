"""Aegis P0: independent safety-control plane.

LLM / agent output is treated as an untrusted *proposal*. Only the Gateway,
holding server-side secrets the model never sees, decides whether anything runs.
"""
