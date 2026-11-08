# Cost and latency notes

The system is designed to spend compute only where it adds value.

## Model choice by role

- **Deterministic, no tokens:** parsing, chunking, BM25, RRF fusion and metadata filtering cost no
  model calls. The cross-encoder re-ranker runs on CPU.
- **Small LLM:** planner and judge run on a small local model (via Ollama). They produce short JSON.
- **Larger generation only at the end:** only the final report benefits from a more capable model;
  everything upstream stays cheap.

## Reducing work

- **Adaptive retrieval:** if the planner decides the alert needs no external knowledge, the RAG loop
  is skipped entirely.
- **Bounded iterations:** the planner/investigator loop is capped (`orchestration.max_iterations`)
  to avoid unbounded retries.
- **Re-ranking depth:** retrieve a wider set (`top_retrieve`) but only re-rank down to `top_final`,
  keeping the LLM context small.

## Latency, by stage

Measure with the CLI (step 5 of the local testing guide) or the API. The dominant costs are:

1. One-time model load at startup (embeddings + cross-encoder), amortised across requests.
2. Embedding + re-ranking per query (CPU-bound, sub-second for this corpus).
3. LLM calls (planner, report, judge) — the largest variable cost; scales with the local model size.

## RAG vs. fine-tuning

The knowledge corpus changes over time (new techniques, playbooks, incidents) and the system must
cite its sources. Both argue for retrieval at inference time rather than fine-tuning, which would be
expensive to refresh and would not provide citations.
