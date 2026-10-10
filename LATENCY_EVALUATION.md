# Latency Evaluation

This document provides the detailed experimental setup, measurement procedure, and results for evaluating the processing latency of Evilog compared to AIOpsShield.

## Experimental Setup

Both AIOpsShield and Evilog were evaluated using identical masking templates and masking-label assignment logic.

- **Baseline:** AIOpsShield
- **Proposed Defense:** Evilog
- **Security Detector:** GPT-4o-mini
- **Input Data:** Seven telemetry field values
- **Repetitions:** 10 runs per input value

## Measurement Procedure

1. Generate the masking templates once and share them between both defenses.
2. Prepare seven telemetry field values.
3. Measure the processing latency of AIOpsShield.
4. Measure the processing latency of Evilog, including its additional LLM-based detection call.
5. Calculate the mean latency and standard deviation.

## Experimental Results

| Defense | Mean Latency | Standard Deviation |
|---|---|---|
| AIOpsShield | 2.06 µs | 4.63 µs |
| Evilog | 0.791 s | 0.112 s |

Evilog introduces additional latency due to the LLM-based security detection call performed before masking. This represents a trade-off between processing efficiency and preserving attack evidence for diagnosis.

## Reproduction Instructions

Detailed benchmark commands and environment configuration will be added alongside the experimental scripts.
