# Latency Evaluation

This document describes the measurement methodology and processing overhead of Evilog compared with AIOpsShield, as reported in Section V-C (Latency Measurement) of *Evilog: Evidence-Preserving Log Sanitization for LLM-based AIOps Agents*.

[← Back to the main README](README.md)

## Objective

Measure the latency introduced by Evilog's security detector, which inspects each unverified user-controlled telemetry field before applying the existing AIOpsShield masking operation.

## Experimental Setup

| Item | Configuration |
|---|---|
| Baseline | AIOpsShield |
| Proposed method | Evilog |
| Security detector | GPT-4o-mini |
| Inputs | Seven distinct telemetry field values |
| Repetitions | Each field value processed 10 times under the comparison procedure |
| Metrics | Mean and standard deviation of processing time |

Both defenses use **the same masking templates and masking-label assignment logic**. Masking templates are generated **once** and shared across the comparison. Evilog reuses the original AIOpsShield masking implementation, adding the security detection call before masking. Consequently, the comparison is designed to isolate the overhead of this additional LLM call.

## Measurement Procedure

1. **Prepare a shared masking configuration.** Generate the original AIOpsShield masking templates once. Confirm that the template set and masking-label assignment logic are identical in both conditions.
2. **Prepare the input set.** Select the seven telemetry field values used for the benchmark. Ensure both defenses receive identical values.
3. **Measure AIOpsShield.** For each input, time the masking operation using the pre-generated templates. Repeat the input measurement 10 times and record the observed processing time.
4. **Measure Evilog.** For the same input, time the combined process: invoke the GPT-4o-mini security detector, record attack-type security metadata when applicable, and apply the original masking operation. Repeat 10 times and record the processing time.
5. **Summarize measurements.** Calculate the mean processing time and standard deviation for each defense. Compare the two means to estimate the additional latency associated with LLM-based evidence detection.

**Scope of timing:** The experiment compares the sanitization-stage processing time, including Evilog's external detection call; it does not claim to benchmark full application response times or end-to-end incident diagnosis.

## Results

| Defense | Mean processing time | Standard deviation |
|---|---:|---:|
| AIOpsShield | 2.06 µs | 4.63 µs |
| Evilog | 0.791 s | 0.112 s |

AIOpsShield performs local substitutions using pre-generated regular-expression templates. Evilog incurs additional network and LLM inference latency for each unverified input field. In the reported measurements, this call contributes roughly **0.7–1.2 seconds per field** depending on the individual request.

This overhead is the cost of inspecting input for application-layer attack evidence before masking, so that the sanitized telemetry can retain a concise security memo rather than losing the information needed for diagnosis.

## Reproduction Notes

To independently reproduce these measurements, configure the original AIOpsShield and Evilog implementations, prepare a shared template set, use the same seven telemetry field values, and measure both processing paths with repeated timing runs. Preserve raw timing observations so the reported mean and standard deviation can be checked.

**Information still needed for exact reproduction:** the benchmark script and command, the exact seven input values, the timer and timing boundaries used in the implementation, runtime/package versions, API configuration, and the original timing records. These are not specified in the paper and should be added here once the corresponding artifacts are available. Do not insert an unverified command as though it were an existing script.
