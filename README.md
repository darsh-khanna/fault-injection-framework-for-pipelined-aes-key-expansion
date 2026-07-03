# Design, Verification, and Fault Analysis of a Pipelined AES Key Expansion Engine

## Overview

This project presents the design, verification, and security evaluation of a parameterized pipelined AES key expansion engine supporting **AES-128**, **AES-192**, and **AES-256**. Alongside functional verification, a comprehensive fault injection framework is implemented to evaluate the effects of transient bit-flip and targeted faults on key schedule correctness, diffusion, and fault propagation.

The implementation is written in **SystemVerilog** and verified using **Xilinx Vivado**, with correctness validated against official **NIST test vectors**.

---

## Features

- Parameterized AES-128, AES-192, and AES-256 key expansion
- High-throughput pipelined architecture
- Non-pipelined reference implementation
- Automated functional verification
- NIST-compliant test vector validation
- Pipeline latency characterization
- Throughput benchmarking
- Fault injection framework
- Differential fault analysis
- Cross-architecture comparison

---

## Project Architecture

The repository contains two independent implementations of the AES key expansion algorithm.

### Pipelined Key Expansion

Designed for high-performance applications where round keys are generated continuously through pipeline stages, improving throughput while maintaining correctness.

### Non-Pipelined Key Expansion

A sequential implementation used as a functional reference for verification and performance comparison.

---

## Verification Methodology

The verification environment performs comprehensive validation of both implementations through automated testbenches.

Verification includes:

- Functional correctness verification
- NIST test vector validation
- Cross-architecture output comparison
- Pipeline timing verification
- Latency measurement
- Throughput benchmarking

The generated round keys are automatically compared against expected values to ensure correctness across all supported AES key sizes.

---

## Fault Injection Framework

A dedicated fault injection framework evaluates the robustness of the AES key expansion process against transient faults.

Supported fault models include:

- Single-bit fault injection
- Multi-bit fault injection
- Targeted register corruption
- Round-specific fault insertion

The framework analyzes:

- Fault propagation
- Round key corruption
- Diffusion characteristics
- Output correctness
- Security implications of injected faults

---

## Experimental Evaluation

The project includes automated experiments for:

- Functional verification
- Pipeline latency analysis
- Throughput benchmarking
- Fault propagation analysis
- Differential fault analysis
- Cross-architecture performance comparison

---

## Repository Structure

```text
.
├── rtl/
│   ├── aes_key_expansion_pipelined.sv
│   ├── aes_key_expansion_nonpipelined.sv
│
├── testbench/
│   ├── aes_key_exp_all_modes_tb.sv
│   ├── aes_key_exp_comparison_tb.sv
│   ├── fault_injection_tb.sv
│   └── ...
│
└── README.md
```

---

## Tools & Technologies

- SystemVerilog
- Xilinx Vivado
- Vivado Simulator
- Digital Hardware Design
- FPGA Verification Methodology

---

## Key Contributions

- Designed a parameterized AES key expansion engine supporting AES-128, AES-192, and AES-256.
- Developed both pipelined and non-pipelined architectures for functional and performance comparison.
- Built an automated verification environment using official NIST test vectors.
- Implemented a fault injection framework to evaluate key schedule robustness against transient hardware faults.
- Characterized pipeline latency and throughput through automated benchmarking.
- Analyzed fault propagation and diffusion across different AES key sizes.

---

## Future Work

Potential extensions include:

- FPGA implementation and hardware validation
- Power and area analysis
- Side-channel attack evaluation
- Formal verification
- Error detection and fault mitigation techniques
