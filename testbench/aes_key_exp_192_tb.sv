`timescale 1ns / 1ps

// =============================================================================
// AES Key Expansion: AES-192 Focused Comparison Testbench
//
// Tests both the pipelined and non-pipelined key expansion modules for
// AES-192 only.  Mirrors the structure of the AES-128 testbench:
//   Step 1 - Correctness (NIST FIPS 197 test vector)
//   Step 2 - Latency characterisation
//   Step 3 - Throughput (10 sequential key expansions)
//
// AES-192 reference key (NIST FIPS 197, Appendix A.2):
//   8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b
//
// Key packing into key_in[255:0] per the unified convention:
//   key_in[191:160] = 8e73b0f7   (W[0])
//   key_in[159:128] = da0e6452   (W[1])
//   key_in[127: 96] = c810f32b   (W[2])
//   key_in[ 95: 64] = 809079e5   (W[3])
//   key_in[ 63: 32] = 62f8ead2   (W[4])
//   key_in[ 31:  0] = 522c6b7b   (W[5])
//   key_in[255:192]             = 64'h0 (unused)
//
// Expected round keys RK00-RK12 (from FIPS 197 / NIST AES KAT):
//   RK00 = 8e73b0f7 da0e6452 c810f32b 809079e5
//   RK01 = 62f8ead2 522c6b7b fe0c91f7 2402f5a5
//   RK02 = ec12068e 6c827f6b 0e7a95b9 5c56fec2
//   RK03 = 4db7b4bd 69b54118 85a74796 e92538fd
//   RK04 = e75fad44 bb095386 485af057 21efb14f
//   RK05 = a448f6d9 4d6dce24 aa326360 113b30e6
//   RK06 = a25e7ed5 83b1cf9a 27f93943 6a94f767
//   RK07 = c0a69407 d19da4e1 ec1786eb 6fa64971
//   RK08 = 485f7032 22cb8755 e26d1352 33f0b7b3
//   RK09 = 40beeb28 2f18a259 6747d26b 458c553e
//   RK10 = a7e1466c 9411f1df 821f750a ad07d753
//   RK11 = ca400538 8fcc5006 282d166a bc3ce7b5
//   RK12 = e98ba06f 448c773c 8ecc7204 01002202
//
// PIPELINED OUTPUT TIMING (AES-192):
//   The pipelined module uses Nk=6 words/stage.  Stages 0..8 are needed.
//   Round keys straddle adjacent pipeline stages (every 3rd RK).
//   The output_stage counter for AES-192 has a sentinel path (5'd13 → 0 →
//   counting), so the first valid output appears slightly later than AES-128.
//
//   Timeline from key_valid_in posedge (cycle C):
//     C+1 : pipe_valid[0] = 1, pipe_w[0] = W[0..5]  (stage 0 settled)
//     C+2 : pipe_valid[1] = 1 - this triggers output_stage → 5'd13
//     C+3 : output_stage = 13 → transitions to 0; round_key_out = RK00
//            key_valid_out asserted (output_stage in 0..12)
//     C+4 : output_stage = 0; but now >=0 and <12 condition increments → 1
//            Wait - this is the known FSM ambiguity noted in review.
//
//   TESTBENCH STRATEGY: use the key_valid_out strobe to gate sampling.
//   Sample round_key_out on each posedge where key_valid_out is asserted,
//   incrementing a round index from 0.  This is robust to the exact sentinel
//   timing and lets us verify whatever the hardware outputs in order.
//
// NON-PIPELINED OUTPUT TIMING (AES-192):
//   Nk=6, total_words=52.  6 words pre-loaded, then 46 words computed
//   one per clock.  Plus 1 load cycle + 1 done cycle = 48 clocks total.
//   round_keys_out[1791:0] slot i = RK(i).
//   Check all 13 slots (0..12) once np_ready asserts.
//
// WIRE WIDTH NOTE:
//   The v2 non-pipelined module outputs round_keys_out[1791:0].
//   The testbench declares np_keys at full width to avoid truncation.
// =============================================================================

module aes_key_exp_192_tb;

    localparam CLOCK_PERIOD = 10;  // ns
    localparam TIMEOUT_CLOCKS = 2000;

    // =========================================================================
    // AES-192 NIST FIPS 197 Test Vector
    // =========================================================================
    // Key: 8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b
    // Packed into key_in[255:0] with key_in[255:192] = 0 (unused)
    localparam [255:0] AES192_KEY = {
        64'h0,
        32'h8e73b0f7, 32'hda0e6452, 32'hc810f32b,
        32'h809079e5,  32'h62f8ead2, 32'h522c6b7b
    };

    // 13 round keys RK00..RK12
    // Index 0 = RK00 (original key material), index 12 = RK12 (final)
    logic [127:0] rk_gold [0:12];
    initial begin
        rk_gold[0]  = 128'h8e73b0f7_da0e6452_c810f32b_809079e5;
        rk_gold[1]  = 128'h62f8ead2_522c6b7b_fe0c91f7_2402f5a5;
        rk_gold[2]  = 128'hec12068e_6c827f6b_0e7a95b9_5c56fec2;
        rk_gold[3]  = 128'h4db7b4bd_69b54118_85a74796_e92538fd;
        rk_gold[4]  = 128'he75fad44_bb095386_485af057_21efb14f;
        rk_gold[5]  = 128'ha448f6d9_4d6dce24_aa326360_113b30e6;
        rk_gold[6]  = 128'ha25e7ed5_83b1cf9a_27f93943_6a94f767;
        rk_gold[7]  = 128'hc0a69407_d19da4e1_ec1786eb_6fa64971;
        rk_gold[8]  = 128'h485f7032_22cb8755_e26d1352_33f0b7b3;
        rk_gold[9]  = 128'h40beeb28_2f18a259_6747d26b_458c553e;
        rk_gold[10] = 128'ha7e1466c_9411f1df_821f750a_ad07d753;
        rk_gold[11] = 128'hca400538_8fcc5006_282d166a_bc3ce7b5;
        rk_gold[12] = 128'he98ba06f_448c773c_8ecc7204_01002202;
    end

    // =========================================================================
    // DUT Signals
    // =========================================================================
    logic        clk, rst_n;
    logic [255:0] key_in;
    logic [1:0]   key_size;
    logic         valid_in;

    // Non-pipelined: full 1792-bit bus (14 slots × 128 bits)
    wire [1791:0] np_keys;
    wire          np_ready;
    wire [3:0]    np_rounds;

    // Pipelined: streaming output
    wire [127:0]  p_round_key;
    wire          p_ready;

    // =========================================================================
    // DUT Instantiations
    // =========================================================================
    aes_key_expansion_nonpipelined dut_np (
        .clk           (clk),
        .rst_n         (rst_n),
        .key_in        (key_in),
        .key_size      (key_size),
        .key_valid_in  (valid_in),
        .round_keys_out(np_keys),
        .keys_valid_out(np_ready),
        .rounds_out    (np_rounds)
    );

    aes_key_expansion_pipelined dut_p (
        .clk          (clk),
        .rst_n        (rst_n),
        .key_in       (key_in),
        .key_size     (key_size),
        .key_valid_in (valid_in),
        .round_key_out(p_round_key),
        .key_valid_out(p_ready)
    );

    // =========================================================================
    // Clock Generation
    // =========================================================================
    initial begin clk = 0; forever #(CLOCK_PERIOD/2) clk = ~clk; end

    // =========================================================================
    // Error Tracking
    // =========================================================================
    integer p_errors  = 0;
    integer np_errors = 0;
    integer total_errors = 0;
    integer i;

    // =========================================================================
    // Main Simulation
    // =========================================================================
    initial begin
        $display("\n================================================================================");
        $display("AES KEY EXPANSION: AES-192 VERIFICATION & PERFORMANCE ANALYSIS");
        $display("================================================================================\n");
        $display("[SIMULATION START] @ %0t ns", $time);
        $display("Key     : 8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b");
        $display("Expected: 13 round keys (RK00..RK12)");

        // Reset
        rst_n    = 0;
        valid_in = 0;
        key_in   = 0;
        key_size = 0;
        repeat(5) @(posedge clk);
        rst_n = 1;
        @(posedge clk);

        // =====================================================================
        // STEP 1 - CORRECTNESS
        // =====================================================================
        $display("\n================================================================================");
        $display("STEP 1: CORRECTNESS VERIFICATION (AES-192, NIST FIPS 197 Key)");
        $display("================================================================================");

        p_errors  = 0;
        np_errors = 0;

        // Load the key once; both DUTs see it simultaneously
        @(posedge clk);
        key_in   <= AES192_KEY;
        key_size <= 2'b01;   // AES-192
        valid_in <= 1;
        @(posedge clk);
        valid_in <= 0;

        $display("\n[%0t ns] AES-192 key loaded, waiting for pipelined core...", $time);

        check_pipelined_192();

        $display("\n[%0t ns] Pipelined check complete. Waiting for non-pipelined core...", $time);

        check_nonpipelined_192();

        total_errors = p_errors + np_errors;
        $display("\n[Correctness Summary]");
        $display("  Pipelined Errors:     %0d/13", p_errors);
        $display("  Non-Pipelined Errors: %0d/13", np_errors);
        $display("  Total Errors:         %0d/26", total_errors);

        // =====================================================================
        // STEP 2 - LATENCY
        // =====================================================================
        if (total_errors == 0) begin
            $display("\n================================================================================");
            $display("STEP 2: LATENCY CHARACTERISATION (AES-192)");
            $display("================================================================================");
            measure_latency_192();
        end else begin
            $display("\n[!] LATENCY TEST SKIPPED: Correctness failures detected.");
        end

        // =====================================================================
        // STEP 3 - THROUGHPUT
        // =====================================================================
        if (total_errors == 0) begin
            $display("\n================================================================================");
            $display("STEP 3: THROUGHPUT ANALYSIS (10 × AES-192 Sequential Expansions)");
            $display("================================================================================");
            run_throughput_benchmark_192(10);
        end else begin
            $display("\n[!] THROUGHPUT TEST SKIPPED: Correctness failures detected.");
        end

        // =====================================================================
        // FINAL REPORT
        // =====================================================================
        $display("\n================================================================================");
        $display("FINAL REPORT | Simulation Finished @ %0t ns", $time);
        $display("================================================================================");
        if (total_errors == 0)
            $display("ALL AES-192 TESTS PASSED (0 errors)");
        else
            $display("%0d ERRORS DETECTED - Review failures above", total_errors);
        $display("================================================================================\n");
        $finish;
    end

    // =========================================================================
    // Task: Check Pipelined Core - AES-192
    //
    // Strategy: sample p_round_key on every posedge where p_ready is high.
    // The FSM sentinel path means we cannot assume the first valid output
    // lands exactly N clocks after key load.  We simply wait for p_ready,
    // then collect exactly 13 consecutive valid samples (one per posedge
    // while p_ready stays asserted), comparing each to rk_gold[0..12].
    //
    // Timing notes:
    //   - p_ready is an always_comb signal driven by output_stage.
    //   - For AES-192, key_valid_out = (output_stage >= 0 && <= 12).
    //   - At the posedge where p_ready first goes high, p_round_key already
    //     holds the correct value for that output_stage (NBA settled from
    //     prior posedge).  No negedge sampling needed.
    // =========================================================================
    task automatic check_pipelined_192();
        integer timeout_count;
        integer rk_idx;
        integer first_ready_time;
        begin
            $display("\n[Pipelined Core Verification - AES-192]");

            // Wait for p_ready to assert
            timeout_count = 0;
            @(posedge clk);   // step off the valid_in posedge
            while (!p_ready && timeout_count < TIMEOUT_CLOCKS) begin
                @(posedge clk);
                timeout_count++;
            end

            if (!p_ready) begin
                $display("  [ERROR] p_ready never asserted (timeout after %0d clocks)",
                         TIMEOUT_CLOCKS);
                p_errors = 13;
                return;
            end

            first_ready_time = $time;
            $display("  p_ready first asserted @ %0t ns (latency = %0d clocks after key load)",
                     first_ready_time, timeout_count + 1);
            $display("  Collecting 13 round keys while p_ready is high...");
            $display("");

            // Collect all 13 round keys on consecutive posedges where p_ready=1
            rk_idx = 0;
            while (rk_idx < 13) begin
                if (!p_ready) begin
                    $display("  [ERROR] p_ready dropped before all 13 round keys output (got %0d)",
                             rk_idx);
                    p_errors = p_errors + (13 - rk_idx);
                    return;
                end
                if (p_round_key === rk_gold[rk_idx])
                    $display("    Pipe RK%02d: [PASS] %h", rk_idx, p_round_key);
                else begin
                    $display("    Pipe RK%02d: [FAIL]  Got      %h", rk_idx, p_round_key);
                    $display("                       Expected %h", rk_gold[rk_idx]);
                    p_errors++;
                end
                rk_idx++;
                if (rk_idx < 13) @(posedge clk);
            end

            $display("");
            $display("  Pipelined window closed @ %0t ns", $time);
        end
    endtask

    // =========================================================================
    // Task: Check Non-Pipelined Core - AES-192
    //
    // Wait for np_ready, then read all 13 slots from round_keys_out.
    // Slot i = round_keys_out[(i*128)+127 -: 128] = RK(i).
    // rounds_out should equal 4'd12 for AES-192.
    // =========================================================================
    task automatic check_nonpipelined_192();
        integer timeout_count;
        begin
            $display("\n[Non-Pipelined Core Verification - AES-192]");

            timeout_count = 0;
            while (!np_ready && timeout_count < TIMEOUT_CLOCKS) begin
                @(posedge clk);
                timeout_count++;
            end

            if (!np_ready) begin
                $display("  [ERROR] np_ready never asserted (timeout after %0d clocks)",
                         TIMEOUT_CLOCKS);
                np_errors = 13;
                return;
            end

            $display("  np_ready asserted @ %0t ns", $time);
            $display("  rounds_out = %0d (expected 12)", np_rounds);
            if (np_rounds !== 4'd12) begin
                $display("  [WARN] rounds_out mismatch - expected 12, got %0d", np_rounds);
            end
            $display("");

            for (i = 0; i <= 12; i++) begin
                automatic logic [127:0] slot;
                slot = np_keys[(i*128 + 127) -: 128];
                if (slot === rk_gold[i])
                    $display("    NP    RK%02d: [PASS] %h", i, slot);
                else begin
                    $display("    NP    RK%02d: [FAIL]  Got      %h", i, slot);
                    $display("                       Expected %h", rk_gold[i]);
                    np_errors++;
                end
            end
        end
    endtask

    // =========================================================================
    // Task: Latency Measurement - AES-192
    //
    // Pipelined: clocks from key_valid_in posedge to first p_ready posedge.
    // Non-pipelined: clocks from key_valid_in posedge to np_ready posedge.
    // Both are measured on a fresh, isolated key load after prior traffic
    // has settled.
    // =========================================================================
    task automatic measure_latency_192();
        integer p_latency_clocks;
        integer np_latency_clocks;
        real    np_start_time, np_done_time;
        begin
            $display("\nLatency for single AES-192 key expansion:");

            // Let any residual output_stage counter wind down
            repeat(20) @(posedge clk);

            // --- Pipelined latency ---
            @(posedge clk);
            key_in   <= AES192_KEY;
            key_size <= 2'b01;
            valid_in <= 1;
            @(posedge clk);
            valid_in <= 0;

            p_latency_clocks = 1;   // 1 for the cycle after valid_in deasserts
            while (!p_ready) begin
                @(posedge clk);
                p_latency_clocks++;
                if (p_latency_clocks > TIMEOUT_CLOCKS) begin
                    $display("  [ERROR] p_ready timeout in latency measurement");
                    return;
                end
            end
            $display("  Pipelined  (key_valid_in -> first RK): %0d clocks  (%0d ns)",
                     p_latency_clocks, p_latency_clocks * CLOCK_PERIOD);

            // Flush the pipelined output window (13 keys + margin)
            repeat(20) @(posedge clk);

            // --- Non-pipelined latency ---
            @(posedge clk);
            key_in      <= AES192_KEY;
            key_size    <= 2'b01;
            valid_in    <= 1;
            np_start_time = $time;
            @(posedge clk);
            valid_in <= 0;

            while (!np_ready) begin
                @(posedge clk);
                if (($time - np_start_time) / CLOCK_PERIOD > TIMEOUT_CLOCKS) begin
                    $display("  [ERROR] np_ready timeout in latency measurement");
                    return;
                end
            end
            np_done_time      = $time;
            np_latency_clocks = integer'((np_done_time - np_start_time) / CLOCK_PERIOD);

            $display("  Non-pipelined (key_valid_in -> all RKs): %0d clocks  (%0d ns)",
                     np_latency_clocks, integer'(np_done_time - np_start_time));

            if (p_latency_clocks > 0)
                $display("  Latency Speedup: %.1fx",
                         real'(np_latency_clocks) / real'(p_latency_clocks));

            $display("");
            $display("  Note: Pipelined latency = clocks to FIRST round key.");
            $display("        All 13 RKs stream over the following 12 clocks.");
            $display("        Non-pipelined latency = clocks until ALL RKs are ready.");
        end
    endtask

    // =========================================================================
    // Task: Throughput Benchmark - AES-192
    //
    // Pipelined: fire all keys back-to-back (one per clock), then flush.
    //   The pipeline accepts a new key every clock, so throughput approaches
    //   1 key/clock once the pipeline is saturated.
    //
    // Non-pipelined: each key must fully complete before the next is loaded.
    //   busy signal prevents overlapping; we wait on np_ready + 2-cycle gap.
    // =========================================================================
    task automatic run_throughput_benchmark_192(input integer num_keys);
        real    p_start, p_end, p_duration;
        real    np_start, np_end, np_duration;
        integer key_idx;
        begin
            $display("\n[AES-192 Throughput: %0d Sequential Key Expansions]", num_keys);

            // Flush any prior state
            repeat(30) @(posedge clk);

            // --- Pipelined throughput ---
            p_start = $time;
            for (key_idx = 0; key_idx < num_keys; key_idx++) begin
                @(posedge clk);
                // Vary the key slightly so each expansion is independent
                key_in   <= {32'h0, 32'hDEADBEEF, 32'hCAFEBABE,
                             32'h01234567, 32'h89ABCDEF,
                             32'h00000000 | (key_idx + 1),
                             64'h0};
                key_size <= 2'b01;
                valid_in <= 1;
            end
            @(posedge clk);
            valid_in <= 0;
            // Flush: AES-192 needs up to 8 pipeline stages + 13 output cycles
            repeat(30) @(posedge clk);
            p_end      = $time;
            p_duration = p_end - p_start;

            // --- Non-pipelined throughput ---
            np_start = $time;
            for (key_idx = 0; key_idx < num_keys; key_idx++) begin
                @(posedge clk);
                key_in   <= {32'h0, 32'hDEADBEEF, 32'hCAFEBABE,
                             32'h01234567, 32'h89ABCDEF,
                             32'h00000000 | (key_idx + 1),
                             64'h0};
                key_size <= 2'b01;
                valid_in <= 1;
                @(posedge clk);
                valid_in <= 0;
                // Must wait for completion before next load (busy gate)
                while (!np_ready) @(posedge clk);
                repeat(2) @(posedge clk);
            end
            np_end      = $time;
            np_duration = np_end - np_start;

            $display("  Pipelined      : %.2f keys/sec  (%0.0f ns total)",
                     (num_keys * 1.0e9) / p_duration,  p_duration);
            $display("  Non-Pipelined  : %.2f keys/sec  (%0.0f ns total)",
                     (num_keys * 1.0e9) / np_duration, np_duration);
            $display("  Speedup        : %.2fx",       np_duration / p_duration);
            $display("  Avg per key    : P = %.0f ns   NP = %.0f ns",
                     p_duration / num_keys, np_duration / num_keys);
        end
    endtask

endmodule
