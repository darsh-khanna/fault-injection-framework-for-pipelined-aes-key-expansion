// AES Key Expansion: Comparison Testbench  - TIMING FIX v3
//
// ROOT CAUSE OF RK01 FAIL:
//   The while loop exits at t=105ns ACTIVE REGION where output_stage=1
//   and round_key_out=RK1 is already correct.  The old @(negedge clk)
//   waited through t=105ns NBA, which advanced output_stage to 2, so
//   i=1 read RK2 instead of RK1.
//
// FIX (single line removed):
//   Deleted "@(negedge clk)" from check_pipelined_core().
//   Read p_round_key directly in the for-loop at posedge active region:
//     - i=1 at t=105ns active : output_stage=1 → RK1  ✓
//     - i=2 at t=115ns active : output_stage=2 → RK2  ✓
//     - ...
//     - i=10 at t=195ns active: output_stage=10→ RK10 ✓
//////////////////////////////////////////////////////////////////////////////////

module aes_key_exp_128_tb;

    localparam CLOCK_PERIOD = 10;

    localparam [127:0] KUNG_FU_KEY = 128'h5468617473206D79204B756E67204675;

    reg [127:0] kung_fu_gold [1:10];
    initial begin
        kung_fu_gold[1]  = 128'hE232FCF191129188B159E4E6D679A293;
        kung_fu_gold[2]  = 128'h56082007C71AB18F76435569A03AF7FA;
        kung_fu_gold[3]  = 128'hD2600DE7157ABC686339E901C3031EFB;
        kung_fu_gold[4]  = 128'hA11202C9B468BEA1D75157A01452495B;
        kung_fu_gold[5]  = 128'hB1293B3305418592D210D232C6429B69;
        kung_fu_gold[6]  = 128'hBD3DC287B87C47156A6C9527AC2E0E4E;
        kung_fu_gold[7]  = 128'hCC96ED1674EAAA031E863F24B2A8316A;
        kung_fu_gold[8]  = 128'h8E51EF21FABB4522E43D7A0656954B6C;
        kung_fu_gold[9]  = 128'hBFE2BF904559FAB2A16480B4F7F1CBD8;
        kung_fu_gold[10] = 128'h28FDDEF86DA4244ACCC0A4FE3B316F26;
    end

    // =========================================================================
    // DUT Signals
    // =========================================================================
    logic clk, rst_n;
    logic [255:0] key_in;
    logic [1:0]   key_size;
    logic         valid_in;

    wire [1407:0] np_keys;
    wire          np_ready;
    wire [127:0]  p_round_key;
    wire          p_ready;

    // =========================================================================
    // DUT Instantiations
    // =========================================================================
    aes_key_expansion_nonpipelined dut_np (
        .clk(clk), .rst_n(rst_n),
        .key_in(key_in), .key_size(key_size), .key_valid_in(valid_in),
        .round_keys_out(np_keys), .keys_valid_out(np_ready)
    );

    aes_key_expansion_pipelined dut_p (
        .clk(clk), .rst_n(rst_n),
        .key_in(key_in), .key_size(key_size), .key_valid_in(valid_in),
        .round_key_out(p_round_key), .key_valid_out(p_ready)
    );

    initial begin clk = 0; forever #(CLOCK_PERIOD/2) clk = ~clk; end

    integer error_count = 0;
    integer i;
    integer p_errors  = 0;
    integer np_errors = 0;

    // =========================================================================
    // Main Simulation Block
    // =========================================================================
    initial begin
        $display("\n================================================================================");
        $display("AES KEY EXPANSION: MULTI-ARCHITECTURE VERIFICATION & PERFORMANCE ANALYSIS");
        $display("================================================================================\n");
        $display("[SIMULATION START] @ %0t ns", $time);

        rst_n    = 0;
        valid_in = 0;
        key_in   = 0;
        key_size = 0;
        repeat(5) @(posedge clk);
        rst_n = 1;
        @(posedge clk);

        // =====================================================================
        // STEP 1: CORRECTNESS CHECK
        // =====================================================================
        $display("\n================================================================================");
        $display("STEP 1: CORRECTNESS VERIFICATION (AES-128, 'Kung Fu' Key)");
        $display("================================================================================");

        @(posedge clk);
        key_in   <= {128'h0, KUNG_FU_KEY};
        key_size <= 2'b00;
        valid_in <= 1;
        @(posedge clk);
        valid_in <= 0;

        $display("\n[%0t] Keys loaded, waiting for pipelined core...", $time);

        p_errors = 0;
        check_pipelined_core();

        $display("\n[%0t] Pipelined check complete. Waiting for non-pipelined core...", $time);

        np_errors = 0;
        check_nonpipelined_core();

        error_count = p_errors + np_errors;
        $display("\n[Verification Summary]");
        $display("  Pipelined Errors:     %0d/10", p_errors);
        $display("  Non-Pipelined Errors: %0d/10", np_errors);
        $display("  Total Errors:         %0d/20", error_count);

        // =====================================================================
        // STEP 2: LATENCY
        // =====================================================================
        if (error_count == 0) begin
            $display("\n================================================================================");
            $display("STEP 2: LATENCY CHARACTERIZATION");
            $display("================================================================================");
            measure_latency_aes128();
        end

        // =====================================================================
        // STEP 3: THROUGHPUT
        // =====================================================================
      /*  if (error_count == 0) begin
            $display("\n================================================================================");
            $display("STEP 3: THROUGHPUT ANALYSIS (Multiple Sequential Keys)");
            $display("================================================================================");
            run_throughput_benchmark("AES-128", 2'b00, 10);
            run_throughput_benchmark("AES-192", 2'b01, 10);
            run_throughput_benchmark("AES-256", 2'b10, 10);
        end else begin
            $display("\n[!] PERFORMANCE TESTS SKIPPED: Correctness verification failed.");
        end

        $display("\n================================================================================");
        $display("FINAL REPORT | Simulation Finished @ %0t ns", $time);
        $display("================================================================================");
        if (error_count == 0)
            $display("ALL TESTS PASSED (0 errors)");
        else
            $display("%0d ERRORS DETECTED - Review failures above", error_count);
        $display("================================================================================\n");
        $finish;*/
    end

    // =========================================================================
    // Task: Check Pipelined Core
    // =========================================================================
    task automatic check_pipelined_core();
        integer timeout_count;
        begin
            $display("\n[Pipelined Core Verification]");

            // ------------------------------------------------------------------
            // Wait for p_ready with timeout.
            // The while loop exits in the ACTIVE REGION of the posedge where
            // p_ready first becomes 1.  At that exact moment:
            //   output_stage = 1  (set by the PREVIOUS posedge NBA)
            //   round_key_out    = pipe_w[1] = RK1   <-- already correct here
            // ------------------------------------------------------------------
            timeout_count = 0;
            while (!p_ready && timeout_count < 1000) begin
                @(posedge clk);
                timeout_count++;
            end

            if (!p_ready) begin
                $display("  [ERROR] p_ready timeout after 1000 clocks.");
                p_errors = 10;
                return;
            end

            $display("  p_ready asserted @ %0t ns (latency = %0d clocks)",
                     $time, timeout_count);

            // ------------------------------------------------------------------
            // FIX: NO @(negedge clk) here.
            //
            // Old code had:  @(negedge clk);
            // That waited through the current posedge NBA which updated
            // output_stage 1→2, so i=1 saw RK2 instead of RK1.
            //
            // Reading directly in the for-loop at posedge active region:
            //   i=1  : output_stage=1  → RK1   (current cycle NBA not yet applied)
            //   @posedge → output_stage becomes 2 (previous NBA now settled)
            //   i=2  : output_stage=2  → RK2
            //   ... and so on up to i=10.
            // ------------------------------------------------------------------
            for (i = 1; i <= 10; i++) begin
                if (p_round_key == kung_fu_gold[i])
                    $display("    Pipe Round %02d: [PASS] %h", i, p_round_key);
                else begin
                    $display("    Pipe Round %02d: [FAIL]  Got %h, Expected %h",
                             i, p_round_key, kung_fu_gold[i]);
                    p_errors++;
                end
                if (i < 10) @(posedge clk);   // advance one cycle; NBA settle before next read
            end
        end
    endtask

    // =========================================================================
    // Task: Check Non-Pipelined Core
    // =========================================================================
    task automatic check_nonpipelined_core();
        begin
            $display("\n[Non-Pipelined Core Verification]");
            wait(np_ready);
            $display("  np_ready asserted @ %0t ns", $time);
            for (i = 1; i <= 10; i++) begin
                if (np_keys[i*128 +: 128] == kung_fu_gold[i])
                    $display("    NP Round %02d: [PASS] %h", i, np_keys[i*128 +: 128]);
                else begin
                    $display("    NP Round %02d: [FAIL]  Got %h, Expected %h",
                             i, np_keys[i*128 +: 128], kung_fu_gold[i]);
                    np_errors++;
                end
            end
        end
    endtask

    // =========================================================================
    // Task: Latency Measurement
    // =========================================================================
    task automatic measure_latency_aes128();
        real   np_start_time, np_done_time;
        integer p_latency_clocks, np_latency_clocks;
        begin
            $display("\nLatency for single AES-128 key expansion:");

            // Fresh key load
            @(posedge clk);
            key_in   <= {128'h0, KUNG_FU_KEY};
            key_size <= 2'b00;
            valid_in <= 1;
            @(posedge clk);
            valid_in <= 0;

            // Pipelined: count clocks until p_ready
            p_latency_clocks = 0;
            while (!p_ready) begin
                @(posedge clk);
                p_latency_clocks++;
                if (p_latency_clocks > 200) break;
            end
            $display("  Pipelined  (key -> first RK): %0d clocks  (%0d ns)",
                     p_latency_clocks, p_latency_clocks * CLOCK_PERIOD);

            // Skip past pipelined output window
            repeat(15) @(posedge clk);

            // Non-pipelined: wall-clock from key load to np_ready
            @(posedge clk);
            key_in   <= {128'h0, KUNG_FU_KEY};
            key_size <= 2'b00;
            valid_in <= 1;
            @(posedge clk);
            valid_in    <= 0;
            np_start_time = $time;

            wait(np_ready);
            np_done_time     = $time;
            np_latency_clocks = integer'((np_done_time - np_start_time) / CLOCK_PERIOD);
            $display("  Non-pipelined (key -> all RKs): %0d clocks  (%0d ns)",
                     np_latency_clocks, integer'(np_done_time - np_start_time));
            $display("  Speedup: %.1fx",
                     real'(np_latency_clocks) / real'(p_latency_clocks));
        end
    endtask

    // =========================================================================
    // Task: Throughput Benchmark
    // =========================================================================
    task automatic run_throughput_benchmark(
        input string  mode,
        input [1:0]   sz,
        input integer num_keys
    );
        real    p_start, p_end, p_duration;
        real    np_start, np_end, np_duration;
        integer key_idx;
        begin
            $display("\n[%s: %0d Sequential Expansions]", mode, num_keys);

            // Pipelined: fire all keys back-to-back
            p_start = $time;
            for (key_idx = 0; key_idx < num_keys; key_idx++) begin
                @(posedge clk);
                key_in   <= (256'hDEADBEEFCAFEBABE << 128) | (key_idx + 1);
                key_size <= sz;
                valid_in <= 1;
            end
            @(posedge clk);
            valid_in <= 0;
            repeat(30) @(posedge clk);   // flush pipeline
            p_end      = $time;
            p_duration = p_end - p_start;

            // Non-pipelined: each key must complete before next
            np_start = $time;
            for (key_idx = 0; key_idx < num_keys; key_idx++) begin
                @(posedge clk);
                key_in   <= (256'hDEADBEEFCAFEBABE << 128) | (key_idx + 1);
                key_size <= sz;
                valid_in <= 1;
                @(posedge clk);
                valid_in <= 0;
                wait(np_ready);
                repeat(2) @(posedge clk);
            end
            np_end      = $time;
            np_duration = np_end - np_start;

            $display("  Pipelined     : %.2f keys/sec  (%0.0f ns total)",
                     (num_keys * 1e9) / p_duration,  p_duration);
            $display("  Non-Pipelined : %.2f keys/sec  (%0.0f ns total)",
                     (num_keys * 1e9) / np_duration, np_duration);
            $display("  Speedup       : %.2fx",        np_duration / p_duration);
            $display("  Avg per key   : P=%.0f ns   NP=%.0f ns",
                     p_duration / num_keys, np_duration / num_keys);
        end
    endtask

endmodule
