`timescale 1ns / 1ps
// =============================================================================
// AES Key Expansion: Fault Injection & Differential Analysis Testbench
//
// PURPOSE
// -------
// Verifies the hardware AES key schedule (128/192/256-bit, pipelined rounds)
// from a SECURITY perspective:
//   1. Fault propagation rate   - what fraction of downstream round keys are
//                                  corrupted by a single injected bit fault.
//   2. Key schedule correctness - NIST FIPS 197 KAT gate (must pass before
//                                  any fault-injection result is meaningful).
//   3. Security coverage        - what fraction of the (stage, word, bit)
//                                  fault-injection space was exercised.
//
// METHODOLOGY (Differential Fault Analysis - DFA)
// ---------------------------------------------------------------------------
// For each injected fault:
//   1. GOLDEN RUN   : load key, capture full RK stream -> golden[].
//   2. FAULTED RUN  : reset, reload SAME key, use hierarchical force/release
//                      to corrupt exactly one bit of pipe_w[s][w][b] for
//                      exactly one clock cycle, capture -> faulted[].
//   3. DIFFERENTIAL : XOR golden[] against faulted[].  Any nonzero XOR marks
//                      that round key as "affected".
//
// FAULT MODEL
// -----------
// RTL-level transient single-bit fault: standard DFA abstraction for
// voltage/clock glitching, laser FI, EM pulse.
//
// NOTE ON force/release AND static TASKS
// ---------------------------------------------------------------------------
// force/release targets must resolve to STATIC storage at elaboration time
// (XSim VRFC 10-3142).  Tasks force_bit, release_bit, force_dispatch are
// therefore declared WITHOUT the `automatic` keyword (static tasks).
// force_target_word is a module-level static variable shared by these tasks.
// All three tasks are called strictly sequentially - no concurrent fork
// branches - so sharing static storage is safe.
// =============================================================================

module aes_key_exp_fault_injection_tb;

    localparam CLK_PERIOD = 10;     // ns
    localparam TIMEOUT    = 200;    // clocks
    localparam IDLE_GAP   = 32;     // clocks between campaign runs

    // BIT_STRIDE: skip factor across the 32-bit word space during fault sweep.
    // STRIDE=7 samples bits 0,7,14,21,28 per word (5 bits/word), bounding
    // runtime while exercising every stage and every word at least once.
    localparam int BIT_STRIDE = 7;

    // =========================================================================
    // DUT I/O
    // =========================================================================
    logic        clk, rst_n;
    logic [255:0] key_in;
    logic [1:0]   key_size;
    logic         valid_in;

    wire [127:0]  p_key;
    wire          p_ready;
    wire          p_fifo_overflow;

    wire [1919:0] np_keys;
    wire          np_ready;
    wire [3:0]    np_rounds;

    // =========================================================================
    // DUT Instantiation
    // =========================================================================
    aes_key_expansion_pipelined dut_p (
        .clk          (clk),
        .rst_n        (rst_n),
        .key_in       (key_in),
        .key_size     (key_size),
        .key_valid_in (valid_in),
        .round_key_out(p_key),
        .key_valid_out(p_ready),
        .fifo_overflow(p_fifo_overflow)
    );

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

    initial begin clk = 0; forever #(CLK_PERIOD/2) clk = ~clk; end

    // =========================================================================
    // NIST FIPS 197 Reference Round Keys
    // =========================================================================
    localparam [127:0] KEY128 = 128'h2b7e151628aed2a6abf7158809cf4f3c;
    localparam [191:0] KEY192 = 192'h8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b;
    localparam [255:0] KEY256 = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;

    // FIX: use fixed-size [0:14] bounds instead of open-array [] to avoid
    // XSim silent failures when passing arrays as task arguments.
    logic [127:0] gold128 [0:10];
    initial begin
        gold128[0]  = 128'h2b7e151628aed2a6abf7158809cf4f3c;
        gold128[1]  = 128'ha0fafe1788542cb123a339392a6c7605;
        gold128[2]  = 128'hf2c295f27a96b9435935807a7359f67f;
        gold128[3]  = 128'h3d80477d4716fe3e1e237e446d7a883b;
        gold128[4]  = 128'hef44a541a8525b7fb671253bdb0bad00;
        gold128[5]  = 128'hd4d1c6f87c839d87caf2b8bc11f915bc;
        gold128[6]  = 128'h6d88a37a110b3efddbf98641ca0093fd;
        gold128[7]  = 128'h4e54f70e5f5fc9f384a64fb24ea6dc4f;
        gold128[8]  = 128'head27321b58dbad2312bf5607f8d292f;
        gold128[9]  = 128'hac7766f319fadc2128d12941575c006e;
        gold128[10] = 128'hd014f9a8c9ee2589e13f0cc8b6630ca6;
    end

    logic [127:0] gold192 [0:12];
    initial begin
        gold192[0]  = 128'h8e73b0f7da0e6452c810f32b809079e5;
        gold192[1]  = 128'h62f8ead2522c6b7bfe0c91f72402f5a5;
        gold192[2]  = 128'hec12068e6c827f6b0e7a95b95c56fec2;
        gold192[3]  = 128'h4db7b4bd69b5411885a74796e92538fd;
        gold192[4]  = 128'he75fad44bb095386485af05721efb14f;
        gold192[5]  = 128'ha448f6d94d6dce24aa326360113b30e6;
        gold192[6]  = 128'ha25e7ed583b1cf9a27f939436a94f767;
        gold192[7]  = 128'hc0a69407d19da4e1ec1786eb6fa64971;
        gold192[8]  = 128'h485f703222cb8755e26d135233f0b7b3;
        gold192[9]  = 128'h40beeb282f18a2596747d26b458c553e;
        gold192[10] = 128'ha7e1466c9411f1df821f750aad07d753;
        gold192[11] = 128'hca4005388fcc5006282d166abc3ce7b5;
        gold192[12] = 128'he98ba06f448c773c8ecc720401002202;
    end

    logic [127:0] gold256 [0:14];
    initial begin
        gold256[0]  = 128'h603deb1015ca71be2b73aef0857d7781;
        gold256[1]  = 128'h1f352c073b6108d72d9810a30914dff4;
        gold256[2]  = 128'h9ba354118e6925afa51a8b5f2067fcde;
        gold256[3]  = 128'ha8b09c1a93d194cdbe49846eb75d5b9a;
        gold256[4]  = 128'hd59aecb85bf3c917fee94248de8ebe96;
        gold256[5]  = 128'hb5a9328a2678a647983122292f6c79b3;
        gold256[6]  = 128'h812c81addadf48ba24360af2fab8b464;
        gold256[7]  = 128'h98c5bfc9bebd198e268c3ba709e04214;
        gold256[8]  = 128'h68007bacb2df331696e939e46c518d80;
        gold256[9]  = 128'hc814e20476a9fb8a5025c02d59c58239;
        gold256[10] = 128'hde1369676ccc5a71fa2563959674ee15;
        gold256[11] = 128'h5886ca5d2e2f31d77e0af1fa27cf73c3;
        gold256[12] = 128'h749c47ab18501ddae2757e4f7401905a;
        gold256[13] = 128'hcafaaae3e4d59b349adf6acebd10190d;
        gold256[14] = 128'hfe4890d1e6188d0b046df344706c631e;
    end

    // =========================================================================
    // Global counters
    // =========================================================================
    integer baseline_errors = 0;
    integer baseline_checks = 0;

    integer total_faults_injected   = 0;
    integer total_faults_propagated = 0;
    integer total_faults_full_diff  = 0;
    integer total_diff_bits_sum     = 0;
    integer total_affected_rk_count = 0;

    integer coverage_points_total_128, coverage_points_hit_128;
    integer coverage_points_total_192, coverage_points_hit_192;
    integer coverage_points_total_256, coverage_points_hit_256;

    // =========================================================================
    // Utility: wait_idle / reset_pulse
    // =========================================================================
    task automatic wait_idle();
        integer g;
        begin
            g = 0;
            while (p_ready && g < IDLE_GAP) begin @(posedge clk); g++; end
            repeat(IDLE_GAP) @(posedge clk);
        end
    endtask

    task automatic reset_pulse();
        begin
            wait_idle();
            rst_n    <= 0;
            valid_in <= 0;
            repeat(4) @(posedge clk);
            rst_n    <= 1;
            repeat(4) @(posedge clk);
        end
    endtask

    // =========================================================================
    // STEP 1: Baseline correctness (NIST KAT)
    // FIX: task arguments use fixed-size [0:14] array instead of open []
    // to avoid XSim silent data loss when passing dynamic arrays to tasks.
    // =========================================================================
    task automatic check_baseline_p(
        input  string        label,
        input  logic [1:0]   ksize,
        input  integer       nr,
        ref    logic [127:0] gold [0:14],   // FIX: ref + fixed bounds
        output integer       errs
    );
        integer t, idx, first_idx;
        begin
            errs = 0; t = 0;
            // AES-192 (ksize=2'b01) streams RK00 first; 128 and 256 start at RK01.
            first_idx = (ksize == 2'b01) ? 0 : 1;
            @(posedge clk);
            while (!p_ready && t < TIMEOUT) begin @(posedge clk); t++; end
            if (!p_ready) begin
                $display("  [BASELINE-P][%s] TIMEOUT waiting for p_ready", label);
                errs = nr - first_idx + 1; return;
            end
            for (idx = first_idx; idx <= nr; idx++) begin
                if (!p_ready) begin errs += (nr - idx + 1); return; end
                if (p_key !== gold[idx]) begin
                    $display("  [BASELINE-P][%s] RK%02d FAIL got=%h exp=%h",
                             label, idx, p_key, gold[idx]);
                    errs++;
                end
                if (idx < nr) @(posedge clk);
            end
        end
    endtask

    task automatic check_baseline_np(
        input  string        label,
        input  integer       nr,
        ref    logic [127:0] gold [0:14],   // FIX: ref + fixed bounds
        output integer       errs
    );
        integer t, slot;
        logic [127:0] got;
        begin
            errs = 0; t = 0;
            while (!np_ready && t < TIMEOUT) begin @(posedge clk); t++; end
            if (!np_ready) begin
                $display("  [BASELINE-NP][%s] TIMEOUT waiting for np_ready", label);
                errs = nr + 1; return;
            end
            for (slot = 0; slot <= nr; slot++) begin
                got = np_keys[(slot*128 + 127) -: 128];
                if (got !== gold[slot]) begin
                    $display("  [BASELINE-NP][%s] RK%02d FAIL got=%h exp=%h",
                             label, slot, got, gold[slot]);
                    errs++;
                end
            end
        end
    endtask

    // Wrapper: needs separate per-size gold arrays since we cannot pass
    // gold128[0:10] where gold[0:14] is expected (different bound).
    // We copy into a [0:14] staging array to satisfy the fixed-bound ref.
    logic [127:0] gold_stage [0:14];

    task automatic run_baseline(
        input  string      label,
        input  logic [1:0] ksize,
        input  logic [255:0] kin,
        input  integer     nr_p,
        input  integer     nr_np
    );
        integer pe, ne;
        begin
            reset_pulse();
            @(posedge clk);
            key_in <= kin; key_size <= ksize; valid_in <= 1;
            @(posedge clk);
            valid_in <= 0;
            fork
                check_baseline_p (label, ksize, nr_p,  gold_stage, pe);
                check_baseline_np(label, nr_np, gold_stage, ne);
            join
            baseline_errors += pe + ne;
            baseline_checks += ((ksize == 2'b01) ? (nr_p + 1) : nr_p) + (nr_np + 1);
            $display("  [%s] baseline: P_errs=%0d NP_errs=%0d  %s",
                      label, pe, ne, (pe==0 && ne==0) ? "PASS" : "FAIL");
        end
    endtask

    // =========================================================================
    // STEP 2: GOLDEN CAPTURE (pipelined DUT only)
    // =========================================================================
    logic [127:0] golden_capture  [0:14];
    logic [127:0] faulted_capture [0:14];
    logic [31:0]  force_target_word;           // static - shared by force tasks

    task automatic capture_pipelined_stream(
        input  logic [1:0]   ksize,
        input  logic [255:0] kin,
        input  integer       n_rk
    );
        // Writes into golden_capture[] directly (module-level, no output arg).
        integer t, idx;
        begin
            reset_pulse();
            @(posedge clk);
            key_in <= kin; key_size <= ksize; valid_in <= 1;
            @(posedge clk);
            valid_in <= 0;

            t = 0;
            @(posedge clk);
            while (!p_ready && t < TIMEOUT) begin @(posedge clk); t++; end
            if (!p_ready) begin
                $display("  [CAPTURE] TIMEOUT waiting for p_ready");
                for (idx = 0; idx < 15; idx++) golden_capture[idx] = 128'hx;
                return;
            end
            for (idx = 0; idx < n_rk; idx++) begin
                golden_capture[idx] = p_ready ? p_key : 128'hx;
                if (idx < n_rk-1) @(posedge clk);
            end
        end
    endtask

    // =========================================================================
    // FAULT INJECTION CORE
    // Resets DUT, reloads same key, waits injection_cycle clocks after
    // valid_in deasserts, forces one bit for one clock, then captures output.
    // Writes into faulted_capture[] (module-level).
    // =========================================================================
    task automatic inject_fault_and_capture(
        input  logic [1:0]   ksize,
        input  logic [255:0] kin,
        input  integer       n_rk,
        input  integer       fault_stage,
        input  integer       fault_word,
        input  integer       fault_bit,
        input  integer       injection_cycle
    );
        integer t, idx;
        begin
            reset_pulse();
            @(posedge clk);
            key_in <= kin; key_size <= ksize; valid_in <= 1;
            @(posedge clk);
            valid_in <= 0;

            // Advance to the injection point (measured from the clock AFTER
            // valid_in deasserts so that injection_cycle=0 forces on the very
            // next edge after loading).
            repeat(injection_cycle) @(posedge clk);

            force_bit(fault_stage, fault_word, fault_bit);
            @(posedge clk);
            release_bit(fault_stage, fault_word, fault_bit);

            // FIX: advance one extra clock before the p_ready loop, exactly
            // matching the golden capture_pipelined_stream which also has one
            // extra @(posedge clk) before its while(!p_ready) check.
            // Without this the two captures start from different FIFO positions,
            // making ALL round keys appear different even when no real corruption
            // reached the output (false-positive propagation).
            t = 0;
            @(posedge clk);
            while (!p_ready && t < TIMEOUT) begin @(posedge clk); t++; end
            if (!p_ready) begin
                $display("  [FAULT %0d,%0d,%0d] TIMEOUT after injection",
                         fault_stage, fault_word, fault_bit);
                for (idx = 0; idx < 15; idx++) faulted_capture[idx] = 128'hx;
                return;
            end
            for (idx = 0; idx < n_rk; idx++) begin
                faulted_capture[idx] = p_ready ? p_key : 128'hx;
                if (idx < n_rk-1) @(posedge clk);
            end
        end
    endtask

    // =========================================================================
    // force_bit / release_bit / force_dispatch
    //
    // STATIC tasks (no `automatic`) so that force/release targets resolve to
    // static module-level storage (XSim VRFC 10-3142 requirement).
    // force_target_word is the module-level staging register.
    //
    // force_dispatch covers pipe_w[0..14][0..7] - 15 stages × 8 words.
    // =========================================================================
    task force_bit(input integer stage, input integer word, input integer bit_idx);
        begin
            force_target_word = dut_p.pipe_w[stage][word];
            force_target_word[bit_idx] = ~force_target_word[bit_idx];
            force_dispatch(stage, word, 1'b1);
        end
    endtask

    task release_bit(input integer stage, input integer word, input integer bit_idx);
        begin
            force_dispatch(stage, word, 1'b0);
        end
    endtask

    task force_dispatch(
        input integer stage,
        input integer word,
        input logic   do_force
    );
        begin
            case ({stage[7:0], word[7:0]})
                // Stage 0
                16'h0000: if(do_force) force dut_p.pipe_w[0][0]=force_target_word; else release dut_p.pipe_w[0][0];
                16'h0001: if(do_force) force dut_p.pipe_w[0][1]=force_target_word; else release dut_p.pipe_w[0][1];
                16'h0002: if(do_force) force dut_p.pipe_w[0][2]=force_target_word; else release dut_p.pipe_w[0][2];
                16'h0003: if(do_force) force dut_p.pipe_w[0][3]=force_target_word; else release dut_p.pipe_w[0][3];
                16'h0004: if(do_force) force dut_p.pipe_w[0][4]=force_target_word; else release dut_p.pipe_w[0][4];
                16'h0005: if(do_force) force dut_p.pipe_w[0][5]=force_target_word; else release dut_p.pipe_w[0][5];
                16'h0006: if(do_force) force dut_p.pipe_w[0][6]=force_target_word; else release dut_p.pipe_w[0][6];
                16'h0007: if(do_force) force dut_p.pipe_w[0][7]=force_target_word; else release dut_p.pipe_w[0][7];
                // Stage 1
                16'h0100: if(do_force) force dut_p.pipe_w[1][0]=force_target_word; else release dut_p.pipe_w[1][0];
                16'h0101: if(do_force) force dut_p.pipe_w[1][1]=force_target_word; else release dut_p.pipe_w[1][1];
                16'h0102: if(do_force) force dut_p.pipe_w[1][2]=force_target_word; else release dut_p.pipe_w[1][2];
                16'h0103: if(do_force) force dut_p.pipe_w[1][3]=force_target_word; else release dut_p.pipe_w[1][3];
                16'h0104: if(do_force) force dut_p.pipe_w[1][4]=force_target_word; else release dut_p.pipe_w[1][4];
                16'h0105: if(do_force) force dut_p.pipe_w[1][5]=force_target_word; else release dut_p.pipe_w[1][5];
                16'h0106: if(do_force) force dut_p.pipe_w[1][6]=force_target_word; else release dut_p.pipe_w[1][6];
                16'h0107: if(do_force) force dut_p.pipe_w[1][7]=force_target_word; else release dut_p.pipe_w[1][7];
                // Stage 2
                16'h0200: if(do_force) force dut_p.pipe_w[2][0]=force_target_word; else release dut_p.pipe_w[2][0];
                16'h0201: if(do_force) force dut_p.pipe_w[2][1]=force_target_word; else release dut_p.pipe_w[2][1];
                16'h0202: if(do_force) force dut_p.pipe_w[2][2]=force_target_word; else release dut_p.pipe_w[2][2];
                16'h0203: if(do_force) force dut_p.pipe_w[2][3]=force_target_word; else release dut_p.pipe_w[2][3];
                16'h0204: if(do_force) force dut_p.pipe_w[2][4]=force_target_word; else release dut_p.pipe_w[2][4];
                16'h0205: if(do_force) force dut_p.pipe_w[2][5]=force_target_word; else release dut_p.pipe_w[2][5];
                16'h0206: if(do_force) force dut_p.pipe_w[2][6]=force_target_word; else release dut_p.pipe_w[2][6];
                16'h0207: if(do_force) force dut_p.pipe_w[2][7]=force_target_word; else release dut_p.pipe_w[2][7];
                // Stage 3
                16'h0300: if(do_force) force dut_p.pipe_w[3][0]=force_target_word; else release dut_p.pipe_w[3][0];
                16'h0301: if(do_force) force dut_p.pipe_w[3][1]=force_target_word; else release dut_p.pipe_w[3][1];
                16'h0302: if(do_force) force dut_p.pipe_w[3][2]=force_target_word; else release dut_p.pipe_w[3][2];
                16'h0303: if(do_force) force dut_p.pipe_w[3][3]=force_target_word; else release dut_p.pipe_w[3][3];
                16'h0304: if(do_force) force dut_p.pipe_w[3][4]=force_target_word; else release dut_p.pipe_w[3][4];
                16'h0305: if(do_force) force dut_p.pipe_w[3][5]=force_target_word; else release dut_p.pipe_w[3][5];
                16'h0306: if(do_force) force dut_p.pipe_w[3][6]=force_target_word; else release dut_p.pipe_w[3][6];
                16'h0307: if(do_force) force dut_p.pipe_w[3][7]=force_target_word; else release dut_p.pipe_w[3][7];
                // Stage 4
                16'h0400: if(do_force) force dut_p.pipe_w[4][0]=force_target_word; else release dut_p.pipe_w[4][0];
                16'h0401: if(do_force) force dut_p.pipe_w[4][1]=force_target_word; else release dut_p.pipe_w[4][1];
                16'h0402: if(do_force) force dut_p.pipe_w[4][2]=force_target_word; else release dut_p.pipe_w[4][2];
                16'h0403: if(do_force) force dut_p.pipe_w[4][3]=force_target_word; else release dut_p.pipe_w[4][3];
                16'h0404: if(do_force) force dut_p.pipe_w[4][4]=force_target_word; else release dut_p.pipe_w[4][4];
                16'h0405: if(do_force) force dut_p.pipe_w[4][5]=force_target_word; else release dut_p.pipe_w[4][5];
                16'h0406: if(do_force) force dut_p.pipe_w[4][6]=force_target_word; else release dut_p.pipe_w[4][6];
                16'h0407: if(do_force) force dut_p.pipe_w[4][7]=force_target_word; else release dut_p.pipe_w[4][7];
                // Stage 5
                16'h0500: if(do_force) force dut_p.pipe_w[5][0]=force_target_word; else release dut_p.pipe_w[5][0];
                16'h0501: if(do_force) force dut_p.pipe_w[5][1]=force_target_word; else release dut_p.pipe_w[5][1];
                16'h0502: if(do_force) force dut_p.pipe_w[5][2]=force_target_word; else release dut_p.pipe_w[5][2];
                16'h0503: if(do_force) force dut_p.pipe_w[5][3]=force_target_word; else release dut_p.pipe_w[5][3];
                16'h0504: if(do_force) force dut_p.pipe_w[5][4]=force_target_word; else release dut_p.pipe_w[5][4];
                16'h0505: if(do_force) force dut_p.pipe_w[5][5]=force_target_word; else release dut_p.pipe_w[5][5];
                16'h0506: if(do_force) force dut_p.pipe_w[5][6]=force_target_word; else release dut_p.pipe_w[5][6];
                16'h0507: if(do_force) force dut_p.pipe_w[5][7]=force_target_word; else release dut_p.pipe_w[5][7];
                // Stage 6
                16'h0600: if(do_force) force dut_p.pipe_w[6][0]=force_target_word; else release dut_p.pipe_w[6][0];
                16'h0601: if(do_force) force dut_p.pipe_w[6][1]=force_target_word; else release dut_p.pipe_w[6][1];
                16'h0602: if(do_force) force dut_p.pipe_w[6][2]=force_target_word; else release dut_p.pipe_w[6][2];
                16'h0603: if(do_force) force dut_p.pipe_w[6][3]=force_target_word; else release dut_p.pipe_w[6][3];
                16'h0604: if(do_force) force dut_p.pipe_w[6][4]=force_target_word; else release dut_p.pipe_w[6][4];
                16'h0605: if(do_force) force dut_p.pipe_w[6][5]=force_target_word; else release dut_p.pipe_w[6][5];
                16'h0606: if(do_force) force dut_p.pipe_w[6][6]=force_target_word; else release dut_p.pipe_w[6][6];
                16'h0607: if(do_force) force dut_p.pipe_w[6][7]=force_target_word; else release dut_p.pipe_w[6][7];
                // Stage 7
                16'h0700: if(do_force) force dut_p.pipe_w[7][0]=force_target_word; else release dut_p.pipe_w[7][0];
                16'h0701: if(do_force) force dut_p.pipe_w[7][1]=force_target_word; else release dut_p.pipe_w[7][1];
                16'h0702: if(do_force) force dut_p.pipe_w[7][2]=force_target_word; else release dut_p.pipe_w[7][2];
                16'h0703: if(do_force) force dut_p.pipe_w[7][3]=force_target_word; else release dut_p.pipe_w[7][3];
                16'h0704: if(do_force) force dut_p.pipe_w[7][4]=force_target_word; else release dut_p.pipe_w[7][4];
                16'h0705: if(do_force) force dut_p.pipe_w[7][5]=force_target_word; else release dut_p.pipe_w[7][5];
                16'h0706: if(do_force) force dut_p.pipe_w[7][6]=force_target_word; else release dut_p.pipe_w[7][6];
                16'h0707: if(do_force) force dut_p.pipe_w[7][7]=force_target_word; else release dut_p.pipe_w[7][7];
                // Stage 8
                16'h0800: if(do_force) force dut_p.pipe_w[8][0]=force_target_word; else release dut_p.pipe_w[8][0];
                16'h0801: if(do_force) force dut_p.pipe_w[8][1]=force_target_word; else release dut_p.pipe_w[8][1];
                16'h0802: if(do_force) force dut_p.pipe_w[8][2]=force_target_word; else release dut_p.pipe_w[8][2];
                16'h0803: if(do_force) force dut_p.pipe_w[8][3]=force_target_word; else release dut_p.pipe_w[8][3];
                16'h0804: if(do_force) force dut_p.pipe_w[8][4]=force_target_word; else release dut_p.pipe_w[8][4];
                16'h0805: if(do_force) force dut_p.pipe_w[8][5]=force_target_word; else release dut_p.pipe_w[8][5];
                16'h0806: if(do_force) force dut_p.pipe_w[8][6]=force_target_word; else release dut_p.pipe_w[8][6];
                16'h0807: if(do_force) force dut_p.pipe_w[8][7]=force_target_word; else release dut_p.pipe_w[8][7];
                // Stage 9
                16'h0900: if(do_force) force dut_p.pipe_w[9][0]=force_target_word; else release dut_p.pipe_w[9][0];
                16'h0901: if(do_force) force dut_p.pipe_w[9][1]=force_target_word; else release dut_p.pipe_w[9][1];
                16'h0902: if(do_force) force dut_p.pipe_w[9][2]=force_target_word; else release dut_p.pipe_w[9][2];
                16'h0903: if(do_force) force dut_p.pipe_w[9][3]=force_target_word; else release dut_p.pipe_w[9][3];
                16'h0904: if(do_force) force dut_p.pipe_w[9][4]=force_target_word; else release dut_p.pipe_w[9][4];
                16'h0905: if(do_force) force dut_p.pipe_w[9][5]=force_target_word; else release dut_p.pipe_w[9][5];
                16'h0906: if(do_force) force dut_p.pipe_w[9][6]=force_target_word; else release dut_p.pipe_w[9][6];
                16'h0907: if(do_force) force dut_p.pipe_w[9][7]=force_target_word; else release dut_p.pipe_w[9][7];
                // Stage 10
                16'h0a00: if(do_force) force dut_p.pipe_w[10][0]=force_target_word; else release dut_p.pipe_w[10][0];
                16'h0a01: if(do_force) force dut_p.pipe_w[10][1]=force_target_word; else release dut_p.pipe_w[10][1];
                16'h0a02: if(do_force) force dut_p.pipe_w[10][2]=force_target_word; else release dut_p.pipe_w[10][2];
                16'h0a03: if(do_force) force dut_p.pipe_w[10][3]=force_target_word; else release dut_p.pipe_w[10][3];
                16'h0a04: if(do_force) force dut_p.pipe_w[10][4]=force_target_word; else release dut_p.pipe_w[10][4];
                16'h0a05: if(do_force) force dut_p.pipe_w[10][5]=force_target_word; else release dut_p.pipe_w[10][5];
                16'h0a06: if(do_force) force dut_p.pipe_w[10][6]=force_target_word; else release dut_p.pipe_w[10][6];
                16'h0a07: if(do_force) force dut_p.pipe_w[10][7]=force_target_word; else release dut_p.pipe_w[10][7];
                // Stage 11
                16'h0b00: if(do_force) force dut_p.pipe_w[11][0]=force_target_word; else release dut_p.pipe_w[11][0];
                16'h0b01: if(do_force) force dut_p.pipe_w[11][1]=force_target_word; else release dut_p.pipe_w[11][1];
                16'h0b02: if(do_force) force dut_p.pipe_w[11][2]=force_target_word; else release dut_p.pipe_w[11][2];
                16'h0b03: if(do_force) force dut_p.pipe_w[11][3]=force_target_word; else release dut_p.pipe_w[11][3];
                16'h0b04: if(do_force) force dut_p.pipe_w[11][4]=force_target_word; else release dut_p.pipe_w[11][4];
                16'h0b05: if(do_force) force dut_p.pipe_w[11][5]=force_target_word; else release dut_p.pipe_w[11][5];
                16'h0b06: if(do_force) force dut_p.pipe_w[11][6]=force_target_word; else release dut_p.pipe_w[11][6];
                16'h0b07: if(do_force) force dut_p.pipe_w[11][7]=force_target_word; else release dut_p.pipe_w[11][7];
                // Stage 12
                16'h0c00: if(do_force) force dut_p.pipe_w[12][0]=force_target_word; else release dut_p.pipe_w[12][0];
                16'h0c01: if(do_force) force dut_p.pipe_w[12][1]=force_target_word; else release dut_p.pipe_w[12][1];
                16'h0c02: if(do_force) force dut_p.pipe_w[12][2]=force_target_word; else release dut_p.pipe_w[12][2];
                16'h0c03: if(do_force) force dut_p.pipe_w[12][3]=force_target_word; else release dut_p.pipe_w[12][3];
                16'h0c04: if(do_force) force dut_p.pipe_w[12][4]=force_target_word; else release dut_p.pipe_w[12][4];
                16'h0c05: if(do_force) force dut_p.pipe_w[12][5]=force_target_word; else release dut_p.pipe_w[12][5];
                16'h0c06: if(do_force) force dut_p.pipe_w[12][6]=force_target_word; else release dut_p.pipe_w[12][6];
                16'h0c07: if(do_force) force dut_p.pipe_w[12][7]=force_target_word; else release dut_p.pipe_w[12][7];
                // Stage 13
                16'h0d00: if(do_force) force dut_p.pipe_w[13][0]=force_target_word; else release dut_p.pipe_w[13][0];
                16'h0d01: if(do_force) force dut_p.pipe_w[13][1]=force_target_word; else release dut_p.pipe_w[13][1];
                16'h0d02: if(do_force) force dut_p.pipe_w[13][2]=force_target_word; else release dut_p.pipe_w[13][2];
                16'h0d03: if(do_force) force dut_p.pipe_w[13][3]=force_target_word; else release dut_p.pipe_w[13][3];
                16'h0d04: if(do_force) force dut_p.pipe_w[13][4]=force_target_word; else release dut_p.pipe_w[13][4];
                16'h0d05: if(do_force) force dut_p.pipe_w[13][5]=force_target_word; else release dut_p.pipe_w[13][5];
                16'h0d06: if(do_force) force dut_p.pipe_w[13][6]=force_target_word; else release dut_p.pipe_w[13][6];
                16'h0d07: if(do_force) force dut_p.pipe_w[13][7]=force_target_word; else release dut_p.pipe_w[13][7];
                // Stage 14
                16'h0e00: if(do_force) force dut_p.pipe_w[14][0]=force_target_word; else release dut_p.pipe_w[14][0];
                16'h0e01: if(do_force) force dut_p.pipe_w[14][1]=force_target_word; else release dut_p.pipe_w[14][1];
                16'h0e02: if(do_force) force dut_p.pipe_w[14][2]=force_target_word; else release dut_p.pipe_w[14][2];
                16'h0e03: if(do_force) force dut_p.pipe_w[14][3]=force_target_word; else release dut_p.pipe_w[14][3];
                16'h0e04: if(do_force) force dut_p.pipe_w[14][4]=force_target_word; else release dut_p.pipe_w[14][4];
                16'h0e05: if(do_force) force dut_p.pipe_w[14][5]=force_target_word; else release dut_p.pipe_w[14][5];
                16'h0e06: if(do_force) force dut_p.pipe_w[14][6]=force_target_word; else release dut_p.pipe_w[14][6];
                16'h0e07: if(do_force) force dut_p.pipe_w[14][7]=force_target_word; else release dut_p.pipe_w[14][7];
                default: $display("  [FORCE] Illegal pipe_w index stage=%0d word=%0d", stage, word);
            endcase
        end
    endtask

    // =========================================================================
    // DIFFERENTIAL ANALYSIS
    // FIX: added $isunknown guard so that a timed-out (X) faulted capture
    // is NOT miscounted as "fault propagated".
    // =========================================================================
    task automatic diff_analysis(
        input  integer n_rk,
        output integer affected_count,
        output integer bit_sum,
        output integer final_rk_affected
    );
        integer idx, b;
        logic [127:0] d;
        begin
            affected_count   = 0;
            bit_sum          = 0;
            final_rk_affected = 0;
            for (idx = 0; idx < n_rk; idx = idx + 1) begin
                d = golden_capture[idx] ^ faulted_capture[idx];
                // FIX: skip X/Z values - a timeout-induced X on faulted_capture
                // would produce d=X, and (X !== 0) is TRUE, falsely counting
                // the fault as propagated.
                if (d !== 128'h0 && !$isunknown(d) && !$isunknown(faulted_capture[idx])) begin
                    affected_count = affected_count + 1;
                    for (b = 0; b < 128; b = b + 1)
                        if (d[b]) bit_sum = bit_sum + 1;
                    if (idx == n_rk - 1) final_rk_affected = 1;
                end
            end
        end
    endtask

    // =========================================================================
    // FAULT CAMPAIGN DRIVER (per mode)
    // Sweeps (stage, word, bit) using BIT_STRIDE to bound runtime.
    // Per-mode stage/word limits match the pipelined DUT's live regions:
    //   AES-128: stages 0..10, words 0..3
    //   AES-192: stages 0..8,  words 0..5
    //   AES-256: stages 0..7,  words 0..7
    //
    // injection_cycle = fault_stage + 1:
    //   Stage s becomes valid 1 clock after valid_in is deasserted (stage 0
    //   data is latched on that same clock), then each subsequent stage adds
    //   one more clock.  Injecting at clock (s+1) after deassert places the
    //   force exactly on the cycle stage s's pipe_w is freshly valid.
    // =========================================================================
    task automatic run_fault_campaign(
        input  string      label,
        input  logic [1:0] ksize,
        input  logic [255:0] kin,
        input  integer     n_rk,
        input  integer     max_stage,
        input  integer     max_word,
        output integer     points_total,
        output integer     points_hit
    );
        integer s, w, b;
        integer affected, bitsum, final_hit;
        integer local_faults, local_prop, local_full;
        begin
            points_total = 0;
            points_hit   = 0;
            local_faults = 0;
            local_prop   = 0;
            local_full   = 0;

            $display("\n  -- Fault campaign: %s (stages 0..%0d, words 0..%0d, stride=%0d) --",
                      label, max_stage, max_word, BIT_STRIDE);

            // Golden reference (single capture, reused for entire mode sweep)
            capture_pipelined_stream(ksize, kin, n_rk);

            for (s = 0; s <= max_stage; s = s + 1) begin
                for (w = 0; w <= max_word; w = w + 1) begin
                    points_total = points_total + (32 / BIT_STRIDE + 1);
                    for (b = 0; b < 32; b = b + BIT_STRIDE) begin
                        points_hit = points_hit + 1;

                        inject_fault_and_capture(
                            ksize, kin, n_rk,
                            s, w, b,
                            s       // FIX: injection_cycle=s so force is active
                                    // while pipe_valid[s]=1 (not one clock too late)
                        );

                        diff_analysis(n_rk, affected, bitsum, final_hit);

                        local_faults++;
                        total_faults_injected++;

                        if (affected > 0) begin
                            local_prop++;
                            total_faults_propagated++;
                            total_diff_bits_sum     += bitsum;
                            total_affected_rk_count += affected;
                            if (final_hit) begin
                                local_full++;
                                total_faults_full_diff++;
                            end
                            $display("    FAULT s=%0d w=%0d b=%0d: %0d/%0d RKs affected, %0d bits, %s",
                                     s, w, b, affected, n_rk, bitsum,
                                     final_hit ? "FULL_DIFFUSION" : "CONTAINED");
                        end else begin
                            $display("    FAULT s=%0d w=%0d b=%0d: NO PROPAGATION", s, w, b);
                        end
                    end
                end
            end

            $display("  [%s] faults=%0d  propagated=%0d (%.1f%%)  full_diff=%0d (%.1f%%)",
                      label, local_faults,
                      local_prop,  (local_faults>0) ? real'(local_prop)*100.0/real'(local_faults)  : 0.0,
                      local_full,  (local_faults>0) ? real'(local_full)*100.0/real'(local_faults)  : 0.0);
        end
    endtask

    // =========================================================================
    // MAIN: top-level initial block
    // =========================================================================
    initial begin
        // Initialise
        rst_n    = 0;
        valid_in = 0;
        key_in   = '0;
        key_size = 2'b00;

        $display("\n================================================================================");
        $display("AES KEY EXPANSION - FAULT INJECTION & DIFFERENTIAL ANALYSIS TESTBENCH");
        $display("Specs   : 128/192/256-bit key schedules, pipelined rounds");
        $display("Analysis: fault propagation rate, key schedule correctness, security coverage");
        $display("================================================================================");
        $display("[SIM START] @ %0t ns", $time);

        repeat(4) @(posedge clk);
        rst_n = 1;
        repeat(4) @(posedge clk);

        // =====================================================================
        // STEP 1: Baseline correctness (NIST FIPS 197 KAT)
        // Populate gold_stage staging array for each mode and call run_baseline.
        // =====================================================================
        $display("\n================================================================================");
        $display("STEP 1: KEY SCHEDULE CORRECTNESS BASELINE (NIST FIPS 197 KAT, both DUTs)");
        $display("================================================================================");

        // AES-128
        for (int i=0; i<=10; i++) gold_stage[i] = gold128[i];
        for (int i=11; i<=14; i++) gold_stage[i] = 128'h0;
        run_baseline("AES-128", 2'b00, {128'h0, KEY128}, 10, 10);

        // AES-192
        for (int i=0; i<=12; i++) gold_stage[i] = gold192[i];
        for (int i=13; i<=14; i++) gold_stage[i] = 128'h0;
        run_baseline("AES-192", 2'b01, {64'h0, KEY192}, 12, 12);

        // AES-256
        for (int i=0; i<=14; i++) gold_stage[i] = gold256[i];
        run_baseline("AES-256", 2'b10, KEY256, 14, 14);

        $display("\n[Baseline Summary] errors=%0d/%0d  %s",
                  baseline_errors, baseline_checks,
                  (baseline_errors==0) ? "PASS" : "FAIL - fault campaign ABORTED (results would be meaningless)");

        if (baseline_errors != 0) begin
            $display("\n================================================================================");
            $display("FINAL REPORT: ABORTED due to baseline correctness failures.");
            $display("================================================================================");
            $finish;
        end

        // =====================================================================
        // STEP 2 & 3: Fault injection campaigns
        // =====================================================================
        $display("\n================================================================================");
        $display("STEP 2: FAULT INJECTION & DIFFERENTIAL ANALYSIS");
        $display("================================================================================");

        // AES-128 campaign
        run_fault_campaign(
            "AES-128", 2'b00, {128'h0, KEY128}, 10,
            10,  // max_stage (stages 0..10)
            3,   // max_word  (words 0..3)
            coverage_points_total_128, coverage_points_hit_128
        );

        // AES-192 campaign
        run_fault_campaign(
            "AES-192", 2'b01, {64'h0, KEY192}, 13,
            8,   // max_stage (stages 0..8)
            5,   // max_word  (words 0..5)
            coverage_points_total_192, coverage_points_hit_192
        );

        // AES-256 campaign
        run_fault_campaign(
            "AES-256", 2'b10, KEY256, 14,
            7,   // max_stage (stages 0..7)
            7,   // max_word  (words 0..7)
            coverage_points_total_256, coverage_points_hit_256
        );

        // =====================================================================
        // FINAL REPORT
        // =====================================================================
        $display("\n================================================================================");
        $display("FINAL REPORT");
        $display("================================================================================");
        $display("  Total faults injected  : %0d", total_faults_injected);
        $display("  Faults propagated      : %0d  (%.1f%%)",
                  total_faults_propagated,
                  (total_faults_injected>0) ?
                      real'(total_faults_propagated)*100.0/real'(total_faults_injected) : 0.0);
        $display("  Faults full-diffusion  : %0d  (%.1f%%)",
                  total_faults_full_diff,
                  (total_faults_injected>0) ?
                      real'(total_faults_full_diff)*100.0/real'(total_faults_injected) : 0.0);
        $display("  Avg affected RKs/fault : %.2f",
                  (total_faults_propagated>0) ?
                      real'(total_affected_rk_count)/real'(total_faults_propagated) : 0.0);
        $display("  Avg Hamming weight/RK  : %.2f",
                  (total_affected_rk_count>0) ?
                      real'(total_diff_bits_sum)/real'(total_affected_rk_count) : 0.0);

        $display("\n  Security Coverage:");
        $display("  AES-128: %0d / %0d fault points exercised (%.1f%%)",
                  coverage_points_hit_128, coverage_points_total_128,
                  (coverage_points_total_128>0) ?
                      real'(coverage_points_hit_128)*100.0/real'(coverage_points_total_128) : 0.0);
        $display("  AES-192: %0d / %0d fault points exercised (%.1f%%)",
                  coverage_points_hit_192, coverage_points_total_192,
                  (coverage_points_total_192>0) ?
                      real'(coverage_points_hit_192)*100.0/real'(coverage_points_total_192) : 0.0);
        $display("  AES-256: %0d / %0d fault points exercised (%.1f%%)",
                  coverage_points_hit_256, coverage_points_total_256,
                  (coverage_points_total_256>0) ?
                      real'(coverage_points_hit_256)*100.0/real'(coverage_points_total_256) : 0.0);

        $display("\n================================================================================");
        $display("[SIM END] @ %0t ns", $time);
        $display("================================================================================");
        $finish;
    end

endmodule
