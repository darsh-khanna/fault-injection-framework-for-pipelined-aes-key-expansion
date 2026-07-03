`timescale 1ns / 1ps

// =============================================================================
// AES Key Expansion - Pipelined  (v8 - XSim fix)
// Supports AES-128 (key_size=2'b00), AES-192 (key_size=2'b01), AES-256 (2'b10)
//
// Key input packing convention:
//   AES-128: key_in[127:0]   = W[0..3],   key_in[255:128] unused
//   AES-192: key_in[191:0]   = W[0..5],   key_in[255:192] unused
//            key_in[191:160]=W[0] ... key_in[31:0]=W[5]
//   AES-256: key_in[255:0]   = W[0..7]
//            key_in[255:224]=W[0] ... key_in[31:0]=W[7]
//
// FIX HISTORY
// -----------
// v1-v6: key schedule output mechanism; v7 added FIFO for back-to-back loads.
//
// v8 (this file) - XSIM void-function / output-argument BUG (CRITICAL):
//   ROOT CAUSE: v7 used three `automatic void function` helpers -
//   expand_128, expand_192, expand_256 - each declared with
//   `output logic [31:0]` ports and called from inside the `always_ff`
//   pipeline expansion loop with multi-dimensional array elements
//   (pipe_w[i][j]) as the actual output arguments.
//
//   Xilinx XSim does NOT correctly write back the 32-bit output ports to
//   unpacked array element lvalues when the function is called from
//   always_ff.  It silently truncates the write to the lowest 8 bits,
//   leaving bits [31:8] at their reset value of zero.  The result is that
//   every computed pipeline word only has its LSByte correct - exactly the
//   pattern seen in the simulation log:
//
//     RK01 got=00000017_000000b1_00000039_00000005
//     RK01 exp=a0fafe17_88542cb1_23a33939_2a6c7605
//
//   FIX: remove expand_128/192/256 void functions entirely.  Replace with a
//   dedicated always_comb block that writes computed words into a module-
//   level intermediate array (nxt_w[1:14][0:7]) using standard blocking
//   assignments - no output-argument mechanics, no automatic-in-always_ff
//   hazards.  The always_ff loop for stages 1..14 then becomes a simple
//   row of non-blocking `<=` registrations from nxt_w[i][w], which XSim
//   handles without any issue.  All other logic (FIFO, push mux, stage 0
//   key load) is unchanged from v7.
// =============================================================================

module aes_key_expansion_pipelined (
    input  logic         clk,
    input  logic         rst_n,
    input  logic [255:0] key_in,
    input  logic [1:0]   key_size,       // 00=128, 01=192, 10=256
    input  logic         key_valid_in,
    output logic [127:0] round_key_out,
    output logic         key_valid_out,
    output logic         fifo_overflow
);

    // =========================================================================
    // PIPELINE STORAGE
    // 15 stages (0..14), 8 words each.
    // AES-128: stages 0..10 active, words 0..3 live (4..7 zero)
    // AES-192: stages 0..8  active, words 0..5 live (6..7 zero)
    // AES-256: stages 0..7  active, words 0..7 all live
    // =========================================================================
    logic [31:0] pipe_w     [0:14][0:7];
    logic [1:0]  pipe_size  [0:14];
    logic        pipe_valid [0:14];
    logic [3:0]  pipe_round [0:14];

    // =========================================================================
    // INTERMEDIATE COMBINATIONAL STAGE WORDS  (NEW v8)
    // nxt_w[i][w] holds the fully-computed word that will be registered into
    // pipe_w[i][w] on the next clock edge.  Computed in always_comb below,
    // registered in always_ff via clean non-blocking assignments - no
    // void-function / output-argument mechanics.
    // =========================================================================
    logic [31:0] nxt_w [1:14][0:7];

    // =========================================================================
    // OUTPUT FIFO
    // Depth 64 entries of 128 bits.  Push rate ≤ 2/clock (AES-192/256 can
    // complete 2 round keys per stage).  Pop rate = 1/clock.
    // =========================================================================
    localparam int FIFO_DEPTH  = 64;
    localparam int FIFO_AWIDTH = 6;   // log2(64)

    logic [127:0]         fifo_mem [0:FIFO_DEPTH-1];
    logic [FIFO_AWIDTH:0] fifo_wr_ptr;
    logic [FIFO_AWIDTH:0] fifo_rd_ptr;

    wire fifo_empty = (fifo_wr_ptr == fifo_rd_ptr);

    logic        push0_en,   push1_en;
    logic [127:0] push0_data, push1_data;

    // =========================================================================
    // AES S-BOX (FIPS 197 verified)
    // =========================================================================
    function automatic [7:0] sbox_byte(input logic [7:0] a);
        case (a)
            8'h00: sbox_byte=8'h63; 8'h01: sbox_byte=8'h7c; 8'h02: sbox_byte=8'h77; 8'h03: sbox_byte=8'h7b;
            8'h04: sbox_byte=8'hf2; 8'h05: sbox_byte=8'h6b; 8'h06: sbox_byte=8'h6f; 8'h07: sbox_byte=8'hc5;
            8'h08: sbox_byte=8'h30; 8'h09: sbox_byte=8'h01; 8'h0a: sbox_byte=8'h67; 8'h0b: sbox_byte=8'h2b;
            8'h0c: sbox_byte=8'hfe; 8'h0d: sbox_byte=8'hd7; 8'h0e: sbox_byte=8'hab; 8'h0f: sbox_byte=8'h76;
            8'h10: sbox_byte=8'hca; 8'h11: sbox_byte=8'h82; 8'h12: sbox_byte=8'hc9; 8'h13: sbox_byte=8'h7d;
            8'h14: sbox_byte=8'hfa; 8'h15: sbox_byte=8'h59; 8'h16: sbox_byte=8'h47; 8'h17: sbox_byte=8'hf0;
            8'h18: sbox_byte=8'had; 8'h19: sbox_byte=8'hd4; 8'h1a: sbox_byte=8'ha2; 8'h1b: sbox_byte=8'haf;
            8'h1c: sbox_byte=8'h9c; 8'h1d: sbox_byte=8'ha4; 8'h1e: sbox_byte=8'h72; 8'h1f: sbox_byte=8'hc0;
            8'h20: sbox_byte=8'hb7; 8'h21: sbox_byte=8'hfd; 8'h22: sbox_byte=8'h93; 8'h23: sbox_byte=8'h26;
            8'h24: sbox_byte=8'h36; 8'h25: sbox_byte=8'h3f; 8'h26: sbox_byte=8'hf7; 8'h27: sbox_byte=8'hcc;
            8'h28: sbox_byte=8'h34; 8'h29: sbox_byte=8'ha5; 8'h2a: sbox_byte=8'he5; 8'h2b: sbox_byte=8'hf1;
            8'h2c: sbox_byte=8'h71; 8'h2d: sbox_byte=8'hd8; 8'h2e: sbox_byte=8'h31; 8'h2f: sbox_byte=8'h15;
            8'h30: sbox_byte=8'h04; 8'h31: sbox_byte=8'hc7; 8'h32: sbox_byte=8'h23; 8'h33: sbox_byte=8'hc3;
            8'h34: sbox_byte=8'h18; 8'h35: sbox_byte=8'h96; 8'h36: sbox_byte=8'h05; 8'h37: sbox_byte=8'h9a;
            8'h38: sbox_byte=8'h07; 8'h39: sbox_byte=8'h12; 8'h3a: sbox_byte=8'h80; 8'h3b: sbox_byte=8'he2;
            8'h3c: sbox_byte=8'heb; 8'h3d: sbox_byte=8'h27; 8'h3e: sbox_byte=8'hb2; 8'h3f: sbox_byte=8'h75;
            8'h40: sbox_byte=8'h09; 8'h41: sbox_byte=8'h83; 8'h42: sbox_byte=8'h2c; 8'h43: sbox_byte=8'h1a;
            8'h44: sbox_byte=8'h1b; 8'h45: sbox_byte=8'h6e; 8'h46: sbox_byte=8'h5a; 8'h47: sbox_byte=8'ha0;
            8'h48: sbox_byte=8'h52; 8'h49: sbox_byte=8'h3b; 8'h4a: sbox_byte=8'hd6; 8'h4b: sbox_byte=8'hb3;
            8'h4c: sbox_byte=8'h29; 8'h4d: sbox_byte=8'he3; 8'h4e: sbox_byte=8'h2f; 8'h4f: sbox_byte=8'h84;
            8'h50: sbox_byte=8'h53; 8'h51: sbox_byte=8'hd1; 8'h52: sbox_byte=8'h00; 8'h53: sbox_byte=8'hed;
            8'h54: sbox_byte=8'h20; 8'h55: sbox_byte=8'hfc; 8'h56: sbox_byte=8'hb1; 8'h57: sbox_byte=8'h5b;
            8'h58: sbox_byte=8'h6a; 8'h59: sbox_byte=8'hcb; 8'h5a: sbox_byte=8'hbe; 8'h5b: sbox_byte=8'h39;
            8'h5c: sbox_byte=8'h4a; 8'h5d: sbox_byte=8'h4c; 8'h5e: sbox_byte=8'h58; 8'h5f: sbox_byte=8'hcf;
            8'h60: sbox_byte=8'hd0; 8'h61: sbox_byte=8'hef; 8'h62: sbox_byte=8'haa; 8'h63: sbox_byte=8'hfb;
            8'h64: sbox_byte=8'h43; 8'h65: sbox_byte=8'h4d; 8'h66: sbox_byte=8'h33; 8'h67: sbox_byte=8'h85;
            8'h68: sbox_byte=8'h45; 8'h69: sbox_byte=8'hf9; 8'h6a: sbox_byte=8'h02; 8'h6b: sbox_byte=8'h7f;
            8'h6c: sbox_byte=8'h50; 8'h6d: sbox_byte=8'h3c; 8'h6e: sbox_byte=8'h9f; 8'h6f: sbox_byte=8'ha8;
            8'h70: sbox_byte=8'h51; 8'h71: sbox_byte=8'ha3; 8'h72: sbox_byte=8'h40; 8'h73: sbox_byte=8'h8f;
            8'h74: sbox_byte=8'h92; 8'h75: sbox_byte=8'h9d; 8'h76: sbox_byte=8'h38; 8'h77: sbox_byte=8'hf5;
            8'h78: sbox_byte=8'hbc; 8'h79: sbox_byte=8'hb6; 8'h7a: sbox_byte=8'hda; 8'h7b: sbox_byte=8'h21;
            8'h7c: sbox_byte=8'h10; 8'h7d: sbox_byte=8'hff; 8'h7e: sbox_byte=8'hf3; 8'h7f: sbox_byte=8'hd2;
            8'h80: sbox_byte=8'hcd; 8'h81: sbox_byte=8'h0c; 8'h82: sbox_byte=8'h13; 8'h83: sbox_byte=8'hec;
            8'h84: sbox_byte=8'h5f; 8'h85: sbox_byte=8'h97; 8'h86: sbox_byte=8'h44; 8'h87: sbox_byte=8'h17;
            8'h88: sbox_byte=8'hc4; 8'h89: sbox_byte=8'ha7; 8'h8a: sbox_byte=8'h7e; 8'h8b: sbox_byte=8'h3d;
            8'h8c: sbox_byte=8'h64; 8'h8d: sbox_byte=8'h5d; 8'h8e: sbox_byte=8'h19; 8'h8f: sbox_byte=8'h73;
            8'h90: sbox_byte=8'h60; 8'h91: sbox_byte=8'h81; 8'h92: sbox_byte=8'h4f; 8'h93: sbox_byte=8'hdc;
            8'h94: sbox_byte=8'h22; 8'h95: sbox_byte=8'h2a; 8'h96: sbox_byte=8'h90; 8'h97: sbox_byte=8'h88;
            8'h98: sbox_byte=8'h46; 8'h99: sbox_byte=8'hee; 8'h9a: sbox_byte=8'hb8; 8'h9b: sbox_byte=8'h14;
            8'h9c: sbox_byte=8'hde; 8'h9d: sbox_byte=8'h5e; 8'h9e: sbox_byte=8'h0b; 8'h9f: sbox_byte=8'hdb;
            8'ha0: sbox_byte=8'he0; 8'ha1: sbox_byte=8'h32; 8'ha2: sbox_byte=8'h3a; 8'ha3: sbox_byte=8'h0a;
            8'ha4: sbox_byte=8'h49; 8'ha5: sbox_byte=8'h06; 8'ha6: sbox_byte=8'h24; 8'ha7: sbox_byte=8'h5c;
            8'ha8: sbox_byte=8'hc2; 8'ha9: sbox_byte=8'hd3; 8'haa: sbox_byte=8'hac; 8'hab: sbox_byte=8'h62;
            8'hac: sbox_byte=8'h91; 8'had: sbox_byte=8'h95; 8'hae: sbox_byte=8'he4; 8'haf: sbox_byte=8'h79;
            8'hb0: sbox_byte=8'he7; 8'hb1: sbox_byte=8'hc8; 8'hb2: sbox_byte=8'h37; 8'hb3: sbox_byte=8'h6d;
            8'hb4: sbox_byte=8'h8d; 8'hb5: sbox_byte=8'hd5; 8'hb6: sbox_byte=8'h4e; 8'hb7: sbox_byte=8'ha9;
            8'hb8: sbox_byte=8'h6c; 8'hb9: sbox_byte=8'h56; 8'hba: sbox_byte=8'hf4; 8'hbb: sbox_byte=8'hea;
            8'hbc: sbox_byte=8'h65; 8'hbd: sbox_byte=8'h7a; 8'hbe: sbox_byte=8'hae; 8'hbf: sbox_byte=8'h08;
            8'hc0: sbox_byte=8'hba; 8'hc1: sbox_byte=8'h78; 8'hc2: sbox_byte=8'h25; 8'hc3: sbox_byte=8'h2e;
            8'hc4: sbox_byte=8'h1c; 8'hc5: sbox_byte=8'ha6; 8'hc6: sbox_byte=8'hb4; 8'hc7: sbox_byte=8'hc6;
            8'hc8: sbox_byte=8'he8; 8'hc9: sbox_byte=8'hdd; 8'hca: sbox_byte=8'h74; 8'hcb: sbox_byte=8'h1f;
            8'hcc: sbox_byte=8'h4b; 8'hcd: sbox_byte=8'hbd; 8'hce: sbox_byte=8'h8b; 8'hcf: sbox_byte=8'h8a;
            8'hd0: sbox_byte=8'h70; 8'hd1: sbox_byte=8'h3e; 8'hd2: sbox_byte=8'hb5; 8'hd3: sbox_byte=8'h66;
            8'hd4: sbox_byte=8'h48; 8'hd5: sbox_byte=8'h03; 8'hd6: sbox_byte=8'hf6; 8'hd7: sbox_byte=8'h0e;
            8'hd8: sbox_byte=8'h61; 8'hd9: sbox_byte=8'h35; 8'hda: sbox_byte=8'h57; 8'hdb: sbox_byte=8'hb9;
            8'hdc: sbox_byte=8'h86; 8'hdd: sbox_byte=8'hc1; 8'hde: sbox_byte=8'h1d; 8'hdf: sbox_byte=8'h9e;
            8'he0: sbox_byte=8'he1; 8'he1: sbox_byte=8'hf8; 8'he2: sbox_byte=8'h98; 8'he3: sbox_byte=8'h11;
            8'he4: sbox_byte=8'h69; 8'he5: sbox_byte=8'hd9; 8'he6: sbox_byte=8'h8e; 8'he7: sbox_byte=8'h94;
            8'he8: sbox_byte=8'h9b; 8'he9: sbox_byte=8'h1e; 8'hea: sbox_byte=8'h87; 8'heb: sbox_byte=8'he9;
            8'hec: sbox_byte=8'hce; 8'hed: sbox_byte=8'h55; 8'hee: sbox_byte=8'h28; 8'hef: sbox_byte=8'hdf;
            8'hf0: sbox_byte=8'h8c; 8'hf1: sbox_byte=8'ha1; 8'hf2: sbox_byte=8'h89; 8'hf3: sbox_byte=8'h0d;
            8'hf4: sbox_byte=8'hbf; 8'hf5: sbox_byte=8'he6; 8'hf6: sbox_byte=8'h42; 8'hf7: sbox_byte=8'h68;
            8'hf8: sbox_byte=8'h41; 8'hf9: sbox_byte=8'h99; 8'hfa: sbox_byte=8'h2d; 8'hfb: sbox_byte=8'h0f;
            8'hfc: sbox_byte=8'hb0; 8'hfd: sbox_byte=8'h54; 8'hfe: sbox_byte=8'hbb; 8'hff: sbox_byte=8'h16;
            default: sbox_byte=8'h00;
        endcase
    endfunction

    function automatic [31:0] subword(input logic [31:0] word);
        subword = {sbox_byte(word[31:24]), sbox_byte(word[23:16]),
                   sbox_byte(word[15:8]),  sbox_byte(word[7:0])};
    endfunction

    function automatic [31:0] rotword(input logic [31:0] word);
        rotword = {word[23:16], word[15:8], word[7:0], word[31:24]};
    endfunction

    function automatic [31:0] rcon(input logic [3:0] round);
        case (round)
            4'h1: rcon=32'h01000000; 4'h2: rcon=32'h02000000;
            4'h3: rcon=32'h04000000; 4'h4: rcon=32'h08000000;
            4'h5: rcon=32'h10000000; 4'h6: rcon=32'h20000000;
            4'h7: rcon=32'h40000000; 4'h8: rcon=32'h80000000;
            4'h9: rcon=32'h1b000000; 4'ha: rcon=32'h36000000;
            default: rcon=32'h00000000;
        endcase
    endfunction

    // =========================================================================
    // COMBINATIONAL STAGE EXPANSION  (NEW v8 - replaces void function calls)
    //
    // Each iteration i (1..14) computes the next values for pipeline stage i
    // from the CURRENT registered values of stage (i-1).  Blocking `=`
    // assignments within always_comb are immediately visible to dependent
    // statements in the same iteration (e.g. nxt_w[i][1] = ... ^ nxt_w[i][0]
    // correctly uses the nxt_w[i][0] just computed above it).  There is NO
    // cross-stage dependency: nxt_w[i] depends only on pipe_w[i-1] (registers)
    // and pipe_size/pipe_round[i-1] (registers), never on nxt_w[i±1].
    //
    // AES-128: 4-word chain using RotWord/SubWord on last word of previous stage
    // AES-192: 6-word chain using RotWord/SubWord on word[5] of previous stage
    // AES-256: 4-word chain then SubWord-only on word[3] for second 4-word chain
    // =========================================================================
    always_comb begin
        for (int i = 1; i <= 14; i++) begin

            // Default all words to zero; live words are overwritten below.
            for (int w = 0; w < 8; w++) nxt_w[i][w] = 32'h0;

            case (pipe_size[i-1])

                // ---------------------------------------------------------
                // AES-128  (Nk=4, Nr=10, stages 0..10 active)
                // ---------------------------------------------------------
                2'b00: begin
                    nxt_w[i][0] = pipe_w[i-1][0]
                                  ^ subword(rotword(pipe_w[i-1][3]))
                                  ^ rcon(pipe_round[i-1]);
                    nxt_w[i][1] = pipe_w[i-1][1] ^ nxt_w[i][0];
                    nxt_w[i][2] = pipe_w[i-1][2] ^ nxt_w[i][1];
                    nxt_w[i][3] = pipe_w[i-1][3] ^ nxt_w[i][2];
                    // words 4..7 stay 0 (unused for AES-128)
                end

                // ---------------------------------------------------------
                // AES-192  (Nk=6, Nr=12, stages 0..8 active)
                // ---------------------------------------------------------
                2'b01: begin
                    nxt_w[i][0] = pipe_w[i-1][0]
                                  ^ subword(rotword(pipe_w[i-1][5]))
                                  ^ rcon(pipe_round[i-1]);
                    nxt_w[i][1] = pipe_w[i-1][1] ^ nxt_w[i][0];
                    nxt_w[i][2] = pipe_w[i-1][2] ^ nxt_w[i][1];
                    nxt_w[i][3] = pipe_w[i-1][3] ^ nxt_w[i][2];
                    nxt_w[i][4] = pipe_w[i-1][4] ^ nxt_w[i][3];
                    nxt_w[i][5] = pipe_w[i-1][5] ^ nxt_w[i][4];
                    // words 6..7 stay 0 (unused for AES-192)
                end

                // ---------------------------------------------------------
                // AES-256  (Nk=8, Nr=14, stages 0..7 active)
                // First 4 words use RotWord/SubWord; next 4 use SubWord only
                // ---------------------------------------------------------
                default: begin
                    nxt_w[i][0] = pipe_w[i-1][0]
                                  ^ subword(rotword(pipe_w[i-1][7]))
                                  ^ rcon(pipe_round[i-1]);
                    nxt_w[i][1] = pipe_w[i-1][1] ^ nxt_w[i][0];
                    nxt_w[i][2] = pipe_w[i-1][2] ^ nxt_w[i][1];
                    nxt_w[i][3] = pipe_w[i-1][3] ^ nxt_w[i][2];
                    nxt_w[i][4] = pipe_w[i-1][4] ^ subword(nxt_w[i][3]);
                    nxt_w[i][5] = pipe_w[i-1][5] ^ nxt_w[i][4];
                    nxt_w[i][6] = pipe_w[i-1][6] ^ nxt_w[i][5];
                    nxt_w[i][7] = pipe_w[i-1][7] ^ nxt_w[i][6];
                end

            endcase
        end
    end

    // =========================================================================
    // PIPELINE REGISTERS
    // Stage 0: direct key load.
    // Stages 1..14: register nxt_w[] via clean non-blocking <= assignments.
    //   No void functions, no output-argument write-backs.
    // =========================================================================
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            for (int s = 0; s <= 14; s++) begin
                pipe_valid[s] <= 1'b0;
                pipe_size[s]  <= 2'b00;
                pipe_round[s] <= 4'd0;
                for (int w = 0; w < 8; w++) pipe_w[s][w] <= 32'h0;
            end
        end else begin

            // ---- Stage 0: latch incoming key --------------------------------
            pipe_valid[0] <= key_valid_in;
            pipe_size[0]  <= key_size;
            pipe_round[0] <= 4'd1;

            if (key_valid_in) begin
                case (key_size)
                    2'b00: begin   // AES-128
                        pipe_w[0][0] <= key_in[127:96];
                        pipe_w[0][1] <= key_in[95:64];
                        pipe_w[0][2] <= key_in[63:32];
                        pipe_w[0][3] <= key_in[31:0];
                        pipe_w[0][4] <= 32'h0; pipe_w[0][5] <= 32'h0;
                        pipe_w[0][6] <= 32'h0; pipe_w[0][7] <= 32'h0;
                    end
                    2'b01: begin   // AES-192
                        pipe_w[0][0] <= key_in[191:160];
                        pipe_w[0][1] <= key_in[159:128];
                        pipe_w[0][2] <= key_in[127:96];
                        pipe_w[0][3] <= key_in[95:64];
                        pipe_w[0][4] <= key_in[63:32];
                        pipe_w[0][5] <= key_in[31:0];
                        pipe_w[0][6] <= 32'h0; pipe_w[0][7] <= 32'h0;
                    end
                    default: begin // AES-256
                        pipe_w[0][0] <= key_in[255:224];
                        pipe_w[0][1] <= key_in[223:192];
                        pipe_w[0][2] <= key_in[191:160];
                        pipe_w[0][3] <= key_in[159:128];
                        pipe_w[0][4] <= key_in[127:96];
                        pipe_w[0][5] <= key_in[95:64];
                        pipe_w[0][6] <= key_in[63:32];
                        pipe_w[0][7] <= key_in[31:0];
                    end
                endcase
            end

            // ---- Stages 1..14: register from combinational nxt_w -----------
            // FIX v8: simple non-blocking registrations - no void function
            // calls, no output-argument mechanics, no XSim truncation hazard.
            for (int i = 1; i <= 14; i++) begin
                pipe_valid[i] <= pipe_valid[i-1];
                pipe_size[i]  <= pipe_size[i-1];
                pipe_round[i] <= pipe_round[i-1] + 4'd1;
                for (int w = 0; w < 8; w++)
                    pipe_w[i][w] <= nxt_w[i][w];
            end

        end
    end

    // =========================================================================
    // OUTPUT FIFO PUSH LOGIC (unchanged from v7)
    //
    // Computed combinationally from CURRENT pipe_w/pipe_valid so that each
    // round key is captured at the exact clock its source data is valid,
    // before the pipeline register update can overwrite it.
    //
    // Per-mode push map (each condition is mutually exclusive via else-if):
    //
    //   AES-128: pipe_valid[1..10] → push RK01..RK10 (1 push each)
    //
    //   AES-192 straddling map:
    //     pipe_valid[0] → push RK00 = w[0][0..3]
    //     pipe_valid[1] → push RK01 = {w[0][4..5], w[1][0..1]},
    //                     push RK02 = w[1][2..5]
    //     pipe_valid[2] → push RK03 = w[2][0..3]
    //     pipe_valid[3] → push RK04 = {w[2][4..5], w[3][0..1]},
    //                     push RK05 = w[3][2..5]
    //     pipe_valid[4] → push RK06 = w[4][0..3]
    //     pipe_valid[5] → push RK07 = {w[4][4..5], w[5][0..1]},
    //                     push RK08 = w[5][2..5]
    //     pipe_valid[6] → push RK09 = w[6][0..3]
    //     pipe_valid[7] → push RK10 = {w[6][4..5], w[7][0..1]},
    //                     push RK11 = w[7][2..5]
    //     pipe_valid[8] → push RK12 = w[8][0..3]
    //
    //   AES-256:
    //     pipe_valid[0] → push RK01 = w[0][4..7]
    //     pipe_valid[1] → push RK02 = w[1][0..3], RK03 = w[1][4..7]
    //     pipe_valid[2] → push RK04 = w[2][0..3], RK05 = w[2][4..7]
    //     pipe_valid[3] → push RK06 = w[3][0..3], RK07 = w[3][4..7]
    //     pipe_valid[4] → push RK08 = w[4][0..3], RK09 = w[4][4..7]
    //     pipe_valid[5] → push RK10 = w[5][0..3], RK11 = w[5][4..7]
    //     pipe_valid[6] → push RK12 = w[6][0..3], RK13 = w[6][4..7]
    //     pipe_valid[7] → push RK14 = w[7][0..3]
    // =========================================================================
    always_comb begin
        push0_en   = 1'b0;  push1_en   = 1'b0;
        push0_data = 128'h0; push1_data = 128'h0;

        // ---- AES-128 ----
        if      (pipe_valid[1]  && pipe_size[1]  == 2'b00) begin push0_en=1; push0_data={pipe_w[1][0], pipe_w[1][1], pipe_w[1][2], pipe_w[1][3]}; end
        else if (pipe_valid[2]  && pipe_size[2]  == 2'b00) begin push0_en=1; push0_data={pipe_w[2][0], pipe_w[2][1], pipe_w[2][2], pipe_w[2][3]}; end
        else if (pipe_valid[3]  && pipe_size[3]  == 2'b00) begin push0_en=1; push0_data={pipe_w[3][0], pipe_w[3][1], pipe_w[3][2], pipe_w[3][3]}; end
        else if (pipe_valid[4]  && pipe_size[4]  == 2'b00) begin push0_en=1; push0_data={pipe_w[4][0], pipe_w[4][1], pipe_w[4][2], pipe_w[4][3]}; end
        else if (pipe_valid[5]  && pipe_size[5]  == 2'b00) begin push0_en=1; push0_data={pipe_w[5][0], pipe_w[5][1], pipe_w[5][2], pipe_w[5][3]}; end
        else if (pipe_valid[6]  && pipe_size[6]  == 2'b00) begin push0_en=1; push0_data={pipe_w[6][0], pipe_w[6][1], pipe_w[6][2], pipe_w[6][3]}; end
        else if (pipe_valid[7]  && pipe_size[7]  == 2'b00) begin push0_en=1; push0_data={pipe_w[7][0], pipe_w[7][1], pipe_w[7][2], pipe_w[7][3]}; end
        else if (pipe_valid[8]  && pipe_size[8]  == 2'b00) begin push0_en=1; push0_data={pipe_w[8][0], pipe_w[8][1], pipe_w[8][2], pipe_w[8][3]}; end
        else if (pipe_valid[9]  && pipe_size[9]  == 2'b00) begin push0_en=1; push0_data={pipe_w[9][0], pipe_w[9][1], pipe_w[9][2], pipe_w[9][3]}; end
        else if (pipe_valid[10] && pipe_size[10] == 2'b00) begin push0_en=1; push0_data={pipe_w[10][0],pipe_w[10][1],pipe_w[10][2],pipe_w[10][3]}; end

        // ---- AES-192 ----
        else if (pipe_valid[0] && pipe_size[0] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[0][0],pipe_w[0][1],pipe_w[0][2],pipe_w[0][3]};  // RK00
        end
        else if (pipe_valid[1] && pipe_size[1] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[0][4],pipe_w[0][5],pipe_w[1][0],pipe_w[1][1]};  // RK01
            push1_en=1; push1_data={pipe_w[1][2],pipe_w[1][3],pipe_w[1][4],pipe_w[1][5]};  // RK02
        end
        else if (pipe_valid[2] && pipe_size[2] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[2][0],pipe_w[2][1],pipe_w[2][2],pipe_w[2][3]};  // RK03
        end
        else if (pipe_valid[3] && pipe_size[3] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[2][4],pipe_w[2][5],pipe_w[3][0],pipe_w[3][1]};  // RK04
            push1_en=1; push1_data={pipe_w[3][2],pipe_w[3][3],pipe_w[3][4],pipe_w[3][5]};  // RK05
        end
        else if (pipe_valid[4] && pipe_size[4] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[4][0],pipe_w[4][1],pipe_w[4][2],pipe_w[4][3]};  // RK06
        end
        else if (pipe_valid[5] && pipe_size[5] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[4][4],pipe_w[4][5],pipe_w[5][0],pipe_w[5][1]};  // RK07
            push1_en=1; push1_data={pipe_w[5][2],pipe_w[5][3],pipe_w[5][4],pipe_w[5][5]};  // RK08
        end
        else if (pipe_valid[6] && pipe_size[6] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[6][0],pipe_w[6][1],pipe_w[6][2],pipe_w[6][3]};  // RK09
        end
        else if (pipe_valid[7] && pipe_size[7] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[6][4],pipe_w[6][5],pipe_w[7][0],pipe_w[7][1]};  // RK10
            push1_en=1; push1_data={pipe_w[7][2],pipe_w[7][3],pipe_w[7][4],pipe_w[7][5]};  // RK11
        end
        else if (pipe_valid[8] && pipe_size[8] == 2'b01) begin
            push0_en=1; push0_data={pipe_w[8][0],pipe_w[8][1],pipe_w[8][2],pipe_w[8][3]};  // RK12
        end

        // ---- AES-256 ----
        else if (pipe_valid[0] && pipe_size[0] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[0][4],pipe_w[0][5],pipe_w[0][6],pipe_w[0][7]};  // RK01
        end
        else if (pipe_valid[1] && pipe_size[1] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[1][0],pipe_w[1][1],pipe_w[1][2],pipe_w[1][3]};  // RK02
            push1_en=1; push1_data={pipe_w[1][4],pipe_w[1][5],pipe_w[1][6],pipe_w[1][7]};  // RK03
        end
        else if (pipe_valid[2] && pipe_size[2] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[2][0],pipe_w[2][1],pipe_w[2][2],pipe_w[2][3]};  // RK04
            push1_en=1; push1_data={pipe_w[2][4],pipe_w[2][5],pipe_w[2][6],pipe_w[2][7]};  // RK05
        end
        else if (pipe_valid[3] && pipe_size[3] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[3][0],pipe_w[3][1],pipe_w[3][2],pipe_w[3][3]};  // RK06
            push1_en=1; push1_data={pipe_w[3][4],pipe_w[3][5],pipe_w[3][6],pipe_w[3][7]};  // RK07
        end
        else if (pipe_valid[4] && pipe_size[4] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[4][0],pipe_w[4][1],pipe_w[4][2],pipe_w[4][3]};  // RK08
            push1_en=1; push1_data={pipe_w[4][4],pipe_w[4][5],pipe_w[4][6],pipe_w[4][7]};  // RK09
        end
        else if (pipe_valid[5] && pipe_size[5] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[5][0],pipe_w[5][1],pipe_w[5][2],pipe_w[5][3]};  // RK10
            push1_en=1; push1_data={pipe_w[5][4],pipe_w[5][5],pipe_w[5][6],pipe_w[5][7]};  // RK11
        end
        else if (pipe_valid[6] && pipe_size[6] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[6][0],pipe_w[6][1],pipe_w[6][2],pipe_w[6][3]};  // RK12
            push1_en=1; push1_data={pipe_w[6][4],pipe_w[6][5],pipe_w[6][6],pipe_w[6][7]};  // RK13
        end
        else if (pipe_valid[7] && pipe_size[7] == 2'b10) begin
            push0_en=1; push0_data={pipe_w[7][0],pipe_w[7][1],pipe_w[7][2],pipe_w[7][3]};  // RK14
        end
    end

    // =========================================================================
    // OUTPUT FIFO PUSH/POP REGISTERS (unchanged from v7)
    // =========================================================================
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            fifo_wr_ptr   <= '0;
            fifo_rd_ptr   <= '0;
            fifo_overflow <= 1'b0;
            round_key_out <= 128'h0;
            key_valid_out <= 1'b0;
        end else begin
            automatic logic [FIFO_AWIDTH:0] wr_ptr_next;
            wr_ptr_next = fifo_wr_ptr;

            // -- Push: write side ------------------------------------------
            if (push0_en) begin
                if ((fifo_wr_ptr - fifo_rd_ptr) < FIFO_DEPTH) begin
                    fifo_mem[wr_ptr_next[FIFO_AWIDTH-1:0]] <= push0_data;
                    wr_ptr_next = wr_ptr_next + 1'b1;
                end else begin
                    fifo_overflow <= 1'b1;
                end
            end
            if (push1_en) begin
                if ((wr_ptr_next - fifo_rd_ptr) < FIFO_DEPTH) begin
                    fifo_mem[wr_ptr_next[FIFO_AWIDTH-1:0]] <= push1_data;
                    wr_ptr_next = wr_ptr_next + 1'b1;
                end else begin
                    fifo_overflow <= 1'b1;
                end
            end
            fifo_wr_ptr <= wr_ptr_next;

            // -- Pop: read side (1 entry/clock, independent of push) --------
            if (fifo_rd_ptr != fifo_wr_ptr) begin
                round_key_out <= fifo_mem[fifo_rd_ptr[FIFO_AWIDTH-1:0]];
                key_valid_out <= 1'b1;
                fifo_rd_ptr   <= fifo_rd_ptr + 1'b1;
            end else begin
                round_key_out <= 128'h0;
                key_valid_out <= 1'b0;
            end
        end
    end

endmodule
