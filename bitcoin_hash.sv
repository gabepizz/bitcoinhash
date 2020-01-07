module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;
// Gabriel Pizzolato

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};



enum logic [ 2:0] {IDLE, PRE_READ, READ, PHASE1, CALLING, CALL_SHA, PRE_WRITE, WRITE} state;

logic [31:0] w[num_nonces];
logic [31:0] in[3];
logic [31:0] hash[8];
logic [31:0] hout[num_nonces];

// logic registers used to control phase23 instances.
logic start_non;
logic reset_non;
logic clk_non;
logic done_non[num_nonces];
logic done_n;

// logics that are able to access/update memory.
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;

// used to iterate and change for SHA hashing.
logic [7:0] i, offset;
logic [31:0] a, b, c, d, e, f, g, h;



// done flagged once all instances of phase23 are finished.
assign done_n = done_non[0] & done_non[1] & done_non[2] & done_non[3] & done_non[4] & done_non[5] & done_non[6] & done_non[7] &
					 done_non[8] & done_non[9] & done_non[10] & done_non[11] & done_non[12] & done_non[13] & done_non[14] & done_non[15];
assign clk_non = clk;

// logic controls for memory access/updates based off current values
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

// finishing variable
assign done = (state == IDLE);


genvar ii; // generate the 16 instances of phase23 to do the 2nd and 3rd phases in parrallel.
generate
    for (ii=0; ii<=15; ii=ii+1) begin : generate_block_identifier // <-- example block name
    phase23 sixteen_phase23 (
		.clk(clk_non),
		.reset_n(reset_non),
		.start(start_non),
		.nonce(ii),
		.in(in),
		.h_in(hash),
		.h_out(hout[ii]),
		.done(done_non[ii])
);
end 
endgenerate


// does the main SHA-256 computation
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g); 
    t1 = (h + S1 + ch + k[t] + w);
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
	rightrotate = ((x >> r) | (x << (32-r)));

endfunction

// main time-based always block, controlled by posedge clk./negedge rst
always_ff @(posedge clk, negedge reset_n) begin
	if( !reset_n) begin
		state <= IDLE;
		cur_we <= 1'b0;
	end else begin
	case(state)
		IDLE: begin // idle state- initializes values for hashing.
			if(start) begin
				
				hash[0] <= 32'h6a09e667;
				hash[1] <= 32'hbb67ae85;
				hash[2] <= 32'h3c6ef372;
				hash[3] <= 32'ha54ff53a;
				hash[4] <= 32'h510e527f;
				hash[5] <= 32'h9b05688c;
				hash[6] <= 32'h1f83d9ab;
				hash[7] <= 32'h5be0cd19;
				// same constants above and below
				a <= 32'h6a09e667;
				b <= 32'hbb67ae85;
				c <= 32'h3c6ef372;
				d <= 32'ha54ff53a;
				e <= 32'h510e527f;
				f <= 32'h9b05688c;
				g <= 32'h1f83d9ab;
				h <= 32'h5be0cd19;
				
				
				offset <= 0;
				i <= 0;
				cur_we <= 1'b0; // we start reading data
				cur_addr <= message_addr; 
				cur_write_data <= 32'd0;
				start_non <= 1'b0;
				reset_non <= 1'b0;
				
				state <= PRE_READ;
			end
		end
		
		// PRE-READ: used as buffer before READ state to get correct
		// read values that can be iterated on.
		PRE_READ: begin
			offset <= offset+1;
			state <= READ;
		end
		
		// READ: reads data from mem_read_data, reading the first 19 words
		READ: begin
			if(i < 16) begin
				w[i] <= mem_read_data;
				offset <= offset+1;
				state <= READ;
				i <= i+1;
			end else if(i < 19) begin
				in[i-16] <= mem_read_data;
				offset <= offset+1;
				state <= READ;
				i <= i+1;
			end else begin
				i <= 0;
				state <= PHASE1;
			end
		end
		
		// PHASE1: does first hash of the values and 
		PHASE1: begin
			if(i < 64) begin
				if(i > 14) begin	
					w[15] <= w[0] + 
								(rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1] >> 3)) + 
								w[9] + 
								(rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
								
					for(int n = 0; n < 15 ; n++) begin
						w[n] <= w[n+1];
					end
					
					// doing hash computation
					{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[15],i);
				end else begin // WHEN i < 16
					{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[i],i);
				end
				
				
				i <= i+1;
				state <= PHASE1;
				
			end else begin
				// updates hash value to be used as input in CALL_SHA
				hash[0] <= hash[0] + a;
				hash[1] <= hash[1] + b;
				hash[2] <= hash[2] + c;
				hash[3] <= hash[3] + d;
				hash[4] <= hash[4] + e;
				hash[5] <= hash[5] + f;
				hash[6] <= hash[6] + g;
				hash[7] <= hash[7] + h;

				state <= CALLING;
				reset_non <= 1'b1;
				start_non <= 1'b1;
			end
		end
		
		//CALLING: itermediary state before CALL_SHA to fully reset 
		// and start the phase23 modules.
		CALLING: begin
			state <= CALL_SHA;
		end
		
		//CALL_SHA: waits until phase23 modules are finished (does 2nd and 3rd phase)
		CALL_SHA: begin
			start_non <= 1'b0;
			if(done_n) begin
				reset_non <= 1'b0;
				state <= PRE_WRITE;
				offset <= 0;
				cur_addr <= output_addr;
				cur_write_data <= hout[0];
			end
		end
		
		//PRE_WRITE: acts as buffer before WRITE to correctly iterate output.
		PRE_WRITE: begin
			cur_we <= 1'b1;
			state <= WRITE;
		end
		
		//WRITE: outputs data to memory @ output_addr from hout.
		WRITE: begin
			if(offset < 15) begin
				cur_we <= 1'b1;
				cur_write_data <= hout[offset+1];
				offset <= offset+1;
			end else begin
				state <= IDLE;
			end
		end
		
	
	endcase
	end

end




endmodule
