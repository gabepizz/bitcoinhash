module phase23 (
	input logic clk, reset_n, start,
	input logic [31:0] nonce,
	input logic [31:0] in[3],
	input logic [31:0] h_in[8],
	output logic[31:0] h_out,
	output logic done);

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
	
	
// FSM state variables
enum logic[1:0] {DONE, PHASE2, COMPUTE, PHASE3} state;


// local variables

logic[31:0] a, b, c, d, e, f, g, h, h0;
logic[7:0] i;
logic phase2;		  // in phase2 or phase3
logic[31:0] h_int[8]; // intermediary hash return value
logic[31:0] w[16];    // rotary w array.


assign done = (state == DONE);


// SHA256 hash round
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



// Main clk based round that is controlled by bitcoin_hash module
always_ff @(posedge clk, negedge reset_n) 
begin
	if(!reset_n)
		state <= PHASE2;
	else begin case(state)
	
		// DONE: stays in this state once done.
		DONE: begin
			if(start)
				state <= PHASE2;
		end
		
		// PHASE2: starts here, sets start values.
		PHASE2: begin
			if(start) begin
			
				// starting hash values
				a <= h_in[0];
				b <= h_in[1];
				c <= h_in[2];
				d <= h_in[3];
				e <= h_in[4];
				f <= h_in[5];
				g <= h_in[6];
				h <= h_in[7];
				
				// assigns input message.
				w[0:2] <= in;
				w[3] <= nonce;
				
				// Pads after input
				w[4] <= 32'h80000000;
				w[5] <= 32'h00000000;
				w[6] <= 32'h00000000;
				w[7] <= 32'h00000000;
				w[8] <= 32'h00000000;
				w[9] <= 32'h00000000;
				w[10] <= 32'h00000000;
				w[11] <= 32'h00000000;
				w[12] <= 32'h00000000;
				w[13] <= 32'h00000000;
				w[14] <= 32'h00000000;
				w[15] <= 32'd640;
				
				
				i <= 0;
				phase2 <= 1'b1;
				state <= COMPUTE;
			end
		end
		
		// COMPUTE: does computation of SHA-256 on phase 2 and 3
		COMPUTE: begin
			if(i < 64) begin
				if(i > 14) begin // i==16	
					w[15] <= w[0] + 
								(rightrotate(w[1], 7) ^ rightrotate(w[1], 18) ^ (w[1] >> 3)) + 
								w[9] + 
								(rightrotate(w[14], 17) ^ rightrotate(w[14], 19) ^ (w[14] >> 10));
								
					for(int n = 0; n < 15 ; n++) begin
						w[n] <= w[n+1];
					end
					
					// doing hash computation
					{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[15],i);
				end else begin // WHEN w < 16
					// doing hash computation
					{a,b,c,d,e,f,g,h} <= sha256_op(a,b,c,d,e,f,g,h,w[i],i);
				end
				
				
				i <= i+1;
				state <= COMPUTE;
				
			
			end else if(phase2)begin // end of first hash, go to PHASE3
				h_int[0] <= h_in[0] + a;
				h_int[1] <= h_in[1] + b;
				h_int[2] <= h_in[2] + c;
				h_int[3] <= h_in[3] + d;
				h_int[4] <= h_in[4] + e;
				h_int[5] <= h_in[5] + f;
				h_int[6] <= h_in[6] + g;
				h_int[7] <= h_in[7] + h;
				
				state <= PHASE3;
				
			end else begin // end of 2nd hash, finish. (END OF PHASE3)
				h_out <= h0 + a;
				
				state <= DONE;
			end
			
		end
		
		// PHASE3: controller of 3rd phase, a new hash function on message old hash
		PHASE3: begin
			
			// Input / Padding assigned
			w[0:7] <= h_int;
			w[8]  <= 32'h80000000;
			w[9]  <= 32'h00000000;
			w[10] <= 32'h00000000;
			w[11] <= 32'h00000000;
			w[12] <= 32'h00000000;
			w[13] <= 32'h00000000;
			w[14] <= 32'h00000000;
			w[15] <= 32'd256;

			// Default hash values.
			
			h0 <= 32'h6a09e667;
			
			a <= 32'h6a09e667;
			b <= 32'hbb67ae85;
			c <= 32'h3c6ef372;
			d <= 32'ha54ff53a;
			e <= 32'h510e527f;
			f <= 32'h9b05688c;
			g <= 32'h1f83d9ab;
			h <= 32'h5be0cd19;
			
			phase2 <= 1'b0;
			i <= 0;
			state <= COMPUTE;
		
		end
	endcase end
end


endmodule: phase23