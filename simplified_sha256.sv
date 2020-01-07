module simplified_sha256(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);
// Gabriel Pizzolato - simplified_sha256
 
 
// FSM state variables 
enum logic [2:0] {IDLE, PRE_BLOCK, BLOCK, PRE_COMPUTE, COMPUTE, PRE_WRITE, WRITE} state;


// Local variables
logic [31:0] w[16];
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;

logic [ 7:0] i; // counter for words in block
logic [1:0] j; // counter for blocks
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;


// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


parameter size = 80; // hard-code it to 20 words
assign num_blocks = determine_num_blocks(size); // assume no more than 256 blocks = 16,384 bytes

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.

// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // Student to add function implementation
	if(size%64 == 0)
		determine_num_blocks = size/64;
	else
		determine_num_blocks = (size/64)+1; // 64 bytes per block
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    // Student to add remaning code below
    ch = (e & f) ^ ((~e) & g); 
    t1 = (h + S1 + ch + k[t] + w);
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right rotation function for SHA-256
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);

	rightrotate = ((x >> r) | (x << (32-r)));

endfunction



// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else priority case (state)
    IDLE: begin 
       if(start) begin
          //Initialize hash values:
          //(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
          h0 <= 32'h6a09e667;
          h1 <= 32'hbb67ae85;
          h2 <= 32'h3c6ef372;
          h3 <= 32'ha54ff53a;
          h4 <= 32'h510e527f;
          h5 <= 32'h9b05688c;
          h6 <= 32'h1f83d9ab;
          h7 <= 32'h5be0cd19;
			 
          // initialize pointer to access memory location
          offset <= 0;
			 
	 
 	  // by default set write enable to '1' (i.e. memory write mode)
          cur_we <= 1'b0;
          cur_addr <= message_addr;
			 
	  // initialize write data to memory to '0'
          cur_write_data <= 32'h00000000;
			 
	  // proceed to message block fetch stage
          state <= PRE_BLOCK;
			 i <= 0;
			 j <= 0;
        end
    end
	 
	 PRE_BLOCK: begin
		state <= BLOCK;
		offset <= offset + 1;
	 end
	 
    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
	 
    BLOCK: begin	// Fetch message in 512-bit block size
		
		if(j == 0) begin // BLOCK0 - read first 16 words of data
			if(i < 16) begin 
				w[i] <= mem_read_data;
				offset <= offset+1;
				state <= BLOCK;
				i <= i+1;
			end else begin
				state <= PRE_COMPUTE;
			end
		
		end else if(j==1) begin // BLOCK1 - read next 4 words of data, then pad
			if(i < 4) begin
				w[i] <= mem_read_data;
				offset <= offset+1;
				state <= BLOCK;
				i <= i+1;
			end else begin
				// pad in linear time.
				w[4] <= 32'h80000000;
				for(int k = 5; k < 15 ; k++) begin
					w[k] <= 32'h00000000;
				end
				w[15] <= 32'd640;
				state <= PRE_COMPUTE;
			end
		
		end else begin // TO WRITE
			// time to write
			offset <= 0;
			cur_addr <= output_addr;
			cur_write_data <= h0;
			state <= PRE_WRITE;
		end
	end
	
	PRE_COMPUTE: begin // sets values
		a <= h0;
		b <= h1;
		c <= h2;
		d <= h3;
		e <= h4;
		f <= h5;
		g <= h6;
		h <= h7;
		i <= 0;
		state <= COMPUTE;
	end

   COMPUTE: begin
	// 64 processing rounds steps for 512-bit block 
			if (i < 64) begin
				if(i > 14) begin	// pre-processed wt
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
				state <= COMPUTE;
				
				
			end else begin
				// update hash values
				h0 <= h0 + a;
				h1 <= h1 + b;
				h2 <= h2 + c;
				h3 <= h3 + d;
				h4 <= h4 + e;
				h5 <= h5 + f;
				h6 <= h6 + g;
				h7 <= h7 + h;
				
				// increment block counter 
				j <= j+1;
				i <= 0;
				offset <= offset-1;
				state <= PRE_BLOCK;
			end
    end
	 
	 PRE_WRITE: begin
		cur_we <= 1;
		state <= WRITE;
	 end
	 
    WRITE: begin
		// Writes the next 7 outputs (first inputted in end of BLOCK code
		if(offset < 7) begin
			priority case(offset)
				0: cur_write_data <= h1;
				1: cur_write_data <= h2;
				2: cur_write_data <= h3;
				3: cur_write_data <= h4;
				4: cur_write_data <= h5;
				5: cur_write_data <= h6;
				6: cur_write_data <= h7;
			endcase
			
			offset <= offset+1;
			state <= WRITE;
			
		end else begin // Once done writing, finished. done flag assigned.
			cur_we = 0;
			state <= IDLE;
		end
			
    end
   endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
