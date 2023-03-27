package DES;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.BufferOverflowException;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.math.BigInteger;

/**
 *  HAVENT HANDLED TRY CATCH ERRORS YET.
 *  IN FUTURE
 *  	NEED TO THROW ERRORS OUT OF FUNCTIONS FROM ANY INNER CLASSES
 *  	NEED TO HANDLE ERRORS in the enrypt and decypt classes only. 
 * @author ryan
 *
 */

public class DES 
{	
	private BigInteger masterkey;
	
	public FeistelNetwork f;
	public KeySchedule k;
	
	Logger log = Logger.getLogger("DES");
	
	public DES() // at polong K0 will be serviced by a key manager
	{
		this.f = new FeistelNetwork();
		this.k = new KeySchedule();
	}
	
	public void setKey(long masterKey) throws Exception
	{
		// pairity bits apply for all bits up to pairty bit, including other pairtiy bits
		// Example with pairity bits filled in at "!"
		//            0b       !8      !16     !24     !32     !40     !48     !56     !64  
		//test.setKey(0b0110110001101100001111000011001100111100001001111001110001101010);
		this.k.setMasterKey(masterKey);
	}
	
	public void decrypt(FileInputStream inputstream, FileOutputStream outputstream) throws Exception
	{
		Binary[] binary_array = processInput(inputstream);
		
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES * binary_array.length);
		
		for(int i = 0; i < binary_array.length; i++)
		{

			
			Binary block = binary_array[i];
			long before_IP = block.get().longValue();
			
			/**
			 * Perform and checking initial permutation	
			 */
			
			// Initial permutation
			block.permutation(Tables.IP);
			
				
			// This check makes sure that the IP AND FP reverse one another. 
			Binary blocks_test = new Binary();
			blocks_test.assign(block.get());
			blocks_test.permutation(Tables.FP);
			long after_FP = blocks_test.get().longValue();
			if((after_FP ^ before_IP) != 0b0L)
			{
				String message = "IP does not reverse FP. Aborting. \n" + 
									"Input binary array = " + Long.toBinaryString(before_IP) + "\n" +
									"After FP           = " + Long.toBinaryString(after_FP) + "\n" + 
									"Input ^ FP output  = " + (after_FP ^ before_IP) + " <- condition";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			/**
			 * Divide C into L and R (0)
			 */
			long l0 = ((block.get().longValue() & 0b1111111111111111111111111111111100000000000000000000000000000000L) >> 32)
										 			 & 0b0000000000000000000000000000000011111111111111111111111111111111L;
			long r0 =   block.get().longValue() & 0b0000000000000000000000000000000011111111111111111111111111111111L;
			
			Binary l0b = new Binary(); l0b.assign(BigInteger.valueOf(l0));
			Binary r0b = new Binary(); r0b.assign(BigInteger.valueOf(r0));
			
			this.f.clear();
			
			this.f.L0 = l0b;
			this.f.R0 = r0b;
			
			this.k.reset();
			
			for(int round = 0; round < 16; round ++)
			{	
				this.f.K0 = this.k.reverse();
				this.f.run();
				
			}
			/*
			 	Le0  = 00000000000000000000000000000100
				Re0  = 10110001101111000111110111001011
				
				
				Le15 = 01110011100110001100011100100001
				Re15 = 10000001100010010100010000111101
			 
			 	Ld0  = 10000001100010010100010000111101
				Rd0  = 00011101101011100011100001010011
				
				
				Ld15 = 01000100111011001011011011010000
				Rd15 = 00000110000100010100100000010010
				
				Ld0 = Re15 < true
				Rd0 = Le15
			 */
			
			/** 
			 * Final Permutation
			 */
			BigInteger c1 = BigInteger.valueOf(this.f.R1.get().longValue() << 32 | this.f.L1.get().longValue());			
			block.assign(c1);
			
			block.permutation(Tables.FP);
			
			try {
				buffer.putLong(block.get().longValue());
			}catch(BufferOverflowException e) {
				String message = e.getMessage() + " Overflow of byte buffer occured during encryption on block " + i;
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}	
		}
		/**
		 * Write to output stream
		 */
		try {		
			outputstream.write(buffer.array());
		} catch(IOException e) {
			String message = e.getMessage() + " Failed to write to output file. ";
			log.log(Level.SEVERE, message);
			throw new Exception(message);
		}
		
		
	}
	
	public void encrypt(FileInputStream inputstream, FileOutputStream outputstream) throws Exception
	{
		Binary[] binary_array = processInput(inputstream);
		
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES * binary_array.length);
		
		
		//iterate through all 64 bit message blocks
		for(int i = 0; i < binary_array.length; i++) 
		{
			Binary block = binary_array[i];
			long before_IP = block.get().longValue();
			
			/**
			 * Perform and checking initial permutation	
			 */
			
			// Initial permutation
			block.permutation(Tables.IP);
						
			// This check makes sure that the IP AND FP reverse one another. 
			Binary blocks_test = new Binary();
			blocks_test.assign(block.get());
			blocks_test.permutation(Tables.FP);
			long after_FP = blocks_test.get().longValue();
			if((after_FP ^ before_IP) != 0b0L)
			{
				String message = "FP does not reverse IP. Aborting. \n" + 
									"Input binary array = " + Long.toBinaryString(before_IP) + "\n" +
									"After FP           = " + Long.toBinaryString(after_FP) + "\n" + 
									"Input ^ FP output  = " + (after_FP ^ before_IP) + " <- condition";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
						
			/**
			 * Divide C into L and R (0)
			 */
			long l0 = ((block.get().longValue() & 0b1111111111111111111111111111111100000000000000000000000000000000L) >> 32)
										 			 & 0b0000000000000000000000000000000011111111111111111111111111111111L;
			long r0 =   block.get().longValue() & 0b0000000000000000000000000000000011111111111111111111111111111111L;
			
			
			Binary l0b = new Binary(); l0b.assign(BigInteger.valueOf(l0));
			Binary r0b = new Binary(); r0b.assign(BigInteger.valueOf(r0));
			
			this.f.clear();
			
			this.f.L0 = l0b;
			this.f.R0 = r0b;
			
			this.k.reset();

			for(int round = 0; round < 16; round ++)
			{	
				this.f.K0 = this.k.run();				
				this.f.run();
			}	
			/**
			 * Final Permutation
			 */
			
			/**
			 * L AND R FLIP BEFORE ENTERING IP-1
			 */
			BigInteger c1 = BigInteger.valueOf(this.f.R1.get().longValue() << 32 | this.f.L1.get().longValue());			
			block.assign(c1);			
			
			block.permutation(Tables.FP);
			
			try {
				buffer.putLong(block.get().longValue());
			}catch(BufferOverflowException e) {
				String message = e.getMessage() + " Overflow of byte buffer occured during encryption on block " + i;
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
		}
		/**
		 * Write to output stream
		 */
		try {		
			outputstream.write(buffer.array());			
		} catch(IOException e) {
			String message = e.getMessage() + " Failed to write to output file. ";
			log.log(Level.SEVERE, message);
			throw new Exception(message);
		}
				
	}
	
	private Binary[] processInput(FileInputStream inputstream) throws Exception
	{
		/**
		 * Read from input stream and split into array of 64 bit binary  
		 */
		byte[] inputbytes;
		Binary[] binary_array;
		
		try {
	        inputbytes = inputstream.readAllBytes();
	        
	        
	        int blocks = (int)Math.ceil((float)inputbytes.length/8);
	        int blocks_extended = blocks * 8;
	        
	        if(blocks == 0)
	        	throw new Exception("Reading file length determined zero blocks to encrypt. ");
	        
	        byte[] inputbytes_extended = new byte[blocks_extended];
	        System.arraycopy(inputbytes, 0, inputbytes_extended, 0, inputbytes.length);
	        
	        // blocks_extended is in lengths of bytes (8 bits) not blocks (64). 
	        binary_array = new Binary[blocks_extended/8];

	        int index = 0;
	        for(int j = 0; j < blocks_extended; j+=8)
	        {
		        BigInteger block_64 = BigInteger.valueOf(0b0L);
		        
		        for(int i = j;  i < j+8; i++) // 8*8 = 64
		        {	
		        	long input_byte = inputbytes_extended[i] & 0b0000000011111111L;		
		        	block_64 = block_64.valueOf((block_64.longValue() << (8)) | input_byte);
		        }
		        
		        Binary block_binary = new Binary();
		        block_binary.assign(block_64);
		        binary_array[index++] = block_binary;
		        if(block_binary.string().length() > 64)
		        	throw new Exception("Segementing file into Binary array produces array index greater than 64 bits. ");
	        }   
		}catch(IOException e) {
			String message = e.getMessage() + "Cannot read from file input stream, exiting DES encryption. ";
			log.log(Level.SEVERE, message);
			throw new Exception(message);
		}
		
		return binary_array;
	}
	
	private class KeySchedule
	{
		private Binary masterKey;
		
		private Binary C0;
		private Binary D0;
		
		private int cycle_count;
		
		
		protected KeySchedule()
		{
			this.cycle_count = 1;
			this.masterKey = new Binary();
			this.C0 = new Binary();
			this.D0 = new Binary();
			
		}
		
		protected void setMasterKey(long key) throws Exception
		{
			this.masterKey = new Binary();
			this.masterKey.assign(BigInteger.valueOf(key));
			Binary testPairity = masterKey.copy();
			this.masterKey.permutation(Tables.PC1);
			testPairity.permutation(Tables.PC1_checkbits); // obtain just the check bits
			
			if(this.masterKey.string().length() > 56)
			{
				String message = "master key generated after PC1 exceeds 56 bits, exiting.";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			long c0 = ((this.masterKey.get().longValue() & 0b11111111111111111111111111110000000000000000000000000000L) >> 28)
														 & 0b00000000000000000000000000001111111111111111111111111111L;
			long d0 =  this.masterKey.get().longValue()  & 0b00000000000000000000000000001111111111111111111111111111L;
			
			this.C0.assign(BigInteger.valueOf(c0));
			this.D0.assign(BigInteger.valueOf(d0));
		}
		
		protected void reset()
		{	
			this.cycle_count = 1;
			long c0 = ((this.masterKey.get().longValue() & 0b11111111111111111111111111110000000000000000000000000000L) >> 28)
														 & 0b00000000000000000000000000001111111111111111111111111111L;
			long d0 =  this.masterKey.get().longValue()  & 0b00000000000000000000000000001111111111111111111111111111L;
			
			this.C0.assign(BigInteger.valueOf(c0));
			this.D0.assign(BigInteger.valueOf(d0));
		}
		
		protected Binary run() throws Exception
		{
			int rotate = 2;
			if(cycle_count == 1 || cycle_count == 2 || cycle_count == 9 || cycle_count == 16)
				rotate = 1;
			
			long c0 = C0.get().longValue();
			long d0 = D0.get().longValue();
			
			c0 = ((c0 << rotate) | ( c0 >> (28 - rotate) )) &0b01111111111111111111111111111;
			d0 = ((d0 << rotate) | ( d0 >> (28 - rotate) )) &0b01111111111111111111111111111;
			
			C0.assign( BigInteger.valueOf(c0) ); 
			D0.assign( BigInteger.valueOf(d0) );
			
			if(C0.string().length() > 28 || D0.string().length() > 28)
			{
				String message = "Encryption Cycle half key returns a half key length over 28 after rotation:" +
								"\nC0 = " + C0.string() + 
								"\nD0 = " + D0.string() + ". ";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			Binary cycle_key = new Binary();
			
			long Mc = ((C0.get().longValue() << 28) | (D0.get().longValue()));
									
			cycle_key.assign(BigInteger.valueOf(Mc));
			
			
			if(cycle_key.string().length() > 56)
			{
				String message = "Encryption Cycle key returns a length over 56 prior to permutation: \n" +
								"Key = " + cycle_key.string() +
								"\nC0 = " + C0.string() + 
								"\nD0 = " + D0.string() + ". ";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
						
			cycle_key.permutation(Tables.PC2);
			
			
			this.cycle_count ++;
			
			if(cycle_key.string().length() > 48)
			{
				String message = "Encryption Cycle key returns a length over 48 after PC2";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			return cycle_key;
		}
		
		protected Binary reverse() throws Exception
		{
			int rotate = 2;
			if(cycle_count == 2 || cycle_count == 9 || cycle_count == 16)
				rotate = 1;
			
			if(cycle_count != 1)
			{
				long c0 = C0.get().longValue();
				long d0 = D0.get().longValue();
				
				c0 = ((c0 >> rotate)) | (c0 & (0b011 >> (2-rotate))) << 27-(rotate-1);
				d0 = ((d0 >> rotate)) | (d0 & (0b011 >> (2-rotate))) << 27-(rotate-1);
				
				C0.assign( BigInteger.valueOf(c0) ); 
				D0.assign( BigInteger.valueOf(d0) ); 
			}
			
			if(C0.string().length() > 28 || D0.string().length() > 28)
			{
				String message = "Encryption Cycle half key returns a half key length over 28 after rotation:" +
								"\nC0 = " + C0.string() + 
								"\nD0 = " + D0.string() + ". ";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			Binary cycle_key = new Binary();
			
			long Mc = ((C0.get().longValue() << 28) | (D0.get().longValue()));
			
			cycle_key.assign(BigInteger.valueOf(Mc));
			
			if(cycle_key.string().length() > 56)
			{
				String message = "Decryption Cycle key returns a length over 56 prior to permutation: \n" +
						"Key = " + cycle_key.string() + ". ";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			cycle_key.permutation(Tables.PC2);
			
			
			this.cycle_count ++;
			
			if(cycle_key.string().length() > 48)
			{
				String message = "Decryption Cycle key returns a length over 48 after PC2";
				log.log(Level.SEVERE, message);
				throw new Exception(message);
			}
			
			// 110001110101011001111011110010011000110101010
			// 10100000000010001001110000010101000000001110000
			
			
			return cycle_key;
		}
		
		protected void testPairity()
		{
			
		}
		
	}
	
	private class FeistelNetwork
	{ 
		Logger log = Logger.getLogger("FeistelNetwork");
		
		protected Binary L0;
		protected Binary L1;
		protected Binary R0;
		protected Binary R1;
		
		protected Binary K0;
		
		// Constructor
		public FeistelNetwork()
		{			
			this.L0 = new Binary(); 
			this.L1 = new Binary(); 
			this.R0 = new Binary(); 
			this.R1 = new Binary(); 
			this.K0 = new Binary();	
		}
		
		protected void clear()
		{
			this.L0 = new Binary(); 
			this.L1 = new Binary(); 
			this.R0 = new Binary(); 
			this.R1 = new Binary(); 
			this.K0 = new Binary();	
		}
		
	
		protected void run()
		{			
			
			if(this.L0.string().length() > 32 || this.R0.string().length() > 32)
			{
				log.log(Level.WARNING, "L0 or R0 isnt 32 bits long. ");
			}
			
			//Perform swap and processing
			this.L1 = this.R0.copy(); // this is working
			this.R1 = this.L0.xor(this.f(this.K0, this.R0)); // not working
			
			//Prepare for next round
			this.R0 = this.R1; // = L0 XOR f(R0, K0))
			this.L0 = this.L1; // = R0
		}
		
		
		private Binary f(Binary K, Binary R)
		{
			/* Expansion */
			if(R.string().length() > 32)
				log.log(Level.WARNING, "Expansion: R0 isnt 32 bits long, " 
						+ R.string().length() + " bits long");
			// expansion is 48 bits long (longeger represents position) 
			
			R.permutation(Tables.Expansion);
			
			if(R.string().length() > 48)
				log.log(Level.WARNING, "Result of Expansion isnt 48 bits long " 
						+ R.string().length() + " bits long");
			
			/* XOR with key */
			R = R.xor(K);
			
			if(R.string().length() > 48)
				log.log(Level.WARNING, "Result of XOR with key and R0 produces output not 48 bits long");
			
			
			
			/* Substitution */			
			
			Binary substitution_slice = new Binary();
			Binary[] slices = new Binary[8];
			for (int s = 0; s <= 7; s++)
			{
				// make binary slice of original binary object
				substitution_slice = R.slice(s*6, (s*6)+5);
								
				
				if(substitution_slice.string().length() > 6)
					log.log(Level.WARNING, "Slice for substitution boxes is not 6 bits long. " +
							substitution_slice.string().length() + " bits long. " +
							substitution_slice.string());
				
				substitution_slice.substitution(Tables.SBox[s]);
				
				if(substitution_slice.string().length() > 4)
					log.log(Level.WARNING, "After substitution, slice is not 4 bits long. " +
							substitution_slice.string().length() + " bits long.");
				
				slices[s] = substitution_slice;
			}
			
			
			
			/* Combine slices */
			Binary S = new Binary();
			long concat = 0b00000000000000000000000000000000L; // 32 bits 
			for (int s = 0; s < 8; s++)
			{
				concat = concat | (slices[s].get().longValue() << 4*s);				
			}
			BigInteger concat_bigint = BigInteger.valueOf(concat);
			S.assign(concat_bigint);
			
			
			/* Final permutation */
			S.permutation(Tables.Permutation);
			
			if(S.string().length() > 32)
				log.log(Level.WARNING, "Result of Expansion is over 32 bits long " 
						+ S.string().length() + " bits long");
			
			return S;
		}
	}
	
	private final class Binary  
	{
		Logger log = Logger.getLogger("Binary");
		
		/* Private class variables */
		private BigInteger i; 
		private String i_str;
		
		private BigInteger[] i_array;
		
		/* Encapsulation methods */
		public void assign(BigInteger i)
		{
			this.i = i;
			this.i_str = Long.toBinaryString(i.longValue());
		}
		
		public BigInteger get()
		{
			return this.i;
		}
		
		public BigInteger[] getArray()
		{
			return this.i_array;
		}
		
		public String string()
		{
			return this.i_str;
		}
		
		public Binary copy()
		{
			long value = this.get().longValue();
			Binary clone = new Binary();
			clone.assign(BigInteger.valueOf(value));
			return clone;
		}
		
		public Binary slice(int start, int end)
		{
			// start is RHS of binary
			// end is LHS of binary
			int length = (int)(end-start); // end = 8, start = 4, length = 4
			long one = 0b01L; // 1
			long mask = 0b0L;
			
			for (int i = length; i >= 0; i--)
				mask = mask | (one << i); 
			
			mask = mask << start;
			long binary = (mask & this.i.longValue()) >> start;
			BigInteger binary_bigint = BigInteger.valueOf(binary);
			
			Binary binary_slice =  new Binary();
			binary_slice.assign(binary_bigint);
			
			return binary_slice;
		}
		
		public void permutation(long[] E)
		{
			long permutated_binary = 0b0L;
			for (int x = 0; x < E.length; x++) // iterate through length of binary
			{
				
				long pos_x = x+1;
				long pos = E[x];
				long bit = selectbit(pos);
				permutated_binary = addbit(pos_x, bit, permutated_binary);
				
			}
			BigInteger permutated_bigint = BigInteger.valueOf(permutated_binary);
			
			this.assign(permutated_bigint);
		}
		
		public Binary xor(Binary b)
		{
			Binary x = new Binary();
			long xor_binary = (this.get().longValue() ^ b.get().longValue());
			BigInteger xor_bigint = BigInteger.valueOf(xor_binary);
			x.assign(xor_bigint);
			
			return x;
		}
		
		public void substitution(long[][] S)
		{
			
			long column = (this.get().longValue() & 0b011110L) >> 1;
					
			long row = ((this.get().longValue() & 0b100000L) >> 4 ) | (this.get().longValue() & 0b000001L);
			
			long result = S[(int)row][(int)column];
			BigInteger result_bigint = BigInteger.valueOf(result);
			
			this.assign(result_bigint);
		}
		
		/* private methods */
		private long selectbit(long pos)
		{
			long sel = (0b1L << pos-1);
			long ret = i.longValue() & sel;
			ret = ret >> pos-1;
			long ret_old = ret;
			
			ret = ret & (0b0L << pos-1 | 0b1L);
			
			
			
			return ret;
		}
		
		private long addbit(long pos, long bit, long binary)
		{
			bit = bit << pos-1;
			binary = binary | bit;
			return binary;
		}
	}

	
	private static class Tables
	{
		static long[] IP = 
			{58, 50, 42, 34, 26, 18, 10,  2, 
			 60, 52, 44, 36, 28, 20, 12,  4, 
			 62, 54, 46, 38, 30, 22, 14,  6, 
			 64, 56, 48, 40, 32, 24, 16,  8,
			 57, 49, 41, 33, 25, 17,  9,  1, 
			 59, 51, 43, 35, 27, 19, 11,  3,
			 61, 53, 45, 37, 29, 21, 13,  5,
			 63, 55, 47, 39, 31, 23, 15,  7};
		
		static long[] FP = 
			{40,  8, 48, 16, 56, 24, 64, 32,
			 39,  7, 47, 15, 55, 23, 63, 31,
			 38,  6, 46, 14, 54, 22, 62, 30,
			 37,  5, 45, 13, 53, 21, 61, 29,
			 36,  4, 44, 12, 52, 20, 60, 28,
			 35,  3, 43, 11, 51, 19, 59, 27,
			 34,  2, 42, 10, 50, 18, 58, 26,
			 33,  1, 41,  9, 49, 17, 57, 25};
		
		static long[] Permutation = 
			{16,  7, 20, 21, 29, 12, 28, 17, 
			  1, 15, 23, 26,  5, 28, 31, 10, 
			  2,  8, 24, 14, 32, 27,  3,  9, 
			 19, 13, 30,  6, 22, 11,  4, 25};
		
		static long[] Expansion = 
			{32,  1,  2,  3,  4,  5,
		      4,  5,  6,  7,  8,  9,
		      8,  9, 10, 11, 12, 13,
		     12, 13, 14, 15, 16, 17,
		     16, 17, 18, 19, 20, 21,
		     20, 21, 22, 23, 24, 25,
		     24, 25, 26, 27, 28, 29,
		     28, 29, 30, 31, 32,  1,};
		
		static long[][] SBox1 = {
				{0b1110, 0b0100, 0b1101, 0b0001, 0b0010, 0b1111, 0b1011, 0b1000, 0b0011, 0b1010, 0b0110, 0b1100, 0b0101, 0b1001, 0b0000, 0b0111}, 
				{0b0000, 0b1111, 0b0111, 0b0100, 0b1110, 0b0010, 0b1101, 0b0001, 0b1010, 0b0110, 0b1100, 0b1011, 0b1001, 0b0101, 0b0011, 0b1000},
				{0b0100, 0b1001, 0b1110, 0b1000, 0b1101, 0b0110, 0b0010, 0b1011, 0b1111, 0b1100, 0b1001, 0b0111, 0b0011, 0b1010, 0b0101, 0b0000},
				{0b1111, 0b1100, 0b1000, 0b0010, 0b0100, 0b1001, 0b0001, 0b0111, 0b0101, 0b1011, 0b0011, 0b1110, 0b1010, 0b0000, 0b0110, 0b1101}
				};
		static long[][] SBox2 = {
				{0b1111, 0b0001, 0b1000, 0b1110, 0b0110, 0b1011, 0b0011, 0b0100, 0b1001, 0b0111, 0b0010, 0b1101, 0b1100, 0b0000, 0b0101, 0b1010}, 
				{0b0011, 0b1101, 0b0100, 0b0111, 0b1111, 0b0010, 0b0100, 0b1110, 0b1100, 0b0000, 0b0001, 0b1010, 0b0110, 0b1001, 0b1011, 0b0101},
				{0b0000, 0b1110, 0b0111, 0b1011, 0b1010, 0b0100, 0b1101, 0b0001, 0b0101, 0b1000, 0b1100, 0b0110, 0b1001, 0b0011, 0b0010, 0b1111},
				{0b1101, 0b1000, 0b1010, 0b0001, 0b0011, 0b1111, 0b0100, 0b0010, 0b1011, 0b0110, 0b0111, 0b1100, 0b0000, 0b0101, 0b1110, 0b1001}
				};
		static long[][] SBox3 = 
				{
				{10, 0,   9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
				{13, 7,   0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
				{13, 6,   4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
				{1,  10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12} 
				};
		
		static long[][] SBox4 = 
				{
				{ 7, 13, 14,  3,  0,   6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
				{13, 8,  11,  5,  6,  15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
				{10, 6,   9,  0,  12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
				{ 3, 15,  0,  6,  10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
				};
				
		static long[][] SBox5 = 
			    {
				{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0,	14,	 9},
				{14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,	 6},
				{ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0,	14},
				{11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,	 3}
			    };
		
		static long[][] SBox6 = 
			    {
				{12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
				{10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
				{ 9, 14, 15,  5, 2,  8,	12,  3,  7,  0,  4,	10,  1, 13, 11,  6},
				{ 4,  3,  2, 12, 9,  5,	15,	10,	11,	14,  1,  7,	 6,  0,  8,	13}
			    };
		
		static long[][] SBox7 = 
			    {
				{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12, 9,  7,	 5, 10,  6,  1},
				{13,  0, 11,  7,  4,  9,  1, 10, 14,  3, 5, 12,	 2, 15,  8,  6},
				{ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15, 6,  8,  0,  5,  9,  2},
				{ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5, 0, 15,	14,  2,  3, 12}
			    };
		
		static long[][] SBox8 = 
			    {
				{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
				{ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
				{ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
				{ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
			    };
		
		
		static long[][][] SBox = {SBox1, SBox2, SBox3, SBox4, SBox5, SBox6, SBox7, SBox8};
		
		static long[] PC1 = 
			{57, 49, 41, 33, 25, 17,  9,  1,
			 58, 50, 42, 34, 26, 18, 10,  2,
			 59, 51, 43, 35, 27, 19, 11,  3, 
			 60, 52, 44, 36, 63, 55, 47, 39,
			 31, 23, 15,  7, 62, 54, 46, 38,
			 30, 22, 14,  6, 61, 53, 45, 37,
			 29, 21, 13,  5, 28, 20, 12,  4};
		static long[] PC1_checkbits = 
			{8, 16, 24, 32, 40, 48, 56, 64};
		
		
		static long[] PC2 = 
			{14, 17, 11, 24,  1,  5,  3, 28,
		     15,  6, 21, 10, 23, 19, 12,  4,
		     26,  8, 16,  7, 27, 20, 13,  2,
		     41, 52, 31, 37, 47, 55, 30, 40, 
		     51, 45, 33, 48, 44, 49, 39, 56, 
		     34, 53, 46, 42, 50, 36, 29, 32}; 
							
	}
}
