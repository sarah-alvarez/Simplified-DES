from bitstring import BitArray, BitStream

######## CONSTANTS ########

PERM_CHOICE_1C = [3, 5, 2, 7, 4]
PERM_CHOICE_1D = [10, 1, 9, 8, 6]
PERM_CHOICE_2 = [6, 3, 7, 4, 8, 5, 10, 9]

INIT_PERM = [2, 6, 3, 1, 4, 8, 5, 7]
INVERSE_PERM = [4, 1, 3, 5, 7, 2, 8, 6]

E_BIT_TABLE = [4, 1, 2, 3, 2, 3, 4, 1]
PERM_P = [2, 4, 3, 1]

S_BOX_1 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
S_BOX_2 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

###########################


#
# Function Rotate() will rotate the elements of
# a list to the left by the number specified in
# num_rotate. NOTE: BitArrays are treated as
# lists!
#
def Rotate(list, num_rotate):
    return list[num_rotate:] + list[:num_rotate]

#
# Function GenKey() will generate an 8-bit round
# key from a given 10-bit cipher key.
#
def GenKey(cipher_key, round_num):
    # 1) Break cipher_key into two 5-bit blocks using permuted choice 1.
    half_c = BitArray('0b00000')
    half_d = BitArray('0b00000')

    for i in range(5):
        half_c[i] = cipher_key[PERM_CHOICE_1C[i] - 1]
        half_d[i] = cipher_key[PERM_CHOICE_1D[i] - 1]      
    
    # 2) Shift each half to the left (circular) by the round_num.
    half_c = Rotate(half_c, round_num)
    half_d = Rotate(half_d, round_num)
  
    # 3) Obtain round key using permuted choice 2.
    round_key = BitArray('0b00000000')
    combined_halves = half_c + half_d
    for i in range(8):
        round_key[i] = combined_halves[PERM_CHOICE_2[i] - 1]
        
    # 4) Return produced round key for use in the algorithm.
    return round_key
    
#
# SFunction1 takes in a 4 bit block and outputs a 2 bit block according
# to the S1 table.
#
def SFunction1(left_block):
    # 1) Get i and j 
    temp = BitArray('0b00')     
    temp[0] = left_block[0]
    temp[1] = left_block[3]

    i = temp.uint

    
    temp[0] = left_block[1]
    temp[1] = left_block[2]

    j = temp.uint

    # 2) Get number at (i, j) of S-box 1 and convert to binary
    temp.uint = S_BOX_1[i][j]
    
    # 3) Return block
    return temp


#
# SFunction2 takes in a 4 bit block and outputs a 2 bit block according
# to the S2 table.
#
def SFunction2(right_block):
    # 1) Get i and j 
    temp = BitArray('0b00')     
    temp[0] = right_block[0]
    temp[1] = right_block[3]

    i = temp.uint
 
    temp[0] = right_block[1]
    temp[1] = right_block[2]

    j = temp.uint

    # 2) Get number at (i, j) of S-box 1 and convert to binary
    temp.uint = S_BOX_2[i][j]
    
    # 3) Return block
    return temp

    
#
# CipherFunction is the equivalent to function f in the specifications document.
#
def CipherFunction(input_block, input_key):
    # 1) Expand the block to 8 bits using E-bit selection table.
    expanded_block =  BitArray('0b00000000')
    for i in range(8):
        expanded_block[i] = input_block[E_BIT_TABLE[i] - 1]

    # 2) XOR 8 bit block with 8 bit round key.
    xor_block = expanded_block ^ input_key
    
    # 3) Break the 8 bit block into two 4 bit halves.
    xor_block_l = xor_block[:4]
    xor_block_r = xor_block[4:]
    
    # 3) Input left half into S-box 1 and the right half into S-box 2
    temp_block = SFunction1(xor_block_l) + SFunction2(xor_block_r)
    
    # 4) Take the permutation P of the resulting 4 bit block.
    final_block = BitArray('0b0000')
    for i in range(4):
        final_block[i] = temp_block[PERM_P[i] - 1]

    # 5) Output the block.
    return final_block

#
# SDES is the main encryption algorithm.
# initial_block is the block to be encrypted.
# initial_key is the main key to be used in the algorithm.
# mode specifies whether the algorithim is for encryption or decryption.
# Set mode to 0 for encryption or 1 for decryption.
#
def SDES(initial_block, initial_key, mode):
    # 1) The input block is subjected to an initial permutation.
    permuted_block = BitArray('0b00000000')
    for i in range(8):
        permuted_block[i] = initial_block[INIT_PERM[i] - 1]
        
    # 2) The permuted block must be broken in to two halves.
    left_half = permuted_block[:4]
    right_half = permuted_block[4:]

    if (mode == 1):
        round_num = 2
    else:
        round_num = 1
        
    for i in range(2):
        # 3) Get round key
        if (round_num == 2):
            round_key = GenKey(initial_key, round_num + 1)
        else:
            round_key = GenKey(initial_key, round_num)
        
        # 4) Input right half and round key into the cipher function.
        temp_block = right_half
        right_half = CipherFunction(right_half, round_key) ^ left_half
        left_half = temp_block

        if (mode == 1):
            round_num = round_num - 1
        else:
            round_num = round_num + 1
        
    # 5) Subject the block to the inverse permutation.
    combined_block = right_half + left_half
    inverse_block = BitArray('0b00000000')
    for i in range(8):
        inverse_block[i] = combined_block[INVERSE_PERM[i] - 1]
        
    # 6) Return output.
    return inverse_block


#
# MITM is the function used to perform the MITM attack.
# p1 and c1 are plaintext 1 and ciphertext 1 respectively. The attack will use
# this pair to generate the tables. The other pairs will be used to confirm the
# validity of the keys.
# DOES NOT RETURN THE KEYS. PRINTS OUT THE RESULTS TO STDOUT.
#
def MITM(p1, c1, p2, c2, p3, c3, p4, c4, p5, c5):
    print 'Starting a Meet-In-The-Middle attack...'
    
    # 1) Initialize list of size 2^10 (number of possible keys)
    possible_enc = [None] * 1024
    possible_dec = [None] * 1024

    # 2) Encrypt plaintext with all possible keys
    curr_key = BitArray('0b0000000000')
    for i in range(1023):
        possible_enc[i] = [curr_key.copy(), SDES(p1, curr_key, 0)]
        if i < 1023:
            curr_key.uint = curr_key.uint + 1
            
    # 3) Decrypt ciphertext with all possible keys
    curr_key = BitArray('0b0000000000')
    for i in range(1023):
        possible_dec[i] = [curr_key.copy(), SDES(c1, curr_key, 1)]
        if i < 1023:
            curr_key.uint = curr_key.uint + 1

    # 4) Search for matches between tables
    match_key1 = BitArray('0b0000000000')
    match_key2 = BitArray('0b0000000000')
    found_match = False
    for i in range(1023):
        for j in range(1023):
            if (found_match):
                break
            if (possible_enc[i][1] == possible_dec[j][1]):
                # 5) Check match with other p/c pairs
                if (SDES(p2, possible_enc[i][0], 0) == SDES(c2, possible_dec[j][0], 1) and
                    SDES(p3, possible_enc[i][0], 0) == SDES(c3, possible_dec[j][0], 1) and
                    SDES(p4, possible_enc[i][0], 0) == SDES(c4, possible_dec[j][0], 1) and
                    SDES(p5, possible_enc[i][0], 0) == SDES(c5, possible_dec[j][0], 1)):
                    match_key1 = possible_enc[i][0]
                    match_key2 = possible_dec[j][0]
                    found_match = True
                    break
        if (found_match):
            break
        

    if (found_match):
        print 'Match found!'
        print 'key1 is ', match_key1.bin
        print 'key2 is ', match_key2.bin
    else:
        print 'Match not found :( Try something else!'
            

#
# BruteForce performs a brute force attack against 2SDES
#
def BruteForce(p1, c1, p2, c2, p3, c3, p4, c4, p5, c5):
    print 'Starting a brute force attack...'
    
    # 1) Encrypt with every possible key.
    curr_key1 = BitArray('0b0000000000')
    curr_key2 = BitArray('0b0000000000')
    match_key1 = BitArray('0b0000000000')
    match_key2 = BitArray('0b0000000000')
    found_match = False
    for i in range(1023):
        first_enc = SDES(p1, curr_key1, 0)
        # 2) Encrypt that again with every possible key
        for j in range(1023):
            if (found_match):
                break
            
            second_enc = SDES(first_enc, curr_key2, 0)
            # 3) Check if the ciphertext generated matches ciphertext given.
            if (second_enc == c1):
                # 4) If matches, confirm with other p/c pairs.
                if (SDES(SDES(p2, curr_key1, 0), curr_key2, 0) == c2 and
                    SDES(SDES(p3, curr_key1, 0), curr_key2, 0) == c3 and
                    SDES(SDES(p4, curr_key1, 0), curr_key2, 0) == c4 and
                    SDES(SDES(p5, curr_key1, 0), curr_key2, 0) == c5):
                    match_key1 = curr_key1.copy()
                    match_key2 = curr_key2.copy()
                    found_match = True
                    break
           
            if j < 1023:
                curr_key2.uint = curr_key2.uint + 1
        if (found_match):
            break
        if (i < 1023):
            curr_key1.uint = curr_key1.uint + 1
            curr_key2 = BitArray('0b0000000000')

    if (found_match):
        print 'Match found!'
        print 'key1 is ', match_key1.bin
        print 'key2 is ', match_key2.bin
    else:
        print 'Match not found :( Try something else!'
    

#
# CBC_decrypt takes in blocks of ciphertext and decodes it using CBC mode in conjection with 2SDES
#
def CBC_decrypt(ciphertext, key1, key2, i_vector):
    print 'Starting a CBC decryption of the given ciphertext...'
    
    # 1) Process the ciphertext by 8 bit bocks until the length is 0.
    cipher_copy = ciphertext.copy()
    plaintext = None
    prev_block = BitArray('0b00000000')
    while (cipher_copy.len > 0):
        curr_block = cipher_copy[:8]
        cipher_copy = cipher_copy[8:]
        
        # 2) Decrypt the current block.
        if plaintext == None:
            plaintext = SDES(SDES(curr_block, key2, 1), key1, 1) ^ i_vector
        else:
            plaintext = plaintext + (SDES(SDES(curr_block, key2, 1), key1, 1) ^ prev_block)
        prev_block = curr_block.copy()
        
    print 'CBC decryption of the ciphertext complete!'
    print 'Plaintext:'
    print plaintext.bin
    print 'The ASCII representation is: '
    print plaintext.hex.decode("hex")

   

        
p1 = BitArray('0b01101011')
c1 = BitArray('0b11001000')
p2 = BitArray('0b10010110')
c2 = BitArray('0b00000111')
p3 = BitArray('0b00101011')
c3 = BitArray('0b00010010')
p4 = BitArray('0b10101010')
c4 = BitArray('0b10011011')
p5 = BitArray('0b00011100')
c5 = BitArray('0b10100000')


#MITM(p1, c1, p2, c2, p3, c3, p4, c4, p5, c5)
#BruteForce(p1, c1, p2, c2, p3, c3, p4, c4, p5, c5)

ciphertext = BitArray('0xd06699c35238750bf6ebd1b33f28ea132dd2cb23750b726bc181fac5315a6a40')
init_vector = BitArray('0x9c')
key1 = BitArray('0b1011101001')
key2 = BitArray('0b0111011010')
CBC_decrypt(ciphertext, key1, key2, init_vector)



    
    
