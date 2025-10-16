# encode.py
# random.seed(65537)

# random_ops = [
#     lambda x: x+3,
#     lambda x: x-3,
#     lambda x: x*3,
#     lambda x: x^3,
# ]

# flag = list(open("flag.txt", "rb").read())
# enc_flag = []

# for value in flag:
#     enc_flag.append(random.choice(random_ops)(value))
    
# with open("flag.txt.enc", "w") as output_flag:
#     output_flag.write(str(enc_flag))

import random

# Recreate the same sequence of random operations
random.seed(65537)

# Define a set of operations and their corresponding inverse operations
random_ops = [
    (lambda x: x + 3, lambda x: x - 3),
    (lambda x: x - 3, lambda x: x + 3),
    (lambda x: x * 3, lambda x: x // 3),
    (lambda x: x ^ 3, lambda x: x ^ 3),
]

# Given encoded flag
enc_flag = [69, 79, 195, 68, 120, 306, 49, 104, 54, 285, 99, 51, 342, 92, 348, 153, 345, 113, 52, 109, 309, 128]

# Reverse the encoding process by applying the inverse operations
decoded_flag = []
for value in enc_flag:
    # Choose a random operation and its inverse
    op, inverse_op = random.choice(random_ops)
    
    # Apply the inverse operation to retrieve the original byte value
    decoded_flag.append(inverse_op(value))

# Convert the decoded byte values back to a string
flag_str = ''.join(map(chr, decoded_flag))

# Output the decoded flag
print("Decoded Flag:", flag_str)