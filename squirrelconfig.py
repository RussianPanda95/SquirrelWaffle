import pefile

data = open('path to the payload', 'rb').read()

# getting the data
pe = pefile.PE(data=data)

for i in pe.sections:
    if b'.rdata' in i.Name:
        rdata = i.get_data()

# split the null bytes
data_blocks = rdata.split(b'\x00')

# removing empty strings
data_blocks = [x for x in data_blocks if x != b'']

# sort the keys by size 
data_block_sorted = sorted(data_blocks, key=len)

# XOR decryption function
def decrypt(key, data):
    decrypted_config = ''
    for f in range(len(data)):
        decrypted_config += chr(data[f] ^ key[f % len(key)])
    return decrypted_config

# extracting the IPs
for f in range (len(data_blocks)):
    if data_blocks[f] == data_block_sorted[-1]:
        decrypted_config_ips = decrypt(data_blocks[f+1], data_blocks[f])

# extracting the domains
for f in range (len(data_blocks)):
    if data_blocks[f] == data_block_sorted[-2]:
        decrypted_config_domains = decrypt(data_blocks[f+1], data_blocks[f])

print(f'IPs: {decrypted_config_ips} \n')

print ('Domains:', decrypted_config_domains.replace('|', '\n'))