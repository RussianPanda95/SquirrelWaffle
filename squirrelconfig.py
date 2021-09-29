import pefile

data = open('C:\\Users\\annap\\Desktop\\Malware\\squirrel.bin', 'rb').read()

# getting the data
pe = pefile.PE(data=data)

for i in pe.sections:
    if b'.rdata' in i.Name:
        rdata = i.get_data()

# split the null bytes
blocks = rdata.split(b'\x00')

# removing empty strings
blocks = [x for x in blocks if x != b'']

# sort the keys by size 
block_sorted = sorted(blocks, key=len)

# XOR decryption function
def decrypt(key, data):
    decrypted_config = ''
    for f in range(len(data)):
        decrypted_config += chr(data[f] ^ key[f % len(key)])
    return decrypted_config

# extracting the IPs
for f in range (len(blocks)):
    if blocks[f] == block_sorted[-1]:
        decrypted_config_ips = decrypt(blocks[f+1], blocks[f])

# extracting the domains
for f in range (len(blocks)):
    if blocks[f] == block_sorted[-2]:
        decrypted_config_domains = decrypt(blocks[f+1], blocks[f])

print(f'IPs: {decrypted_config_ips} \n')

print ('Domains:', decrypted_config_domains.replace('|', '\n'))