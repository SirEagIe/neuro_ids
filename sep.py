import random

with open('Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv', 'r+') as file:
    lines = file.readlines()

labels = []
b, d = 0, 0

with open('train.csv', 'w+') as file:
    file.write(lines[0])
    for line in lines[1:len(lines)//2]:
        file.write(line)

with open('test.csv', 'w+') as file:
    file.write(lines[0])
    for line in lines[len(lines)//2:]:
        file.write(line)
        

