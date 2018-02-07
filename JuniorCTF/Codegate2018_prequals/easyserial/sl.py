import string

u = [i for i in string.uppercase]
l = [i for i in string.lowercase]
d = [i for i in '1234567890']

in1 = [70, 108, 97, 103, 123, 83, 48, 109, 101, 48, 102, 85, 53]
in2 = [103, 110, 105, 107, 48, 48, 76, 51, 114, 52]; in2.reverse()
in3 = [u[0],l[19],u[19],l[7],d[2],u[18],l[19],d[3],l[17],l[18]]

flag = "".join([chr(i) for i in in1]) + "#"
flag += "".join([chr(i) for i in in2]) + "#"
flag += "".join(in3)

print "FLAG : " + flag

