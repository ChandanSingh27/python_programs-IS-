
#s0 tables values return
def s0_table(rows,column):
    lists=[[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
    return lists[rows][column]

def s1_table(rows,column):
    lists=[[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
    return lists[rows][column]

def ip_table(list):
    index = [1,5,2,0,3,7,4,6]
    data = []
    for i in range(0,8):
        data.append(list[index[i]])
    return data

def ip_inverse_table(list):
    index = [3,0,2,4,6,1,7,5]
    data = []
    for i in range(0,8):
        data.append(list[index[i]])
    return data

def p4_table(list):
    index = [1,3,2,0]
    data = []
    for i in range(0,4):
        data.append(list[index[i]])
    return data

def expand_table(list):
    index = [3,0,1,2,1,2,3,0]
    data = []
    for i in range(0,8):
        data.append(list[index[i]])
    return data

def divide_bits(list):
    left_parts = []
    right_parts = []
    for i in range(0,len(list)):
        if i < len(list)//2:
            left_parts.append(list[i])
        else:
            right_parts.append(list[i])
    return left_parts,right_parts

def xor(list1,list2):
    ints = ""
    xor_data = []
    xor_value = []
    for i in range(0,len(list1)):
        expands = int(list1[i])
        key = int(list2[i])
        value = expands ^ key
        xor_data.append(value)
        ints += str(xor_data[i])
    xor_value.extend(ints)
    return xor_value

def find_rows_column(s0):
    index_of_s0 = []
    if s0[0] == '0':
        if s0[3] == '0':
            index_of_s0.append(0)
        else:
            index_of_s0.append(1)
    elif s0[0] == '1':
        if s0[3] == '0':
            index_of_s0.append(2)
        else:
            index_of_s0.append(3)
    if s0[1] == '0':
        if s0[2] == '0':
            index_of_s0.append(0)
        else:
            index_of_s0.append(1)
    elif s0[1] == '1':
        if s0[2] == '0':
            index_of_s0.append(2)
        else:
            index_of_s0.append(3)
    return index_of_s0


def fk_function(plaintext,key,flag):
    #now convert into ip
    ip_value = ip_table(plaintext)

    #now dividing ip_value into 4-4 bits
    #we getting 4-4 bits. Starting 4-bits store in ip_left parts and next 4-bits store in ip_right parts. 
    ip_left,ip_right = divide_bits(ip_value if flag == 0 else plaintext)

    #4-bits ip_right parts send to the expand table.And we getting 8-bits from expand_table
    expand_value = expand_table(ip_right)

    #now performing xor operation between expand_value and key1.And storing result in after_xor 
    after_xor = xor(expand_value,key)

    #Again divide 4-4 bits.And left parts passing to the s0_value.
    #Right parts passing to the s1_value.
    s0_value,s1_value = divide_bits(after_xor)

    #form s0_value,s1_value finding the index of row and column.
    s0_value_rows_column = find_rows_column(s0_value)
    s1_value_rows_column = find_rows_column(s1_value)

    #finding the value of given index of row and column from s0_table or s1_table
    s0_table_value = s0_table(s0_value_rows_column[0],s0_value_rows_column[1])
    s1_table_value = s1_table(s1_value_rows_column[0],s1_value_rows_column[1])

    #now create we creating empty list
    data = []
    """
    We add s0_table_value and s1_table_value in binary form into the data list.
    example :
        s0_table_value = 3
        s1_table_value = 2
        convert both value in binary form like (1110)
        Extend these binary value into data[] list like ['1','1','1','0'].
    """
    data.extend(str(bin(s0_table_value)[2:].zfill(2)+""+bin(s1_table_value)[2:].zfill(2)))

    #data [] list passing to the p4_table.And storing the value in p4_table_value.
    p4_table_value = p4_table(data)

    #now performing xor operations between p4_table_value and ip_left.
    p4_table_value_xor_ip_left = xor(p4_table_value,ip_left)
    ip_right1 = ip_right.copy() 

    if flag == 0:   
        p4_table_value_xor_ip_left,ip_right1 = ip_right1,p4_table_value_xor_ip_left
        swapping = p4_table_value_xor_ip_left + ip_right1
        return swapping
    else:
        union_of_p4_ip_right = p4_table_value_xor_ip_left+ip_right1
        return ip_inverse_table(union_of_p4_ip_right)

#method for converting list into string
def convert_into_string(s):
    ciphertext = ""
    # traverse in the string
    for x in s:
        ciphertext += x 
    # return string
    return ciphertext       

#Take input from user
def encryption():
    #taking input for the plaintext
    input_plaintext = input("Enter the Plaintext : ")
    input_key1 = input("Enter the Key 1 : ")
    input_key2 = input("Enter the Key 2 : ")

    #now converting input data into list data structure
    plaintext = []
    key1 = []
    key2 = []
    plaintext.extend(input_plaintext)
    key1.extend(input_key1)
    key2.extend(input_key2)

    ciphertext_values = fk_function(fk_function(plaintext,key1,0),key2,1)
    print("Ciphertext : ",convert_into_string(ciphertext_values))

def decryption():
    #taking input for the plaintext
    input_cipher = input("Enter the Ciphertext : ")
    input_key1 = input("Enter the Key 1 : ")
    input_key2 = input("Enter the Key 2 : ")

    #now converting input data into list data structure
    ciphertext = []
    key1 = []
    key2 = []
    ciphertext.extend(input_cipher)
    key1.extend(input_key1)
    key2.extend(input_key2)

    plaintext_value = fk_function(fk_function(ciphertext,key2,0),key1,1)
    print("Plaintext : ",convert_into_string(plaintext_value))    

#method for displaying menu to the user
def menu():
    flag = True
    while flag:
        print("1. Encryption")
        print("2. Decryption")
        print("3. Exit")
        print("Enter your Choice : ",end="")
        choice = int(input())
        if choice == 1:
            encryption()
        elif choice == 2:
            decryption()
        else:
            flag = False
        print()
#here the programs are started
menu()