from QRED.QRED import *

if __name__ == "__main__":
    dict = {}
    dict['string1'] = 1
    dict['string2'] = 2
    print(dict[None])


    # flags = "00"
    # i = int(flags, 16)
    # for i in range(0, 256):
    #     string = str(hex(i))
    #     string = string[2:]
    #     if len(string) == 1:
    #         string = "0" + string
    #
    #     # print("string is:", string)
    #     if get_delay_from_flags(string) != bool(i & 0x10):
    #         print("problem!")
    #     # if :
    #     #     print("success on", hex(i))
