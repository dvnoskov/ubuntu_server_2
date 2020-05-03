#-------------------------------------------------------------------
# v01.2020
# records- A,TXT,SOA,NS
# project AAAA,RFC 2136, 2535,4043,4044,4045
#
#-------------------------------------------------------------------

import binascii
import socket
import base64
import time


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))


def hex2str(h):
    return binascii.unhexlify(h)


def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """
    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(binascii.unhexlify(message), server_address)
        sock.settimeout(1)
        data, _ = sock.recvfrom(1024)
    except socket.error:
        sock.close()
        print('socket error')
    else:
        sock.close()
        return binascii.hexlify(data).decode("utf-8")


def List_callback():
    # distionary answer dns server
    #
    print(response)
    List_in = {}
    List_in["ID"] = response[0:4]
    id4 = ("{0:4b}".format(int(response[4:5], 16)) + "{0:4b}".format(int(response[5:6], 16)) +
           '{0:4b}'.format(int(response[6:7], 16)) + '{0:4b}'.format(int(response[7:8], 16)))

    i = 0
    id4_1 = {}
    while i <= 15:
        if id4[i] == "1":
            id4_1[i] = "1"
          #  i = i + 1
        else:
            id4_1[i] = "0"
        i = i + 1

    List_in["QR"] = id4_1[0]
    List_in["OPCODE"] = id4_1[1] + id4_1[2] + id4_1[3] + id4_1[4]
    List_in["AA"] = id4_1[5]
    List_in["TC"] = id4_1[6]
    List_in["RD"] = id4_1[7]
    List_in["RA"] = id4_1[8]
    List_in["Z"] = id4_1[9] + id4_1[10] + id4_1[11]
    List_in["RCODE"] = id4_1[12] + id4_1[13] + id4_1[14] + id4_1[15]
    List_in["QDCOUNT"] = response[8:12]
    List_in["ANCOUNT"] = response[12:16]
    List_in["NSCOUNT"] = response[16:20]
    List_in["ARCOUNT"] = response[20:24]
    i = (int((response[24:26]), 16))
    y = i

    while True:
        if (response[(26 + y * 2):(28 + y * 2)]) == "00":
            z = y
            List_in["QNAME"] = response[24:28 + y * 2]
            break
        else:
            i = (int((response[(26 + y * 2):(28 + y * 2)]), 16))
            y = y + i + 1

    if List_in["Z"] != "000":
        List_in["D0"] = List_in["Z"][0]
        List_in["AD"] = List_in["Z"][1]
        List_in["CD"] = List_in["Z"][2]
    else:
        List_in["D0"] = "0"
        List_in["AD"] = "0"
        List_in["CD"] = "0"

    List_in["QTYPE"] = response[(28 + z * 2):(32 + z * 2)]
    List_in["LIST_IN"] = response
    List_in["QCLASS"] = response[(32 + z * 2):(36 + z * 2)]
    if List_in["RCODE"] == "0000":
        List_in["NAME"] = response[(36 + z * 2):(40 + z * 2)]
        List_in["TYPE"] = response[(40 + z * 2):(44 + z * 2)]
        List_in["CLASS"] = response[(44 + z * 2):(48 + z * 2)]
        List_in["TTL"] = response[(48 + z * 2):(56 + z * 2)]
        List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]
    elif  response[(36 + z * 2):(38 + z * 2)] == "c0":
        List_in["NAME"] = response[(36 + z * 2):(40 + z * 2)]
        List_in["TYPE"] = response[(40 + z * 2):(44 + z * 2)]
        List_in["CLASS"] = response[(44 + z * 2):(48 + z * 2)]
        List_in["TTL"] = response[(48 + z * 2):(56 + z * 2)]
        List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]
    elif  response[(36 + z * 2):(38 + z * 2)] == "00":
        List_in["NAME"] = response[(36 + z * 2):(38 + z * 2)]
        List_in["TYPE"] = response[(38 + z * 2):(42 + z * 2)]
        List_in["CLASS"] = response[(42 + z * 2):(46 + z * 2)]
        List_in["TTL"] = response[(46 + z * 2):(54 + z * 2)]
        List_in["RDLENGTH"] = response[(54 + z * 2):(58 + z * 2)]


   # List_in["ARCOUNT_new"] = "0001"
    if List_in["TYPE"] == "0001" and List_in["ANCOUNT"] == "0001" and List_in["RCODE"] == "0000": # A(0001)
        List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]   #"0004":  #RDLENGTH
        List_in["RDDATA"] = response[(60 + z * 2):(68 + z * 2)]

    elif List_in["TYPE"] == "0001" and List_in["ANCOUNT"] != "0001" and List_in["RCODE"] == "0000":
        List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]  # "0004":  #RDLENGTH
        List_in["RDDATA"] = response[(60 + z * 2):(68 + z * 2)]
        List_in["KEY_z"] = z

    elif List_in["TYPE"] == "001c" and List_in["ANCOUNT"] == "0001" and List_in["RCODE"] == "0000": # AAAA (28) 001C
        List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]   #"0010":  #RDLENGTH
        List_in["RDDATA"] = response[(60 + z * 2):(76 + z * 2)]

    elif List_in["TYPE"] == "001c" and List_in["ANCOUNT"] != "0001" and List_in["RCODE"] == "0000": #AAAA (28) 001C
        List_in["RDLENGTH"] = response[(56 + z * 2):(60 + z * 2)]  # "0010":  #RDLENGTH
        List_in["RDDATA"] = response[(60 + z * 2):(76 + z * 2)]
        List_in["KEY_z"] = z


    elif List_in["TYPE"] == "0006" and( List_in["NSCOUNT"] == "0001" or List_in["ANCOUNT"] == "0001"):  # 'SOA (6) 0110'
        if response[(36 + z * 2):(38 + z * 2)] == "00":
            List_in["SOA"] = response[(58 + z * 2):]
        else:
            List_in["SOA"] = response[(60 + z * 2):]

        sta = 0
        while True:
            if List_in["SOA"][ sta: sta + 2] == "00" or List_in["SOA"][ sta: + sta + 2] == "c0":
                if List_in["SOA"][ sta:  sta + 2] == "c0":
                    st = int(List_in["SOA"][2 + sta:2 + sta + 2], 16)
                    sto = 0
                    while True:
                        if List_in["LIST_IN"][st * 2 + sto:st * 2 + 2 + sto] == "00":
                            List_in["MNAME"] = List_in["SOA"][0:  sta] + List_in["LIST_IN"][st * 2:st * 2 + 2 + sto]
                            break
                        else:
                            sto = sto + 2
                    break
                else:
                    List_in["MNAME"] = List_in["SOA"][0:0 + sta]
                    break
            else:
                sta = sta + 2

        sta1 = 2 + sta
        while True:
            if List_in["SOA"][2 + sta:2 + sta + 2] == "00" or List_in["SOA"][2 + sta:2 + sta + 2] == "c0":
                if List_in["SOA"][2 + sta:2 + sta + 2] == "c0":
                    st = int(List_in["SOA"][4 + sta:4 + sta + 2], 16)
                    sto = 0
                    while True:
                        if List_in["LIST_IN"][st * 2 + sto:st * 2 + 2 + sto] == "00"\
                                or List_in["LIST_IN"][st * 2 + sto:st * 2 + 2 + sto] == "c0":
                            List_in["RNAME"] = List_in["SOA"][sta1:2 + sta] + List_in["LIST_IN"][st * 2:st * 2  + sto]
                            break
                        else:
                            sto = sto + 2
                    break
                else:
                    List_in["RNAME"] = List_in["SOA"][sta1:2 + sta]
                    break
            else:
                sta = sta + 2

        sta = sta + 4
      #  sta = sta + 2
        List_in["SERIAL"] = List_in["SOA"][2 + sta:10 + sta]
        List_in["REFRESH"] = List_in["SOA"][10 + sta:18 + sta]
        List_in["RETRY"] = List_in["SOA"][18 + sta:26 + sta]
        List_in["EXPIRE"] = List_in["SOA"][26 + sta:34 + sta]
        List_in["MINIMUM"] = List_in["SOA"][34 + sta:]


    elif List_in["TYPE"] == "0010" and( List_in["NSCOUNT"] == "0001" or List_in["ANCOUNT"] == "0001"):  # 'TXT (16) 0010'
        List_in["TXT"] = response[(60 + z * 2):]
        List_in["TXT-DATA"] = List_in["TXT"][0:]


    elif List_in["TYPE"] == "0010" and ( List_in["NSCOUNT"] != "0001" or List_in["ANCOUNT"] != "0001"):  # 'TXT (16) 0010'
        List_in["TXT"] = response[(60 + z * 2):]
        List_in["TXT-DATA"] = List_in["TXT"][0:]

    elif List_in["TYPE"] == "0019":  # 'KEY (25) 0019'
        List_in["KEY"] = response[(60 + z * 2):]
        List_in["flags"] = List_in["KEY"][0:4]
        List_in["protocol"] = List_in["KEY"][4:6]
        List_in["algorithm"] = List_in["KEY"][6:8]
        List_in["public_key"] = List_in["KEY"][8:]

    elif List_in["TYPE"] == "0030":  # 'DNSKEY (48) 0030'
        List_in["KEY"] = response[(60 + z * 2):]
        List_in["flags"] = List_in["KEY"][0:4]
        List_in["protocol"] = List_in["KEY"][4:6]
        List_in["algorithm"] = List_in["KEY"][6:8]
        List_in["public_key"] = List_in["KEY"][8:]


    elif List_in["TYPE"] == "002e":  # '#RRSIG (46) 002E'
        List_in["KEY"] = response[(60 + z * 2):]
        List_in["type_cover"] = List_in["KEY"][0:4]
        List_in["algorithm"] = List_in["KEY"][4:6]
        List_in["labels"] = List_in["KEY"][6:8]
        List_in["orig_ttl"] = List_in["KEY"][8:16]
        List_in["sig_exp"] = List_in["KEY"][16:24]
        List_in["sig_ince"] = List_in["KEY"][24:32]
        List_in["key_tag"] = List_in["KEY"][32:36]
        sta = 0
        while True:
            if List_in["KEY"][36+sta: 36+sta + 2] == "00" or List_in["KEY"][36+sta: 36 + sta + 2] == "c0":
                if List_in["KEY"][36+sta: 36+ sta + 2] == "c0":
                    st = int(List_in["KEY"][36+2 + sta:36+2 + sta + 2], 16)
                    sto = 0
                    while True:
                        if List_in["LIST_IN"][st * 2 + sto:st * 2 + 2 + sto] == "00":
                            List_in["sig_name"] = List_in["KEY"][36:  sta] + List_in["LIST_IN"][st * 2:st * 2 + 2 + sto]
                            break
                        else:
                            sto = sto + 2
                    break
                else:
                    List_in["sig_name"] = List_in["KEY"][36:36 + sta]
                    break
            else:
                sta = sta + 2
       # List_in["sig_name"] = List_in["KEY"][36:]
        List_in["Signature"] = List_in["KEY"][36 + sta + 4:]


    elif List_in["TYPE"] == "002b" and List_in["NSCOUNT"] == "0001":  # 'DS (43) 002B'
        List_in["KEY"] = response[(60 + z * 2):]
        List_in["key tag"] = List_in["KEY"][0:4]
        List_in["algorithm"] = List_in["KEY"][4:6]
        List_in["Digest type"] = List_in["KEY"][6:8]
        List_in["Digest"] = List_in["KEY"][8:] #(length depends on type)

    elif List_in["TYPE"] == "002b" and List_in["NSCOUNT"] != "0001":  # 'DS (43) 002B'
        List_in["KEY"] = response[(60 + z * 2):]

    elif List_in["TYPE"] == "0002" :  # 'NS (2) 0002'
        List_in["NS"] = response[(60 + z * 2):]

    else:
        pass

    List_in["LIST_IN"] = response
    print(List_in)
    return List_in


def List_read_in(List_in):
    # Decode answer distionary answer dns server
    #
    for i in List_in.values():
        if i == "Att_Error":
            print('Error DNS name ,not ip adress')

    print("--------------------------------------------------------------------------------------------------------")
    print("")
    print("")
    print("ID      :" + "  indification request                                          " + List_in.get("ID"))
    print("        QR :" + "  request(0) or answer(1)                                    " + List_in.get("QR"))
    print("        OPCODE :" + "Code status(0-st.req,1-inv.req,2-stat.ser,3-15-reserv)   " + List_in.get("OPCODE"))
    print("        AA :" + "  indification request                                       " + List_in.get("AA"))
    print("        TC :" + "  TrunCation                                                 " + List_in.get("TC"))
    print("        RD :" + "  Recursion Desired                                          " + List_in.get("RD"))
    print("        RA :" + "  Recursion Available                                        " + List_in.get("RA"))
    print("        Z  :" + "  Reservation                                                " + List_in.get("Z"))
    print("        D0  :" + "  DNSSEC OK  D0-RFC 3225                               " + List_in.get("D0"))
    print("        AD  :" + "  AD RFC 4035                                          " + List_in.get("AD"))
    print("        CD  :" + "  CD RFC 4035                                          " + List_in.get("CD"))
    print("        RCODE   :" + " Code answer(0,1,2,3,4,5,6-15)                          " + List_in.get("RCODE"))
    if  List_in["RCODE"] == "0000":
        print("                                  Code answer = NoError (0)")
    elif List_in["RCODE"] == "0001":
        print("                                  Code answer = FormErr (1)")
    elif List_in["RCODE"] == "0010":
        print("                                  Code answer = ServFail (2)")
    elif List_in["RCODE"] == "0011":
        print("                                  Code answer = NXDomain (3)")
    elif List_in["RCODE"] == "0100":
        print("                                  Code answer = NotImp (4)")
    elif List_in["RCODE"] == "0101":
        print("                                  Code answer = Refused (5)")
    elif List_in["RCODE"] == "0110":
        print("                                  Code answer = YXDomain (6)")
    elif List_in["RCODE"] == "0111":
        print("                                  Code answer = YXRRSet (7)")
    elif List_in["RCODE"] == "1000":
        print("                                  Code answer = NXRRSet (8)")
    elif List_in["RCODE"] == "1001":
        print("                                  Code answer = NotAuth (9)")
    elif List_in["RCODE"] == "1010":
        print("                                  Code answer = NotZone (10)")
    else:
        print("                                  Code answer = ")
    print("QDCOUNT :" + " quantity element answer                                        " + List_in.get("QDCOUNT"))
    print("ANCOUNT :" + " quantity resurs answer                                         " + List_in.get("ANCOUNT"))
    print("NSCOUNT :" + " quantity record server recurs                                  " + List_in.get("NSCOUNT"))
    print("ARCOUNT :" + " quantity record server recurs additionally                     " + List_in.get("ARCOUNT"))

    l = (int((List_in.get("QNAME")[0:2]), 16))
    qname = (List_in.get("QNAME")[2: 2 + l * 2])
    while True:
        if (List_in.get("QNAME")[2 + l * 2:4 + l * 2]) == "00":
            break
        else:
            m = int(List_in.get("QNAME")[2 + l * 2:4 + l * 2], 16)
            qname = qname + "2e" + (List_in.get("QNAME")[4 + l * 2:4 + (l + m) * 2])
            l = l + m + 1

    print("QNAME :" + " domain name                                                      " + hex2str(qname).decode(
        'utf-8'))
    print("QTYPE :" + " type request                                                     " + List_in.get("QTYPE"))
    print("QCLASS:" + " type class request                                               " + List_in.get("QCLASS"))
    print("--------------------------------------------------------------------------------------")

    if List_in["NAME"] == "00":
        print("NAME :" )
    else :
      #  List_in.get("NAME") is not None:
        id4 = bin(int(List_in.get("NAME"), 16))
        stpname = int(id4[4:18], 2)
        name_lend = int(List_in.get("LIST_IN")[0 + stpname * 2:2 + stpname * 2], 16)
        start_ind = 2 + stpname * 2
        stop_ind = 2 + stpname * 2 + name_lend * 2
        name = List_in.get("LIST_IN")[start_ind:stop_ind]
        s = 2
        nam_lend = int(List_in.get("LIST_IN")[stop_ind:2 + stop_ind], 16)

        while True:
            if nam_lend == 00:
                break

            else:
                start_ind = s + stop_ind
                stop_ind = s + stop_ind + nam_lend * 2
                name = name + "2e" + (List_in.get("LIST_IN")[start_ind:stop_ind])
                nam_lend = int(List_in.get("LIST_IN")[stop_ind:2 + stop_ind], 16)

          #  List_in["NAME"] == "c00c":
        print("NAME :" + " Name                                                              " + hex2str(name).decode('utf-8'))
    print("TYPE :" + " Type                                                              " + List_in.get("TYPE"))
    print("CLASS :" + " Class                                                            " + List_in.get("CLASS"))
    print("TTL :" + " Time    sek                                                        " + str(
        int(List_in.get("TTL"), 16)))
    print(
        "RDLENGTH :" + " lend RDDATA                                                   " + List_in.get("RDLENGTH"))
    print("--------------------------------------------------------------------------------------")
    if List_in["TYPE"] == "0001" and  List_in["ANCOUNT"] == "0001":  # A(0001)
        print("RDDATA :" + "   IP ADRESS" + "                                                     " + ".".join(
                (str(int((List_in.get("RDDATA")[0:2]), 16)),
                 (str(int((List_in.get("RDDATA")[2:4]), 16))),
                 (str(int((List_in.get("RDDATA")[4:6]), 16))),
                 (str(int((List_in.get("RDDATA")[6:8]), 16))))))

    elif List_in["TYPE"] == "0001" and  List_in["ANCOUNT"] != "0001":  # A(0001):
            print("RDDATA :" + "   IP ADRESS" + "                                                     " + ".".join(
                (str(int((List_in.get("RDDATA")[0:2]), 16)),
                (str(int((List_in.get("RDDATA")[2:4]), 16))),
                (str(int((List_in.get("RDDATA")[4:6]), 16))),
                (str(int((List_in.get("RDDATA")[6:8]), 16))))))
            start = 2
            count = int(List_in.get("ANCOUNT"))
            z1 = int(List_in.get("KEY_z"))
            while True:
                if start > count:
                    break
                else:
                    List_in["KEY"] = response[(68 + z1 * 2):(100 + z1 * 2)]
                   # print(List_in["KEY"])
                    print(
                        "RDDATA :" + "   IP ADRESS" + "                                                     " + ".".join(
                            (str(int((List_in.get("KEY")[-8:-6]), 16)),
                            (str(int((List_in.get("KEY")[-6:-4]), 16))),
                            (str(int((List_in.get("KEY")[-4:-2]), 16))),
                            (str(int((List_in.get("KEY")[-2:]), 16))))))

                    start = start + 1
                    z1 = z1 + 16

    elif List_in["TYPE"] == "001c" and  List_in["ANCOUNT"] == "0001":  # AAAA(001c) # 28
           print("RDDATA :" + "   IP ADRESS" + "                                                     " + ":".join(
                 (str(List_in.get("RDDATA")[0:2]),
                 (str(List_in.get("RDDATA")[2:4])),
                 (str(List_in.get("RDDATA")[4:6])),
                 (str(List_in.get("RDDATA")[6:8])),
                 (str(List_in.get("RDDATA")[8:10])),
                 (str(List_in.get("RDDATA")[10:12])),
                 (str(List_in.get("RDDATA")[12:14])),
             (str(List_in.get("RDDATA")[14:16])))))

    elif List_in["TYPE"] == "001c" and List_in["ANCOUNT"] != "0001":  # AAAA(001c) # 28
            print("RDDATA :" + "   IP ADRESS" + "                                                     " + ":".join(
                (str(List_in.get("RDDATA")[0:2]),
                 (str(List_in.get("RDDATA")[2:4])),
                 (str(List_in.get("RDDATA")[4:6])),
                 (str(List_in.get("RDDATA")[6:8])),
                 (str(List_in.get("RDDATA")[8:10])),
                 (str(List_in.get("RDDATA")[10:12])),
                 (str(List_in.get("RDDATA")[12:14])),
                 (str(List_in.get("RDDATA")[14:16])))))
            start = 2
            count = int(List_in.get("ANCOUNT"))
            z1 = int(List_in.get("KEY_z"))
            while True:
                if start > count:
                    break
                else:
                    List_in["KEY"] = response[(68 + z1 * 2):(108 + z1 * 2)]
                    # ---------------------------------------------------------------------???????????????????????
                    print(
                        "RDDATA :" + "   IP ADRESS" + "                                                     " + ":".join(
                            (str(List_in.get("RDDATA")[-16:-14]),
                             (str(List_in.get("RDDATA")[-14:-12])),
                             (str(List_in.get("RDDATA")[-12:-10])),
                             (str(List_in.get("RDDATA")[-10:-8])),
                             (str(List_in.get("RDDATA")[-8:-6])),
                             (str(List_in.get("RDDATA")[-6:-4])),
                             (str(List_in.get("RDDATA")[-4:-2])),
                             (str(List_in.get("RDDATA")[-2:])))))

                    start = start + 1
                    z1 = z1 + 20

    elif List_in["TYPE"] == "0006"  and( List_in["NSCOUNT"] == "0001" or List_in["ANCOUNT"] == "0001"):  # SOA (0110) 6
        print("MNAME :" +  "MNAME                                    " + hex2str(List_in.get("MNAME")).decode('utf-8'))
        print("RNAME  :" + "RNAME                                    " + hex2str(List_in.get("RNAME")).decode('utf-8'))
        print("SERIAL :" + "                                         " + List_in.get("SERIAL"))
        print("REFRESH :" + "                                        " + str(int(List_in.get("REFRESH"), 16)))
        print("RETRY :" + "                                          " + str(int(List_in.get("RETRY"), 16)))
        print("EXPIRE :" + "                                         " + str(int(List_in.get("EXPIRE"), 16)))
        print("MINIMUM :" + "                                        " + str(int(List_in.get("MINIMUM"), 16)))



#    elif List_in["QTYPE"] == "0001" and List_in["ARCOUNT"] != "0000" and List_in["ARCOUNT_new"] != "0000":
    elif List_in["QTYPE"] == "0001" and List_in["ARCOUNT"] == "0001" :

        print("type_cover:" + "                                                  " + List_in.get("type_cover"))
        print("arlgorithm:" + "    value algorithm                               " + List_in.get("arlgorithm"))
        print("labels:" + "                                                      " + List_in.get("labels"))
        print("orig_ttl:" + "  original ttl kodes                                " + List_in.get("orig_ttl"))
        print("sig_exp:" + "    time end word                                    " + List_in.get("sig_exp"))
        print("sig_ince:" + "                                                    " + List_in.get("sig_ince"))
        print("key_tag:" + "   Key Tag Field                                     " + List_in.get("key_tag"))
        print("sig_name:" + "                                                    " + str(List_in.get("sig_name")))
        print("signature:" + "     " + List_in.get("signature"))

    elif List_in["TYPE"] == "0010" and List_in["ANCOUNT"] == "0001" : # TXT
        print( "TXT-DATA:" + hex2str(List_in.get("TXT-DATA")).decode('utf-8'))

    elif List_in["TYPE"] == "0010" and List_in["ANCOUNT"] != "0001":  # TXT
            s = 0
            st = -4
            while s <= len(List_in["TXT-DATA"]):
                if List_in["TXT-DATA"][s:s + 2] == "c0":
                    if List_in["TXT-DATA"][s + 2:s + 4] == "0c":
                        print("TXT-DATA:" + hex2str(List_in["TXT-DATA"][st+4:s]).decode('utf-8'))
                        s = s + 4
                        st = s + 16 # out(16 bit)
                    else:
                        pass
                else:
                    s = s + 2
            print("TXT-DATA:" + hex2str(List_in["TXT-DATA"][st+4:s]).decode('utf-8'))

    elif List_in["TYPE"] == "0019":  # KEY
    #

        id5 = ("{0:4b}".format(int(List_in.get("flags")[0:1], 16)) + "{0:4b}".format(int(List_in.get("flags")[1:2], 16)) +
               '{0:4b}'.format(int(List_in.get("flags")[2:3], 16)) + '{0:4b}'.format(int(List_in.get("flags")[3:4], 16)))

        i = 0
        id5_1 = {}
        while i <= 15:
            if id5[i] == "1":
                id5_1[i] = "1"
            #    i = i + 1
            else:
                id5_1[i] = "0"
            #    i = i + 1
            i = i + 1

        key = id5_1[7]
        sep = id5_1[15]
        if key == "1":
            print("                 Ключ зоны DNS") # bit 0-6 and 8-14  default ==0
        else:
            print("                  Открытый ключ DNS")

        if sep == "1":
            print("DNSKEY содержит ключ [ RFC3757 ] SEP- Бит SEP рекомендуется устанавливать (равным 1) всякий раз, "
                  "когда открытый ключ пары ключей будет распространяться в родительскую зону для построения "
                  "цепочки аутентификации или если открытый ключ должен распространяться для статической "
                  "конфигурации в верификаторах. ")
        else:
            pass

        print("protocol:" + List_in.get("protocol"))
        if List_in["protocol"] != "03":
            print("Поле протокола ДОЛЖНО иметь значение 3, а DNSKEY RR ДОЛЖЕН "
                  "рассматриваться как недействительный во время проверки подписи, "
                  "если установлено, что оно имеет какое- либо значение, отличное от 3.")

        print("algorithm:      " + List_in.get("algorithm"))
        if int(List_in.get("algorithm"), 16) == 0:
            print("зарезервировано")
        elif int(List_in.get("algorithm"), 16) == 1:
            print("RSA / MD5 [RSAMD5] n [ RFC2537 ] НЕ РЕКОМЕНДУЕТСЯ")
        elif int(List_in.get("algorithm"), 16) == 2:
            print("Диффи-Хеллман [DH] n [ RFC2539 ]")
        elif int(List_in.get("algorithm"), 16) == 3:
            print("DSA / SHA-1 [DSA] y [ RFC2536 ] ДОПОЛНИТЕЛЬНО")
        elif int(List_in.get("algorithm"), 16) == 4:
            print("Эллиптическая кривая [ECC] TBA")
        elif int(List_in.get("algorithm"), 16) == 5:
            print("зRSA / SHA-1 [RSASHA1] y [ RFC3110 ] ОБЯЗАТЕЛЬНО")
        elif int(List_in.get("algorithm"), 16) == 252:
            print("Косвенный [НЕПОСРЕДСТВЕННЫЙ] [ RFC4033 ]")
        elif int(List_in.get("algorithm"), 16) == 253:
            print("Частный [ЧАСТНЫЕ] и смотрите ниже ДОПОЛНИТЕЛЬНО [ RFC4033 ]")
        elif int(List_in.get("algorithm"), 16) == 254:
            print("Приватный [ЧАСТНЫЙ] см. Ниже ДОПОЛНИТЕЛЬНО [ RFC4033 ]")
        elif int(List_in.get("algorithm"), 16) == 255:
            print("зарезервировано")
        else:
            pass
        print("public_key:" + (base64.b64encode(hex2str(List_in.get("public_key"))).decode('utf-8')))


    elif List_in["TYPE"] == "0030":  # DNSKEY  0030  48


        id5 = (
        "{0:4b}".format(int(List_in.get("flags")[0:1], 16)) + "{0:4b}".format(int(List_in.get("flags")[1:2], 16)) +
        '{0:4b}'.format(int(List_in.get("flags")[2:3], 16)) + '{0:4b}'.format(int(List_in.get("flags")[3:4], 16)))

        i = 0
        id5_1 = {}
        while i <= 15:
            if id5[i] == "1":
                id5_1[i] = "1"
                i = i + 1
            else:
                id5_1[i] = "0"
                i = i + 1

        key = id5_1[7]
        sep = id5_1[15]
        if key == "1":
            print("                                   Ключ зоны DNS")  # bit 0-6 and 8-14  default ==0
        else:
            print("                                   Открытый ключ DNS")

        if sep == "1":
            print("DNSKEY содержит ключ [ RFC3757 ] SEP- Бит SEP рекомендуется устанавливать (равным 1) всякий раз, "
                  "когда открытый ключ пары ключей будет распространяться в родительскую зону для построения "
                  "цепочки аутентификации или если открытый ключ должен распространяться для статической "
                  "конфигурации в верификаторах. ")
        else:
            pass

        print("protocol:" + List_in.get("protocol"))
        if List_in["protocol"] != "03":
            print("Поле протокола ДОЛЖНО иметь значение 3, а DNSKEY RR ДОЛЖЕН "
                  "рассматриваться как недействительный во время проверки подписи, "
                  "если установлено, что оно имеет какое- либо значение, отличное от 3.")

        print("algorithm:      " + List_in.get("algorithm"))
        if int(List_in.get("algorithm"), 16) == 0:
            print("зарезервировано")
        elif int(List_in.get("algorithm"), 16) == 1:
            print("RSA / MD5 [RSAMD5] n [ RFC2537 ] НЕ РЕКОМЕНДУЕТСЯ")
        elif int(List_in.get("algorithm"), 16) == 2:
            print("Диффи-Хеллман [DH] n [ RFC2539 ]")
        elif int(List_in.get("algorithm"), 16) == 3:
            print("DSA / SHA-1 [DSA] y [ RFC2536 ] ДОПОЛНИТЕЛЬНО")
        elif int(List_in.get("algorithm"), 16) == 4:
            print("Эллиптическая кривая [ECC] TBA")
        elif int(List_in.get("algorithm"), 16) == 5:
            print("зRSA / SHA-1 [RSASHA1] y [ RFC3110 ] ОБЯЗАТЕЛЬНО")
        elif int(List_in.get("algorithm"), 16) == 252:
            print("Косвенный [НЕПОСРЕДСТВЕННЫЙ] [ RFC4033 ]")
        elif int(List_in.get("algorithm"), 16) == 253:
            print("Частный [ЧАСТНЫЕ] и смотрите ниже ДОПОЛНИТЕЛЬНО [ RFC4033 ]")
        elif int(List_in.get("algorithm"), 16) == 254:
            print("Приватный [ЧАСТНЫЙ] см. Ниже ДОПОЛНИТЕЛЬНО [ RFC4033 ]")
        elif int(List_in.get("algorithm"), 16) == 255:
            print("зарезервировано")
        else:
            pass
        print("public_key:" + (base64.b64encode(hex2str(List_in.get("public_key"))).decode('utf-8')))


    elif List_in["TYPE"] == "002e":  # RRSIG (46) 002E


        print("type_cover :"+List_in["type_cover"])
        print("algorithm:"+List_in["algorithm"])
        print("labels:"+List_in["labels"])
        print("orig_ttl:" + List_in["orig_ttl"] + "         " + time.ctime(int(List_in.get("orig_ttl"), 16)))
        print("sig_exp:"+List_in["sig_exp"]+"         "+ time.ctime(int(List_in.get("sig_exp"), 16)))
        print("sig_ince:"+List_in["sig_ince"]+"        "+ time.ctime(int(List_in.get("sig_ince"), 16)))
        print("key_tag:"+List_in["key_tag"])
        print("sig_name:"+List_in["sig_name"]  +"   " +(base64.b64encode(hex2str(List_in.get("sig_name"))).decode('utf-8')))
        print("Signature:"+List_in["Signature"]  +"   " +(base64.b64encode(hex2str(List_in.get("Signature"))).decode('utf-8')))



    elif List_in["TYPE"] == "002b" and List_in["NSCOUNT"] == "0001":  # 'DS (43) 002B'
        print("key tag :"+List_in["key tag"]  + "         "+str(int(List_in.get("key tag"), 16)))
        print("algorithm:"+List_in["algorithm"])
        print("Digest type:"+List_in["Digest type"])
        if List_in["Digest type"] != "01":
            print("Digest:              " + List_in["KEY"][8: - 24])
            print("(SHA-1) 24b:         " + List_in["KEY"][-24:])
        else:
            print("Digest:" + List_in["Digest"])  #

        print("Digest:" + List_in["Digest"])# + "         " + time.ctime(int(List_in.get("digest"), 16)))
        print(                             "" +(base64.b64encode(hex2str(List_in.get("Digest"))).decode('utf-8')))

    elif List_in["TYPE"] == "002b" and List_in["NSCOUNT"] != "0001":  # 'DS (43) 002B'
        List_in["key tag"] = List_in["KEY"][0:4]
        List_in["algorithm"] = List_in["KEY"][4:6]
        List_in["Digest type"] = List_in["KEY"][6:8]

        s = 8
        st = s
        while s <= len(List_in["KEY"]):
            if List_in["KEY"][s:s + 2] == "c0":
                if List_in["KEY"][s + 2:s + 4] == "0c":
                    List_in["Digest"] = List_in["KEY"][8:s]
                    print("key tag :          " + List_in["key tag"] + "         " + str(int(List_in.get("key tag"), 16)))
                    print("algorithm:         " + List_in["algorithm"])
                    print("Digest type:       " + List_in["Digest type"])
                    print("Digest:            " + List_in["Digest"])
                    s = s + 4
                    st = s
                    break

                else:
                    pass
            else:
                s = s + 2

        s = st
        st1 = s
        while s <= len(List_in["KEY"]):
            if List_in["KEY"][s:s + 2] == "c0" or s+2 == len(List_in["KEY"]):
                if List_in["KEY"][s + 2:s + 4] == "0c" or s+2 == len(List_in["KEY"]):

                    print("#------------------------------------------------------------------------------------------")
                    print("                                                NAME :               " + hex2str(qname).decode('utf-8'))
                    print("                                                TYPE :               " + List_in["KEY"][st1+0:st1+4])
                    print("                                                CLASS :              " + List_in["KEY"][st1 + 4:st1 + 8])#CLASS : Class
                    print("                                                TTL :Time    sek     " + str(int(List_in.get("KEY")[st1 + 12:st1 + 16], 16))) #TTL : Time    sek
                    print("                                                RDLENGTH :" + " lend RDDATA    " + List_in["KEY"][st1 + 16:st1 + 20])
                    print("key tag :            " + List_in["KEY"][st1 + 20:st1 + 24] + "         " + str(int(List_in["KEY"][st1 + 20:st1 + 24], 16)))
                    print("algorithm:           " + List_in["KEY"][st1 + 24:st1 + 26] + "         " + str(int(List_in["KEY"][st1 + 24:st1 + 26], 16)))
                    print("Digest type:         " + List_in["KEY"][st1 + 26:st1 + 28] + "         " + str(int(List_in["KEY"][st1 + 26:st1 + 28], 16)))
                    if  List_in["KEY"][st1 + 26:st1 + 28]!= "01":
                        print("Digest:              " + List_in["KEY"][st1 + 28:s-24])
                        print("(SHA-1) 24b:         " + List_in["KEY"][s-24:s])
                    else:
                        print("Digest:              " + List_in["KEY"][st1 + 28:s])

                    s = s + 4
                    st1 = s

                else:
                    pass
            else:
                s = s + 2

    elif List_in["TYPE"] == "0002" and( List_in["NSCOUNT"] == "0001" or List_in["ANCOUNT"] == "0001"): # 'NS (2) 0002'
        s = 2* int(List_in.get("RDLENGTH"), 16)
      #  print("s=",s,"List_in.get(RDLENGTH",List_in.get("RDLENGTH"))
        List_in["NSa"] = (List_in["NS"])[:+ s]
        sta = 0
        while True:
            if List_in["NSa"][sta: sta + 2] == "00" or List_in["NSa"][sta:  sta + 2] == "c0":
                if List_in["NSa"][sta: sta + 2] == "c0":
                    st = int(List_in["NSa"][2 + sta: sta + 4], 16)
                    sto = 0
                    while True:
                        if List_in["LIST_IN"][st * 2 + sto:st * 2 + 2 + sto] == "00":
                            List_in["NS_name"] = List_in["NSa"][:sta] + List_in["LIST_IN"][st * 2:st * 2 + 2 + sto]
                            break
                        else:
                            sto = sto + 2
                    break
                else:
                    List_in["NS_name"] = List_in["NSa"][: sta]
                    break
            else:
                sta = sta + 2
        print("NS_DATA :                                         " + hex2str(List_in["NS_name"]).decode('utf-8'))

    elif List_in["TYPE"] == "0002" and( List_in["NSCOUNT"] != "0001" or List_in["ANCOUNT"] != "0001"):  # 'NS (2) 0002'
        start = 1
        s0 = 0
        stop = int(List_in["ANCOUNT"],16)
        while start <= stop:
             s = 2* int(List_in.get("RDLENGTH"),16)   #
            # s =  int(List_in.get("RDLENGTH"), 16) #!!!!!!!!!!!
          #   print("s=", s, "List_in.get(RDLENGTH", List_in.get("RDLENGTH"))
             List_in["NSa"] = (List_in["NS"])[s0:s0+s]
             sta = 0
             while True:
                 if List_in["NSa"][sta: sta + 2] == "00" or List_in["NSa"][sta:  sta + 2] == "c0":
                     if List_in["NSa"][sta: sta + 2] == "c0":
                         st = int(List_in["NSa"][2 + sta: sta + 4], 16)
                         sto = 0
                         while True:
                             if List_in["LIST_IN"][st * 2 + sto:st * 2 + 2 + sto] == "00":
                                 List_in["NS_name"] = List_in["NSa"][:sta] + List_in["LIST_IN"][st * 2:st * 2 + 2 + sto]
                                 break
                             else:
                                 sto = sto + 2
                         break
                     else:
                         List_in["NS_name"] = List_in["NSa"][: sta]
                         break
                 else:
                     sta = sta + 2


             print("NS_DATA :                                         " + hex2str(List_in["NS_name"]).decode('utf-8'))
             start = start + 1
             s0 = s + 24
             List_in["RDLENGTH"] = List_in["NS"][s+20:s+ 24]
           #  print("List_in[RDLENGTH]===",List_in["RDLENGTH"],"s",s)


    else:
        pass

    return


def List_call():
    # write message for request in DNS server
    #
    List_out_call = {}
    #RFC 3225 DNSSEC OK
    #print('Enter a CD RFC 2136, 2535: (blank to  default CD = "0")')
    print('Enter DNSSEC OK  D0-RFC 3225: (blank to  default D0 = "0")')
    name = input()
    if name == '':
        name = "0"
        List_out_call["Z"] = "000"
        List_out_call["ARCOUNT"] = "0000"
    elif name == '1':
        #List_out_call["Z"] = "100"
        List_out_call["Z"] = "100"  #Модификации протокола RFC 4035 DNSSEC, март 2005 г.
        List_out_call["ARCOUNT"] = "0000"

    print("Name input  D0 :", name)

    List_out_call["ID"] = "AAAA"  # id request
    List_out_call["QR"] = "0"  # 0-requst , 1 answer
    List_out_call["OPCODE"] = "0000"  # 0- standart requst and variant
    List_out_call["AA"] = "0"  # Code answer
    List_out_call["TC"] = "0"  # TrunCation
    List_out_call["RD"] = "1"  # Recursion
    List_out_call["RA"] = "0"  # Recursion Available
    List_out_call["RCODE"] = "0000"  # Code answer(0,1,2,3,4,5,6-15)
    List_out_call["QDCOUNT"] = "0001"  # 1-requst
    List_out_call["ANCOUNT"] = "0000"  # Code answer
    List_out_call["NSCOUNT"] = "0000"  # numba write name servis available

    Header_1 = List_out_call.get("QR") + List_out_call.get("OPCODE") + List_out_call.get("AA") \
               + List_out_call.get("TC") + List_out_call.get("RD")
    Header_2 = List_out_call.get("RA") + List_out_call.get("Z") + List_out_call.get("RCODE")

    Header_1_1 = Header_1[0:4]
    Header_1_2 = Header_1[4:8]
    Header_2_1 = Header_2[0:4]
    Header_2_2 = Header_2[4:8]
    List_out_call["Header"] = str(int((Header_1_1), 2)) + str(int((Header_1_2), 2)) \
                              + str(int((Header_2_1), 2)) + str(int((Header_2_2), 2))

    print('Enter a name: (blank to  default example.com)')
    name = input()
    if name == '':
        name = "example.com"
    else:
        pass
    print("Name input :", name)
    name_hex = str2hex(name).decode('utf-8')
    start_in = 0
    lis_name_hex = ""
    for i in range(0, len(name_hex), 2):
        if name_hex[i: i + 2] == "2e":  # 2e toshka
            stop_in = i  # toshka
            sum_in = str(hex(int((stop_in - start_in) / 2)))
            if int(sum_in, 16) < 16:
                lis_name_hex = lis_name_hex + "".join(sum_in[0] + sum_in[2] + name_hex[start_in:stop_in])
                start_in = stop_in + 2
            else:
                lis_name_hex = lis_name_hex + "".join(sum_in[2] + sum_in[3] + name_hex[start_in:stop_in])
                start_in = stop_in + 2

    stop_in = len(name_hex)
    sum_in = str(hex(int((stop_in - start_in) / 2)))
    lis_name_hex = lis_name_hex + "".join(sum_in[0] + sum_in[2] + name_hex[start_in:stop_in]) + "00"
    List_out_call["QNAME"] = lis_name_hex
    print('Enter QTYPE: (blank to  default A (1) 0001)')
    print('NS (2) 0002')
    print('SOA (6) 0110')
    print('TXT (16) 0010')
    print('KEY (25) 0019')
    print('AAAA (28) 001C')
    print('DNSKEY (48) 0030  ??????')
    print('RRSIG (46) 002E   ????????')
    print('DS (43) 002B')
    name = input()
    if name == '':
        name = "0001"
        List_out_call["QTYPE"] = "0001"  # write A
    elif name == "6":
        List_out_call["QTYPE"] = "0110"
    elif name == "28":
        List_out_call["QTYPE"] = "001C"
    elif name == "16":
        List_out_call["QTYPE"] = "0010"
    elif name == "25":
        List_out_call["QTYPE"] = "0019"
    elif name == "48":
        List_out_call["QTYPE"] = "0030"
    elif name == "46":
        List_out_call["QTYPE"] = "002E"
    elif name == "43":
        List_out_call["QTYPE"] = "002B"
    elif name == "2":
        List_out_call["QTYPE"] = "0002"
    print("Name QTYPE :", name)

    List_out_call["QCLASS"] = "0001"  # 1 internet

    message = List_out_call.get("ID") + List_out_call.get("Header") + List_out_call.get("QDCOUNT") + List_out_call.get(
        "ANCOUNT") + List_out_call.get("NSCOUNT") + List_out_call.get("ARCOUNT") + List_out_call.get(
        "QNAME") + List_out_call.get("QTYPE") + List_out_call.get("QCLASS")
    if 1==2 :#List_out_call["CD"] == "1":
        List_out_call["A/C"] = "00"  # key autofication
        List_out_call["Z0"] = "0"  # reserv
        List_out_call["XT"] = "0"  # reserv
        List_out_call["Z1"] = "0"  # reserv
        List_out_call["Z2"] = "0"  # reserv
        List_out_call["NAMTYP"] = "00"  # user soa (00) key zono (01)
        List_out_call["Z3"] = "0"  # reserv
        List_out_call["Z4"] = "0"  # reserv
        List_out_call["Z5"] = "0"  # reserv
        List_out_call["Z6"] = "0"  # reserv
        List_out_call["SIG"] = "0000"
        List_out_call["FLAGS"] = str(int((List_out_call["A/C"] + "00"), 2)) + str(
            int(("00" + List_out_call["NAMTYP"]), 2)) \
                                 + str(int(("0000"), 2)) + str(int((List_out_call["SIG"]), 2))
        List_out_call["PROTOKOL"] = "29"  # "11" 3-dns securiti   29!
        List_out_call["ALGORITHM"] = "10"  # 10   01 rsa-md5
        List_out_call["P_KEY"] = "00000080000000"
        message = message + List_out_call.get("FLAGS") + List_out_call.get("PROTOKOL") + List_out_call.get("ALGORITHM") \
                  + List_out_call.get("P_KEY")
    else:
        pass
    print(message)
    return (message)


def ip_server():
   # print('Enter DNS server: (blank to  default "8.8.8.8")')  # "127.0.0.1"
    print('Enter DNS server: (blank to  default "192.168.1.180")')  # "127.0.0.1"
    ip_server = input()
    if ip_server == '':
        ip_server = "192.168.1.180"  # "127.0.0.1"
       # ip_server = "8.8.8.8"  # "127.0.0.1"

    else:
        pass
    print("DNS server adress :", ip_server)
    return (str(ip_server))


response = send_udp_message(List_call(), ip_server(), 53)
List_read_in(List_callback())


